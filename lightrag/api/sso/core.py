"""Security core of the SSO flow. **Not pluggable.**

Everything that decides whether a login is trustworthy lives here: PKCE, the
one-time ``state``/``nonce`` transaction, OIDC discovery, JWKS retrieval,
``id_token`` verification (signature, issuer, audience, expiry, nonce), group
authorization, role mapping, and the minting of the LightRAG session token.

Providers (:mod:`lightrag.api.sso.spec`) only describe *where* an identity
provider lives and *how its claims are shaped*.  Keeping the decisions here is
what makes third-party providers safe to load: a broken or hostile provider can
cause a failed login, but it cannot forge a session or relax verification.

The browser never receives the identity provider's ``id_token``.  It is
redeemed server-side and exchanged for the ordinary LightRAG JWT that
``get_combined_auth_dependency`` already understands, so the blast radius of a
stolen browser token is exactly what it was before SSO existed.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWKClient

from lightrag.utils import logger

from .registry import get_provider
from .spec import IdentityClaims, SSOProvider


class SSOError(Exception):
    """A login could not be completed. Message is safe to show a user."""


@dataclass(frozen=True)
class SSOSettings:
    """Resolved, validated SSO configuration (all sourced from .env)."""

    provider: str
    tenant_id: str | None
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: tuple[str, ...]
    allowed_groups: frozenset[str]
    role_mapping: Mapping[str, str]
    default_role: str
    session_ttl_hours: float
    state_ttl_seconds: float
    post_login_redirect: str

    @classmethod
    def from_args(cls, args: Any) -> "SSOSettings":
        def _csv(value: str | None) -> tuple[str, ...]:
            return tuple(p.strip() for p in (value or "").split(",") if p.strip())

        mapping: dict[str, str] = {}
        for pair in _csv(getattr(args, "sso_role_mapping", "")):
            group, sep, role = pair.partition(":")
            if not sep or not group.strip() or not role.strip():
                raise ValueError(
                    "SSO_ROLE_MAPPING must be comma-separated '<group-id>:<role>' "
                    f"pairs. Invalid entry: {pair!r}"
                )
            mapping[group.strip()] = role.strip()

        return cls(
            provider=(getattr(args, "sso_provider", "") or "entra").strip(),
            tenant_id=(getattr(args, "sso_tenant_id", None) or None),
            client_id=(getattr(args, "sso_client_id", "") or "").strip(),
            client_secret=(getattr(args, "sso_client_secret", "") or "").strip(),
            redirect_uri=(getattr(args, "sso_redirect_uri", "") or "").strip(),
            scopes=_csv(getattr(args, "sso_scopes", "openid,profile,email")),
            allowed_groups=frozenset(_csv(getattr(args, "sso_allowed_groups", ""))),
            role_mapping=mapping,
            default_role=(getattr(args, "sso_default_role", "user") or "user").strip(),
            session_ttl_hours=float(getattr(args, "sso_session_ttl_hours", 8) or 8),
            state_ttl_seconds=float(getattr(args, "sso_state_ttl_seconds", 600) or 600),
            post_login_redirect=(
                getattr(args, "sso_post_login_redirect", "/webui/") or "/webui/"
            ),
        )


@dataclass(frozen=True)
class _Transaction:
    """One in-flight login, created at /login and consumed at /callback."""

    nonce: str
    code_verifier: str
    created_at: float
    return_to: str | None


class TransactionStore:
    """One-time, TTL-bounded store for in-flight login transactions.

    Keyed by ``state``.  ``consume`` deletes before returning, so a replayed
    callback -- the same authorization code presented twice -- finds nothing and
    is rejected.  In-process by design: a multi-worker deployment must run
    sticky sessions or a shared store, which is called out in the docs.
    """

    # Refuse to grow without bound if callbacks never arrive (a crawler hitting
    # /auth/sso/login repeatedly). Oldest entries are dropped first; a dropped
    # transaction simply means that login must be restarted.
    MAX_ENTRIES = 4096

    def __init__(self, ttl_seconds: float) -> None:
        self._ttl = ttl_seconds
        self._entries: dict[str, _Transaction] = {}

    def _purge_expired(self, now: float) -> None:
        expired = [
            k for k, v in self._entries.items() if now - v.created_at > self._ttl
        ]
        for key in expired:
            self._entries.pop(key, None)

    def create(self, *, nonce: str, code_verifier: str, return_to: str | None) -> str:
        now = time.monotonic()
        self._purge_expired(now)
        if len(self._entries) >= self.MAX_ENTRIES:
            oldest = min(self._entries, key=lambda k: self._entries[k].created_at)
            self._entries.pop(oldest, None)
        state = secrets.token_urlsafe(32)
        self._entries[state] = _Transaction(
            nonce=nonce,
            code_verifier=code_verifier,
            created_at=now,
            return_to=return_to,
        )
        return state

    def consume(self, state: str) -> _Transaction:
        """Return and delete the transaction for ``state``.

        Raises :class:`SSOError` when the state is unknown (forged, already
        used, or from a restarted process) or expired.
        """
        now = time.monotonic()
        self._purge_expired(now)
        # Deleted unconditionally: even an expired hit must not be reusable.
        transaction = self._entries.pop(state, None)
        if transaction is None:
            raise SSOError("Login session is invalid or has already been used.")
        if now - transaction.created_at > self._ttl:
            raise SSOError("Login session has expired. Please sign in again.")
        return transaction


def _pkce_pair() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` for PKCE S256 (RFC 7636)."""
    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


class SSOFlow:
    """Drives the authorization-code + PKCE handshake."""

    def __init__(self, settings: SSOSettings, *, http_timeout: float = 15.0) -> None:
        self.settings = settings
        self._http_timeout = http_timeout
        self.provider: SSOProvider = get_provider(settings.provider)
        self.transactions = TransactionStore(settings.state_ttl_seconds)
        self._metadata: dict[str, Any] | None = None
        self._jwk_client: PyJWKClient | None = None

    # -- discovery ---------------------------------------------------------

    async def _discovery(self) -> dict[str, Any]:
        """Fetch and cache the OIDC discovery document."""
        if self._metadata is not None:
            return self._metadata
        url = self.provider.discovery_url(self.settings)
        async with httpx.AsyncClient(timeout=self._http_timeout) as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                raise SSOError(
                    f"Could not reach the identity provider's discovery endpoint: {exc}"
                ) from exc
            metadata = response.json()

        expected_issuer = self.provider.issuer(self.settings)
        if metadata.get("issuer") != expected_issuer:
            # The document tells us where tokens will claim to come from. If it
            # disagrees with the tenant we were configured for, the deployment is
            # pointed at the wrong tenant and every later issuer check would be
            # validating against an attacker-influenced value.
            raise SSOError(
                "Identity provider discovery issuer mismatch: expected "
                f"{expected_issuer!r}, got {metadata.get('issuer')!r}."
            )
        self._metadata = metadata
        return metadata

    async def _jwks(self, uri: str) -> PyJWKClient:
        if self._jwk_client is None:
            # PyJWKClient caches signing keys and refetches on an unknown kid,
            # which is what makes provider key rotation transparent here.
            self._jwk_client = PyJWKClient(uri, cache_keys=True)
        return self._jwk_client

    # -- step 1: authorize -------------------------------------------------

    async def build_authorize_url(self, *, return_to: str | None = None) -> str:
        metadata = await self._discovery()
        verifier, challenge = _pkce_pair()
        nonce = secrets.token_urlsafe(32)
        state = self.transactions.create(
            nonce=nonce, code_verifier=verifier, return_to=return_to
        )

        params = {
            "client_id": self.settings.client_id,
            "response_type": "code",
            "redirect_uri": self.settings.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(self.settings.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        params.update(self.provider.authorize_params(self.settings))
        return f"{metadata['authorization_endpoint']}?{urlencode(params)}"

    # -- step 2: callback --------------------------------------------------

    async def complete(
        self, *, code: str, state: str
    ) -> tuple[IdentityClaims, str, str | None]:
        """Redeem ``code`` and return ``(claims, role, return_to)``.

        Every failure path raises :class:`SSOError`; there is no partial
        success that still yields a session.
        """
        transaction = self.transactions.consume(state)
        metadata = await self._discovery()

        token_response = await self._exchange_code(
            token_endpoint=metadata["token_endpoint"],
            code=code,
            code_verifier=transaction.code_verifier,
        )
        id_token = token_response.get("id_token")
        if not id_token:
            raise SSOError("Identity provider did not return an id_token.")

        claims = await self._verify_id_token(
            id_token=id_token,
            jwks_uri=metadata["jwks_uri"],
            expected_nonce=transaction.nonce,
        )
        identity = self.provider.map_claims(claims)
        role = self._authorize(identity)
        return identity, role, transaction.return_to

    async def _exchange_code(
        self, *, token_endpoint: str, code: str, code_verifier: str
    ) -> dict[str, Any]:
        data = {
            "client_id": self.settings.client_id,
            "client_secret": self.settings.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.settings.redirect_uri,
            "code_verifier": code_verifier,
        }
        async with httpx.AsyncClient(timeout=self._http_timeout) as client:
            try:
                response = await client.post(token_endpoint, data=data)
            except httpx.HTTPError as exc:
                raise SSOError(f"Token exchange failed: {exc}") from exc
        if response.status_code != 200:
            # The provider's error body can echo request parameters; log the
            # code only, never the response, so a client secret or code cannot
            # reach the log.
            logger.error(
                "[sso] token exchange rejected with HTTP %s", response.status_code
            )
            raise SSOError("The identity provider rejected the sign-in attempt.")
        return response.json()

    async def _verify_id_token(
        self, *, id_token: str, jwks_uri: str, expected_nonce: str
    ) -> dict[str, Any]:
        jwk_client = await self._jwks(jwks_uri)
        try:
            signing_key = jwk_client.get_signing_key_from_jwt(id_token)
        except Exception as exc:  # noqa: BLE001 - any key failure is fatal
            raise SSOError(f"Could not resolve the token signing key: {exc}") from exc

        try:
            claims = jwt.decode(
                id_token,
                signing_key.key,
                # RS256 only: never accept 'none', and never accept a symmetric
                # algorithm here -- with HS256 the public JWKS key would double
                # as the verification secret, letting anyone forge a token.
                algorithms=["RS256"],
                audience=self.settings.client_id,
                issuer=self.provider.issuer(self.settings),
                options={
                    "require": ["exp", "iat", "iss", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.InvalidTokenError as exc:
            raise SSOError(f"Identity token failed validation: {exc}") from exc

        # Replay defence: the nonce ties this token to the authorize request we
        # started. jwt.decode cannot check it, so it is compared explicitly and
        # in constant time.
        token_nonce = claims.get("nonce")
        if not token_nonce or not secrets.compare_digest(
            str(token_nonce), expected_nonce
        ):
            raise SSOError("Identity token nonce mismatch; possible replay.")
        return claims

    # -- authorization -----------------------------------------------------

    def _authorize(self, identity: IdentityClaims) -> str:
        """Apply group allow-list and role mapping. Raises when not permitted."""
        groups = set(identity.groups)

        if self.settings.allowed_groups and not (groups & self.settings.allowed_groups):
            # Authenticated by the identity provider, but not entitled to this
            # deployment. Logged as a warning because it is the signal an
            # operator needs when a user reports being unable to sign in.
            logger.warning(
                "[sso] rejecting %r: not a member of any SSO_ALLOWED_GROUPS",
                identity.username,
            )
            raise SSOError("Your account is not authorized to access this application.")

        for group, role in self.settings.role_mapping.items():
            if group in groups:
                return role
        return self.settings.default_role
