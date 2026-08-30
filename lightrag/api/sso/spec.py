"""Identity-provider metadata for the SSO registry.

Mirrors :mod:`lightrag.parser.registry`: the registry table holds only
lightweight, import-cheap :class:`SSOProviderSpec` metadata, and the
implementation named by ``impl`` is imported lazily the first time a provider
is actually used.  Loading this module therefore imports no provider SDK.

**Scope of a provider.**  A provider adapts LightRAG to one identity
provider's dialect of OIDC and nothing more.  It never makes a security
decision: PKCE, ``state``/``nonce``, JWKS retrieval, signature verification,
issuer/audience pinning, role mapping and session minting all live in
:mod:`lightrag.api.sso.core`, which is not pluggable.  A defective provider
can therefore only cause a *failed login*; it can never mint a session or
weaken validation of one.  See ``docs/EntraIDSSO.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, runtime_checkable

# Bumped when the provider protocol changes shape. A spec declaring a different
# version is refused at registration rather than failing later inside a login.
SSO_PROVIDER_API_VERSION = 1


@dataclass(frozen=True)
class IdentityClaims:
    """The provider-neutral identity distilled from an OIDC ``id_token``.

    ``subject`` is the identity provider's stable, immutable user identifier
    (Entra's ``oid``) and is what any durable per-user record should key on.
    ``username`` is a human-readable display handle and may change over the
    life of an account, so it is used for the session's ``sub`` claim and
    logging only.
    """

    subject: str
    username: str
    groups: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class SSOProvider(Protocol):
    """What a provider implementation must supply.

    Deliberately narrow: four pure, side-effect-free methods that describe an
    identity provider's endpoints and claim shape.  Everything security-bearing
    is handled by the core.

    Providers are **stateless**: configuration arrives as an explicit
    ``settings`` argument rather than being read from module-level globals.
    That keeps a provider unit-testable without a configured process, and makes
    it impossible for one to depend on ambient state the core did not validate.
    """

    def issuer(self, settings: Any) -> str:
        """Return the exact expected ``iss`` claim.

        The core pins the token's issuer to this string.  For a single-tenant
        deployment it embeds the tenant id, which is what stops a token minted
        for a different tenant -- validly signed by the same provider -- from
        authenticating here.
        """
        ...

    def discovery_url(self, settings: Any) -> str:
        """Return the OIDC discovery document URL (``.well-known``)."""
        ...

    def authorize_params(self, settings: Any) -> dict[str, str]:
        """Extra provider-specific query parameters for the authorize request."""
        ...

    def map_claims(self, claims: Mapping[str, Any]) -> IdentityClaims:
        """Project verified ``id_token`` claims onto :class:`IdentityClaims`.

        Called only after the core has verified the token's signature, issuer,
        audience, expiry and nonce, so the input is trusted.
        """
        ...


@dataclass(frozen=True)
class SSOProviderSpec:
    """Import-cheap metadata for one identity provider."""

    name: str
    # "module:Class", imported lazily by the registry.
    impl: str
    # Environment variables that must be non-empty for this provider to work.
    # Verified at startup so a misconfigured deployment fails immediately
    # instead of at a user's first sign-in attempt.
    required_env: tuple[str, ...] = ()
    api_version: int = SSO_PROVIDER_API_VERSION
    description: str = ""
