"""``id_token`` verification tests.

These exercise the real :mod:`jwt` verification path against a locally
generated RSA key pair, so a regression that weakens signature, issuer,
audience, expiry or nonce checking fails here rather than in production.
"""

from __future__ import annotations

import argparse
import datetime as dt

import pytest

jwt = pytest.importorskip("jwt")
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")

from cryptography.hazmat.primitives import serialization  # noqa: E402

from lightrag.api.sso.core import SSOError, SSOFlow, SSOSettings  # noqa: E402

TENANT = "11111111-2222-3333-4444-555555555555"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
CLIENT_ID = "client-id"
NONCE = "the-expected-nonce"


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key, private_pem


def _args(**overrides) -> argparse.Namespace:
    base = dict(
        sso_provider="entra",
        sso_tenant_id=TENANT,
        sso_client_id=CLIENT_ID,
        sso_client_secret="secret",
        sso_redirect_uri="https://example.com/auth/sso/callback",
        sso_scopes="openid",
        sso_allowed_groups="",
        sso_role_mapping="",
        sso_default_role="user",
        sso_session_ttl_hours=8,
        sso_state_ttl_seconds=600,
        sso_post_login_redirect="/webui/",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _make_token(private_pem, **claim_overrides) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "pairwise-subject",
        "oid": "object-id",
        "preferred_username": "user@example.com",
        "nonce": NONCE,
        "iat": now,
        "exp": now + dt.timedelta(minutes=10),
    }
    claims.update(claim_overrides)
    return jwt.encode(claims, private_pem, algorithm="RS256")


@pytest.fixture
def flow(monkeypatch, keypair):
    """An SSOFlow whose JWKS resolves to the local public key."""
    key, _ = keypair
    sso_flow = SSOFlow(SSOSettings.from_args(_args()))

    class _Signing:
        def __init__(self, k):
            self.key = k

    class _FakeJWKClient:
        def get_signing_key_from_jwt(self, token):
            return _Signing(key.public_key())

    async def _fake_jwks(self, uri):
        return _FakeJWKClient()

    monkeypatch.setattr(SSOFlow, "_jwks", _fake_jwks)
    return sso_flow


async def _verify(flow, token, nonce=NONCE):
    return await flow._verify_id_token(
        id_token=token, jwks_uri="https://example/jwks", expected_nonce=nonce
    )


@pytest.mark.asyncio
async def test_valid_token_accepted(flow, keypair):
    _, private_pem = keypair
    claims = await _verify(flow, _make_token(private_pem))
    assert claims["oid"] == "object-id"


@pytest.mark.asyncio
async def test_wrong_issuer_rejected(flow, keypair):
    """A token from another tenant is validly signed but must not authenticate."""
    _, private_pem = keypair
    other = (
        "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0"
    )
    with pytest.raises(SSOError):
        await _verify(flow, _make_token(private_pem, iss=other))


@pytest.mark.asyncio
async def test_wrong_audience_rejected(flow, keypair):
    """A token minted for a different application must not be replayable here."""
    _, private_pem = keypair
    with pytest.raises(SSOError):
        await _verify(flow, _make_token(private_pem, aud="some-other-app"))


@pytest.mark.asyncio
async def test_expired_token_rejected(flow, keypair):
    _, private_pem = keypair
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
    with pytest.raises(SSOError):
        await _verify(
            flow,
            _make_token(private_pem, exp=past, iat=past - dt.timedelta(minutes=5)),
        )


@pytest.mark.asyncio
async def test_nonce_mismatch_rejected(flow, keypair):
    """Replaying a token from a different authorize request must fail."""
    _, private_pem = keypair
    with pytest.raises(SSOError, match="nonce"):
        await _verify(flow, _make_token(private_pem, nonce="a-different-nonce"))


@pytest.mark.asyncio
async def test_missing_nonce_rejected(flow, keypair):
    _, private_pem = keypair
    token = _make_token(private_pem)
    payload = jwt.decode(token, options={"verify_signature": False})
    payload.pop("nonce")
    unsigned = jwt.encode(payload, keypair[1], algorithm="RS256")
    with pytest.raises(SSOError, match="nonce"):
        await _verify(flow, unsigned)


@pytest.mark.asyncio
async def test_signature_from_wrong_key_rejected(flow):
    """A token signed by a key that is not in the JWKS must be refused."""
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_pem = attacker.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(SSOError):
        await _verify(flow, _make_token(attacker_pem))


@pytest.mark.asyncio
async def test_alg_none_rejected(flow, keypair):
    """The classic algorithm-confusion attack must not authenticate."""
    _, private_pem = keypair
    payload = jwt.decode(_make_token(private_pem), options={"verify_signature": False})
    unsigned = jwt.encode(payload, key="", algorithm="none")
    with pytest.raises(SSOError):
        await _verify(flow, unsigned)
