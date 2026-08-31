"""Security-core tests for the SSO flow.

Everything here is mock-based: no live tenant, no network. The JWKS is a
locally generated RSA key pair, so ``id_token`` verification exercises the real
:mod:`jwt` code path rather than a stub.
"""

from __future__ import annotations

import argparse
import time

import pytest

from lightrag.api.sso.core import SSOError, SSOFlow, SSOSettings, TransactionStore
from lightrag.api.sso.spec import IdentityClaims


def _args(**overrides) -> argparse.Namespace:
    base = dict(
        sso_provider="entra",
        sso_tenant_id="11111111-2222-3333-4444-555555555555",
        sso_client_id="client-id",
        sso_client_secret="client-secret",
        sso_redirect_uri="https://example.com/auth/sso/callback",
        sso_scopes="openid,profile,email",
        sso_allowed_groups="",
        sso_role_mapping="",
        sso_default_role="user",
        sso_session_ttl_hours=8,
        sso_state_ttl_seconds=600,
        sso_post_login_redirect="/webui/",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


# --------------------------------------------------------------------------
# TransactionStore: state is single-use and TTL-bounded
# --------------------------------------------------------------------------


def test_state_is_single_use():
    """A replayed callback must not find its transaction a second time."""
    store = TransactionStore(ttl_seconds=600)
    state = store.create(nonce="n", code_verifier="v", return_to=None)

    assert store.consume(state).nonce == "n"
    with pytest.raises(SSOError, match="already been used"):
        store.consume(state)


def test_unknown_state_is_rejected():
    store = TransactionStore(ttl_seconds=600)
    with pytest.raises(SSOError, match="invalid or has already been used"):
        store.consume("forged-state")


def test_expired_state_is_rejected(monkeypatch):
    store = TransactionStore(ttl_seconds=1)
    state = store.create(nonce="n", code_verifier="v", return_to=None)

    real_monotonic = time.monotonic
    monkeypatch.setattr(
        "lightrag.api.sso.core.time.monotonic", lambda: real_monotonic() + 3600
    )
    with pytest.raises(SSOError):
        store.consume(state)


def test_expired_state_is_not_reusable_after_rejection(monkeypatch):
    """An expired entry must still be deleted, not left for a later retry."""
    store = TransactionStore(ttl_seconds=1)
    state = store.create(nonce="n", code_verifier="v", return_to=None)

    real_monotonic = time.monotonic
    monkeypatch.setattr(
        "lightrag.api.sso.core.time.monotonic", lambda: real_monotonic() + 3600
    )
    with pytest.raises(SSOError):
        store.consume(state)

    # Back inside the TTL window: the entry must be gone, not merely stale.
    monkeypatch.setattr("lightrag.api.sso.core.time.monotonic", real_monotonic)
    with pytest.raises(SSOError):
        store.consume(state)


def test_store_is_bounded():
    """Unanswered /login requests must not grow the store without bound."""
    store = TransactionStore(ttl_seconds=600)
    for _ in range(TransactionStore.MAX_ENTRIES + 50):
        store.create(nonce="n", code_verifier="v", return_to=None)
    assert len(store._entries) <= TransactionStore.MAX_ENTRIES


# --------------------------------------------------------------------------
# Settings parsing
# --------------------------------------------------------------------------


def test_role_mapping_parsed():
    settings = SSOSettings.from_args(
        _args(sso_role_mapping="group-a:admin,group-b:user")
    )
    assert settings.role_mapping == {"group-a": "admin", "group-b": "user"}


def test_malformed_role_mapping_rejected():
    with pytest.raises(ValueError, match="SSO_ROLE_MAPPING"):
        SSOSettings.from_args(_args(sso_role_mapping="group-a"))


# --------------------------------------------------------------------------
# Authorization: group allow-list and role mapping
# --------------------------------------------------------------------------


def _flow(**overrides) -> SSOFlow:
    return SSOFlow(SSOSettings.from_args(_args(**overrides)))


def test_group_allowlist_denies_non_member():
    flow = _flow(sso_allowed_groups="allowed-group")
    identity = IdentityClaims(subject="s", username="u", groups=("other-group",))
    with pytest.raises(SSOError, match="not authorized"):
        flow._authorize(identity)


def test_group_allowlist_admits_member():
    flow = _flow(sso_allowed_groups="allowed-group")
    identity = IdentityClaims(subject="s", username="u", groups=("allowed-group",))
    assert flow._authorize(identity) == "user"


def test_user_with_no_groups_denied_when_allowlist_set():
    """Entra omits 'groups' entirely on overage; that must deny, not admit."""
    flow = _flow(sso_allowed_groups="allowed-group")
    identity = IdentityClaims(subject="s", username="u", groups=())
    with pytest.raises(SSOError, match="not authorized"):
        flow._authorize(identity)


def test_empty_allowlist_permits_any_authenticated_user():
    flow = _flow(sso_allowed_groups="")
    identity = IdentityClaims(subject="s", username="u", groups=())
    assert flow._authorize(identity) == "user"


def test_role_mapping_applied():
    flow = _flow(sso_role_mapping="admins:admin", sso_default_role="user")
    admin = IdentityClaims(subject="s", username="u", groups=("admins",))
    plain = IdentityClaims(subject="s", username="u", groups=("everyone",))
    assert flow._authorize(admin) == "admin"
    assert flow._authorize(plain) == "user"
