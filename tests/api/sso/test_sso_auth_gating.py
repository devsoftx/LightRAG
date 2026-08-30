"""Regression tests for the SSO fail-open bypass.

``auth_configured`` gates the whole authentication decision:
:func:`lightrag.api.utils_api.credentials_accepted` returns ``True``
unconditionally when neither auth nor an API key is configured.  Before SSO
existed that flag was ``bool(auth_handler.accounts)``, so a server with
``SSO_ENABLED=true`` and no ``AUTH_ACCOUNTS`` would have computed ``False`` and
served **every protected route to anonymous callers** -- on a deployment whose
operator had just turned on single sign-on.

These tests pin both halves of the fix: the flag now accounts for SSO, and the
guest-token issuers are keyed off the flag rather than off ``accounts``.
"""

from __future__ import annotations

import argparse
import importlib
import sys

import pytest

# lightrag.api.config resolves global_args at import time via argparse, which
# would otherwise consume pytest's own argv and exit. Same guard as
# tests/api/auth/test_shared_credential_check.py.
_original_argv = sys.argv[:]
sys.argv = [sys.argv[0]]
try:
    _utils_api = importlib.import_module("lightrag.api.utils_api")
    _config = importlib.import_module("lightrag.api.config")
finally:
    sys.argv = _original_argv


def test_sso_only_profile_is_not_treated_as_unauthenticated(monkeypatch):
    """The bypass itself: SSO on + no local accounts must NOT authenticate all."""
    monkeypatch.setattr(_utils_api, "auth_configured", True)  # as computed with SSO on
    assert (
        _utils_api.credentials_accepted(
            token=None, api_key=None, api_key_header_value=None
        )
        is False
    )


def test_open_profile_still_authenticates_everything(monkeypatch):
    """The legacy fully-open profile must keep working unchanged."""
    monkeypatch.setattr(_utils_api, "auth_configured", False)
    assert (
        _utils_api.credentials_accepted(
            token=None, api_key=None, api_key_header_value=None
        )
        is True
    )


def test_guest_token_does_not_authenticate_under_sso(monkeypatch):
    """A guest token is signed with the PUBLIC default secret.

    Anyone can mint one, so it must never satisfy an SSO-protected server.
    """
    monkeypatch.setattr(_utils_api, "auth_configured", True)
    guest = _utils_api.auth_handler.create_token(username="guest", role="guest")
    assert (
        _utils_api.credentials_accepted(
            token=guest, api_key=None, api_key_header_value=None
        )
        is False
    )


def test_sso_user_token_authenticates(monkeypatch):
    monkeypatch.setattr(_utils_api, "auth_configured", True)
    token = _utils_api.auth_handler.create_token(
        username="user@example.com", role="user", metadata={"auth_mode": "sso"}
    )
    assert (
        _utils_api.credentials_accepted(
            token=token, api_key=None, api_key_header_value=None
        )
        is True
    )


# --------------------------------------------------------------------------
# Startup validation
# --------------------------------------------------------------------------


def _args(**overrides) -> argparse.Namespace:
    base = dict(
        auth_accounts="",
        token_secret=None,
        sso_enabled=False,
        sso_client_id="",
        sso_client_secret="",
        sso_redirect_uri="",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_sso_rejects_default_token_secret():
    """SSO sessions signed with the public default secret are forgeable."""
    with pytest.raises(ValueError, match="TOKEN_SECRET"):
        _config.validate_auth_configuration(
            _args(sso_enabled=True, token_secret=_config.DEFAULT_TOKEN_SECRET)
        )


def test_sso_rejects_missing_token_secret():
    with pytest.raises(ValueError, match="TOKEN_SECRET"):
        _config.validate_auth_configuration(_args(sso_enabled=True))


def test_sso_requires_client_credentials():
    with pytest.raises(ValueError, match="SSO_CLIENT_ID"):
        _config.validate_auth_configuration(
            _args(
                sso_enabled=True,
                token_secret="real-secret",
                sso_client_secret="x",
                sso_redirect_uri="https://e.com/cb",
            )
        )


def test_sso_rejects_plaintext_redirect_uri():
    """The authorization code travels to this URI; http:// exposes it."""
    with pytest.raises(ValueError, match="https://"):
        _config.validate_auth_configuration(
            _args(
                sso_enabled=True,
                token_secret="real-secret",
                sso_client_id="c",
                sso_client_secret="x",
                sso_redirect_uri="http://evil.example.com/cb",
            )
        )


def test_sso_allows_loopback_http_for_development():
    _config.validate_auth_configuration(
        _args(
            sso_enabled=True,
            token_secret="real-secret",
            sso_client_id="c",
            sso_client_secret="x",
            sso_redirect_uri="http://localhost:9621/auth/sso/callback",
        )
    )


def test_legacy_open_profile_still_starts():
    """No auth of any kind configured: unchanged, must not raise."""
    _config.validate_auth_configuration(_args())
