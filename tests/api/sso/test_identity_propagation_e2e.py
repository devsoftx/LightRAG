"""End-to-end: does a real HTTP request populate the RLS identity context?

The unit tests in test_security_context.py prove the contextvar behaves
correctly when set directly. They do not prove the wiring: that a request
carrying a signed session token actually reaches the storage layer with that
caller's groups bound.

That wiring is the part most likely to be silently wrong, because a contextvar
set in the wrong place -- a different task, a middleware that runs outside the
request's context, a dependency resolved in a threadpool -- fails by being
empty, and an empty identity is indistinguishable from "this caller has no
groups" unless something asserts otherwise.

These tests drive a real FastAPI app through TestClient and read the context
from inside the route, which is exactly where the storage layer would read it.
No database required.
"""

from __future__ import annotations

import sys

import pytest

_original_argv = sys.argv[:]
sys.argv = [sys.argv[0]]
try:
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from lightrag.api.auth import auth_handler
    from lightrag.api.utils_api import get_combined_auth_dependency
    from lightrag.security_context import get_user_groups
    import lightrag.api.utils_api as _utils_api
finally:
    sys.argv = _original_argv


@pytest.fixture
def app_and_client(monkeypatch):
    """An app whose single route reports the identity context it observed."""
    # Force the "authentication configured" profile so tokens are honoured,
    # independent of whatever the developer's .env happens to say.
    monkeypatch.setattr(_utils_api, "auth_configured", True)
    combined_auth = get_combined_auth_dependency()

    app = FastAPI()

    @app.get("/probe", dependencies=[Depends(combined_auth)])
    async def probe():
        groups = get_user_groups()
        return {
            "identity_established": groups is not None,
            "groups": list(groups) if groups is not None else None,
        }

    return app, TestClient(app)


def _token(username: str, groups=None, role: str = "user") -> str:
    metadata = {"auth_mode": "sso"}
    if groups is not None:
        metadata["groups"] = groups
    return auth_handler.create_token(
        username=username, role=role, custom_expire_hours=1, metadata=metadata
    )


def test_groups_reach_the_request_context(app_and_client):
    """The wiring test: a signed token's groups must be readable in the route."""
    _, client = app_and_client
    token = _token("alice@corp.com", ["Sec-Fin-Admins", "Sec-Wealth-EMEA"])

    r = client.get("/probe", headers={"Authorization": f"Bearer {token}"})

    assert r.status_code == 200
    body = r.json()
    assert body["identity_established"] is True
    # Normalized to sorted order by set_user_groups.
    assert body["groups"] == ["Sec-Fin-Admins", "Sec-Wealth-EMEA"]


def test_groups_are_normalized_end_to_end(app_and_client):
    """Duplicates and blanks from the directory must not reach the DB literal."""
    _, client = app_and_client
    token = _token("bob@corp.com", ["Sec-B", "Sec-A", "Sec-B", "   "])

    body = client.get("/probe", headers={"Authorization": f"Bearer {token}"}).json()
    assert body["groups"] == ["Sec-A", "Sec-B"]


def test_token_without_groups_is_authenticated_with_none(app_and_client):
    """A password-auth account: identity established, membership empty."""
    _, client = app_and_client
    token = _token("carol@corp.com", groups=None)

    body = client.get("/probe", headers={"Authorization": f"Bearer {token}"}).json()
    assert body["identity_established"] is True
    assert body["groups"] == []


def test_identity_does_not_persist_across_requests(app_and_client):
    """The failure that would be catastrophic: caller N+1 inheriting caller N.

    TestClient reuses the underlying transport, so if the contextvar were set
    somewhere process-wide rather than per-request, this would leak.
    """
    _, client = app_and_client
    alice = _token("alice@corp.com", ["Sec-Fin-Admins"])
    bob = _token("bob@corp.com", ["Sec-Public-Access"])

    first = client.get("/probe", headers={"Authorization": f"Bearer {alice}"}).json()
    second = client.get("/probe", headers={"Authorization": f"Bearer {bob}"}).json()

    assert first["groups"] == ["Sec-Fin-Admins"]
    assert second["groups"] == ["Sec-Public-Access"]


def test_unauthenticated_request_is_rejected(app_and_client):
    """No token: the route must not run at all, so no identity is established."""
    _, client = app_and_client
    r = client.get("/probe")
    assert r.status_code in (401, 403)


def test_rejected_request_leaves_no_identity_behind(app_and_client):
    """A refused request must not seed an identity for whatever runs next."""
    _, client = app_and_client
    client.get("/probe", headers={"Authorization": "Bearer not-a-real-token"})
    assert get_user_groups() is None
