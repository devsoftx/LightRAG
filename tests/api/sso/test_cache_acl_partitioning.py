"""The answer cache must not be reusable across entitlement boundaries.

The cache sits in FRONT of the database: on a hit the query never reaches
PostgreSQL, so no Row-Level Security policy is evaluated. A key that omits the
caller's entitlements therefore bypasses RLS entirely on any repeated question
-- every policy correct, and still leaking.

These tests assert the property directly on the key-composition function, which
is what both query paths (``kg_query`` and ``naive_query``) use.
"""

from __future__ import annotations

from lightrag.operate import _ANSWER_CACHE_POLICY_VERSION
from lightrag.security_context import acl_fingerprint, user_groups_scope
from lightrag.utils import compute_args_hash


def _key(groups_ctx, query="what are the encryption controls?", mode="local"):
    """Reproduce the key composition used by both query paths."""
    with user_groups_scope(groups_ctx):
        from lightrag.security_context import get_user_groups

        return compute_args_hash(
            _ANSWER_CACHE_POLICY_VERSION,
            acl_fingerprint(get_user_groups()),
            mode,
            query,
        )


def test_different_entitlements_do_not_share_an_entry():
    """The leak, closed: Bob must not be served Alice's answer."""
    alice = _key(["Sec-Fin-Admins"])
    bob = _key(["Sec-Public-Access"])
    assert alice != bob


def test_identical_entitlements_do_share_an_entry():
    """Partitioning must not degenerate into a per-user cache."""
    assert _key(["Sec-Fin-Admins", "Sec-HR"]) == _key(["Sec-HR", "Sec-Fin-Admins"])


def test_superset_does_not_match_subset():
    """Holding an extra group is a different entitlement, not a compatible one."""
    assert _key(["Sec-Fin"]) != _key(["Sec-Fin", "Sec-HR"])


def test_unauthenticated_callers_share_one_partition():
    """Deployments that do not authenticate keep the previous behaviour."""
    assert _key(None) == _key(None)


def test_no_identity_differs_from_no_groups():
    """An anonymous caller must not read an authenticated caller's entry."""
    assert _key(None) != _key([])


def test_same_caller_different_question_differs():
    """Sanity: partitioning did not collapse the rest of the key."""
    assert _key(["A"], query="q1") != _key(["A"], query="q2")


def test_same_caller_different_mode_differs():
    assert _key(["A"], mode="local") != _key(["A"], mode="global")


def test_policy_version_marks_the_partitioned_scheme():
    """Entries written before partitioning must not remain readable.

    They were keyed without any ACL component, so a caller could still be
    served one. Bumping the version orphans them.
    """
    assert _ANSWER_CACHE_POLICY_VERSION == "query-answer-cache-v3-acl"


def test_key_would_collide_without_the_fingerprint():
    """Pin the defect: the same key composition minus the ACL term collides."""
    unpartitioned_alice = compute_args_hash(
        _ANSWER_CACHE_POLICY_VERSION, "local", "same question"
    )
    unpartitioned_bob = compute_args_hash(
        _ANSWER_CACHE_POLICY_VERSION, "local", "same question"
    )
    # This is what shipped before: two different callers, one cache entry.
    assert unpartitioned_alice == unpartitioned_bob
    # And this is the fix.
    assert _key(["Sec-Fin"], query="same question") != _key(
        ["Sec-Public"], query="same question"
    )
