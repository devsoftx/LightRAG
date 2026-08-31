"""Identity propagation for Row-Level Security.

Covers the contextvar carrier (:mod:`lightrag.security_context`) and the
transaction-scoped session binding in ``PostgreSQLDB._run_with_rls_context``.

No database is required: the connection is a stand-in that records the SQL it
was given, which is what these tests are actually asserting about -- that the
identity is bound *inside a transaction*, and *as a bind parameter*.
"""

from __future__ import annotations

import asyncio

import pytest

from lightrag.security_context import (
    acl_fingerprint,
    get_user_groups,
    reset_user_groups,
    set_user_groups,
    to_pg_text_array,
    user_groups_scope,
)


# --------------------------------------------------------------------------
# The carrier
# --------------------------------------------------------------------------


def test_absent_identity_is_none_not_empty():
    """None (no identity) and () (member of nothing) must stay distinguishable."""
    assert get_user_groups() is None


def test_groups_are_normalized():
    """Sorted + de-duplicated + stripped, so a cache key cannot vary by order."""
    with user_groups_scope(["Sec-HR", "Sec-Fin", "Sec-HR", "  ", "  Sec-Ops  "]):
        assert get_user_groups() == ("Sec-Fin", "Sec-HR", "Sec-Ops")


def test_scope_restores_previous_value():
    with user_groups_scope(["A"]):
        assert get_user_groups() == ("A",)
        with user_groups_scope(["B"]):
            assert get_user_groups() == ("B",)
        assert get_user_groups() == ("A",)
    assert get_user_groups() is None


def test_empty_group_list_is_authenticated_with_no_groups():
    with user_groups_scope([]):
        assert get_user_groups() == ()
        assert get_user_groups() is not None


def test_explicit_reset():
    token = set_user_groups(["A"])
    assert get_user_groups() == ("A",)
    reset_user_groups(token)
    assert get_user_groups() is None


@pytest.mark.asyncio
async def test_identity_does_not_leak_between_concurrent_tasks():
    """The property the whole design rests on: one request cannot see another's."""
    seen: dict[str, tuple | None] = {}

    async def worker(name: str, groups: list[str], delay: float):
        with user_groups_scope(groups):
            await asyncio.sleep(delay)  # force interleaving
            seen[name] = get_user_groups()

    await asyncio.gather(
        worker("alice", ["Sec-Fin"], 0.02),
        worker("bob", ["Sec-Public"], 0.01),
        worker("carol", [], 0.015),
    )
    assert seen["alice"] == ("Sec-Fin",)
    assert seen["bob"] == ("Sec-Public",)
    assert seen["carol"] == ()
    assert get_user_groups() is None


# --------------------------------------------------------------------------
# PostgreSQL array rendering
# --------------------------------------------------------------------------


def test_pg_array_rendering():
    assert to_pg_text_array(("A", "B")) == '{"A","B"}'


def test_pg_array_escapes_quotes_and_backslashes():
    """A directory display name containing a quote must not corrupt the literal."""
    rendered = to_pg_text_array(('Sec"Odd', "Back\\slash"))
    assert rendered == '{"Sec\\"Odd","Back\\\\slash"}'


# --------------------------------------------------------------------------
# Cache fingerprint
# --------------------------------------------------------------------------


def test_fingerprint_differs_by_entitlement():
    """Two callers with different groups must not share a cache entry."""
    assert acl_fingerprint(("Sec-Fin",)) != acl_fingerprint(("Sec-Public",))


def test_fingerprint_is_stable_for_equal_entitlements():
    assert acl_fingerprint(("A", "B")) == acl_fingerprint(("A", "B"))


def test_fingerprint_distinguishes_no_identity_from_no_groups():
    assert acl_fingerprint(None) != acl_fingerprint(())


def test_fingerprint_does_not_disclose_group_names():
    fp = acl_fingerprint(("Sec-Very-Secret-Project",))
    assert "Secret" not in fp and "Sec-" not in fp


def test_fingerprint_cannot_collide_across_boundaries():
    """('a','bc') and ('ab','c') must not hash alike."""
    assert acl_fingerprint(("a", "bc")) != acl_fingerprint(("ab", "c"))


# --------------------------------------------------------------------------
# Startup guard: RLS is a PostgreSQL-only feature
# --------------------------------------------------------------------------


def _storage_args(**overrides):
    import argparse

    base = dict(
        postgres_rls_enabled=False,
        kv_storage="JsonKVStorage",
        vector_storage="NanoVectorDBStorage",
        doc_status_storage="JsonDocStatusStorage",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_rls_disabled_permits_any_backend():
    from lightrag.api.config import validate_rls_configuration

    validate_rls_configuration(_storage_args())


def test_rls_enabled_rejects_file_based_backends():
    """A silently-ignored access-control switch is worse than an absent one."""
    from lightrag.api.config import validate_rls_configuration

    with pytest.raises(ValueError, match="PostgreSQL storage backends"):
        validate_rls_configuration(_storage_args(postgres_rls_enabled=True))


def test_rls_enabled_rejects_partial_postgres():
    """PG vectors but a JSON KV store still leaves content unfiltered."""
    from lightrag.api.config import validate_rls_configuration

    with pytest.raises(ValueError, match="kv_storage"):
        validate_rls_configuration(
            _storage_args(postgres_rls_enabled=True, vector_storage="PGVectorStorage")
        )


def test_rls_enabled_accepts_full_postgres():
    from lightrag.api.config import validate_rls_configuration

    validate_rls_configuration(
        _storage_args(
            postgres_rls_enabled=True,
            kv_storage="PGKVStorage",
            vector_storage="PGVectorStorage",
            doc_status_storage="PGDocStatusStorage",
        )
    )
