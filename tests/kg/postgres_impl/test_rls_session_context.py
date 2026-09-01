"""Transaction-scoped RLS session binding in PostgreSQLDB.

These assert the three properties the design depends on, none of which need a
live server:

1. the identity is bound INSIDE a transaction (outside one, ``SET LOCAL`` is a
   silent no-op and plain ``SET`` would persist onto the pooled connection);
2. the group array is passed as a BIND PARAMETER, never interpolated;
3. a missing identity REFUSES rather than running an unscoped query.

A user request is simulated with ``mark_user_request()``: the identity binding
is deliberately skipped for INTERNAL work (the ingestion pipeline, migrations),
which shares these storage methods and has no end user to scope to. Without the
marker these tests would exercise the internal path and assert nothing.
"""

from __future__ import annotations

import pytest

from lightrag.kg.postgres_impl import PostgreSQLDB
from lightrag.security_context import mark_user_request, user_groups_scope


class _FakeTransaction:
    def __init__(self, log):
        self._log = log

    async def __aenter__(self):
        self._log.append(("BEGIN", None))
        return self

    async def __aexit__(self, *exc):
        self._log.append(("COMMIT", None))
        return False


class _FakeConnection:
    """Records statements and their bind parameters, in order."""

    def __init__(self):
        self.log: list[tuple[str, object]] = []

    def transaction(self):
        return _FakeTransaction(self.log)

    async def execute(self, sql, *params):
        self.log.append((sql, params))

    async def fetch(self, sql, *params):
        self.log.append((sql, params))
        return []


@pytest.fixture(autouse=True)
def _as_user_request():
    """These tests exercise the USER-REQUEST path, which the API layer marks."""
    token = mark_user_request()
    yield
    from lightrag.security_context import _is_user_request

    _is_user_request.reset(token)


def _db(rls_enabled=True, work_mem=None) -> PostgreSQLDB:
    """A PostgreSQLDB with only the attributes this path touches."""
    db = PostgreSQLDB.__new__(PostgreSQLDB)
    db.rls_enabled = rls_enabled
    db.rls_work_mem = work_mem
    return db


async def _operation(conn):
    await conn.fetch("SELECT 1")
    return "done"


@pytest.mark.asyncio
async def test_identity_is_bound_inside_a_transaction():
    """SET LOCAL only takes effect inside a transaction, and unwinds with it."""
    conn = _FakeConnection()
    db = _db()
    with user_groups_scope(["Sec-Fin", "Sec-HR"]):
        result = await db._run_with_rls_context(conn, _operation)

    assert result == "done"
    stages = [sql for sql, _ in conn.log]
    assert stages[0] == "BEGIN"
    assert stages[-1] == "COMMIT"
    # set_config must land after BEGIN and before the operation's own query.
    set_idx = next(i for i, s in enumerate(stages) if "set_config" in s)
    query_idx = stages.index("SELECT 1")
    assert 0 < set_idx < query_idx < len(stages) - 1


@pytest.mark.asyncio
async def test_groups_are_passed_as_a_bind_parameter():
    """Never interpolated: a group name with a quote must not reach the SQL text."""
    conn = _FakeConnection()
    db = _db()
    with user_groups_scope(['Sec"Odd']):
        await db._run_with_rls_context(conn, _operation)

    sql, params = next((s, p) for s, p in conn.log if "set_config" in s)
    assert "$1" in sql
    assert "Sec" not in sql  # the value is in params, not the statement
    assert params == ('{"Sec\\"Odd"}',)


@pytest.mark.asyncio
async def test_missing_identity_refuses():
    """An unscoped query is the one failure mode invisible in the results."""
    conn = _FakeConnection()
    db = _db()
    with pytest.raises(PermissionError, match="no identity"):
        await db._run_with_rls_context(conn, _operation)
    # Nothing was executed at all -- not even a transaction was opened.
    assert conn.log == []


@pytest.mark.asyncio
async def test_authenticated_caller_with_no_groups_proceeds():
    """() is a legitimate state, distinct from None; it must not raise."""
    conn = _FakeConnection()
    db = _db()
    with user_groups_scope([]):
        await db._run_with_rls_context(conn, _operation)
    _, params = next((s, p) for s, p in conn.log if "set_config" in s)
    assert params == ("{}",)


@pytest.mark.asyncio
async def test_work_mem_is_set_inside_the_same_transaction():
    """A per-connection GUC must unwind with the transaction, not leak."""
    conn = _FakeConnection()
    db = _db(work_mem="64MB")
    with user_groups_scope(["A"]):
        await db._run_with_rls_context(conn, _operation)

    stages = [sql for sql, _ in conn.log]
    wm_idx = next(i for i, s in enumerate(stages) if "work_mem" in s)
    assert stages[0] == "BEGIN" and stages[-1] == "COMMIT"
    assert 0 < wm_idx < len(stages) - 1
    _, params = next((s, p) for s, p in conn.log if "work_mem" in s)
    assert params == ("64MB",)


@pytest.mark.asyncio
async def test_work_mem_omitted_when_unset():
    conn = _FakeConnection()
    db = _db(work_mem=None)
    with user_groups_scope(["A"]):
        await db._run_with_rls_context(conn, _operation)
    assert not any("work_mem" in sql for sql, _ in conn.log)
