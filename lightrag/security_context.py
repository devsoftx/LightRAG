"""Per-request security identity, carried to the storage layer.

Row-Level Security needs the caller's group membership at the moment a database
connection is used, but the storage layer has no access to the request: storage
instances are constructed once at startup and shared by every concurrent
request, and :meth:`BaseVectorStorage.query` takes ``(query, top_k,
query_embedding)`` with no identity parameter.  Widening that signature would
change an interface implemented by eight backends, only one of which can enforce
RLS.

A :class:`contextvars.ContextVar` is the right carrier here.  It is
asyncio-native: each task gets its own copy, values do not leak between
concurrently-served requests, and no argument has to be threaded through the
call chain.  The API layer sets it once, immediately after the session token is
validated; ``PostgreSQLDB._run_with_retry`` reads it when it opens an
RLS-scoped connection.

**This module holds identity, not authorization.**  Nothing here decides what a
caller may see.  It transports the group set that the database's RLS policies
evaluate, and it deliberately offers no way to ask "is this allowed?" — that
answer belongs to PostgreSQL.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterable, Iterator

# The caller's effective group set, or None when no identity has been
# established for this task.
#
# None and the empty tuple mean different things and must stay distinguishable:
#   None  -> no identity was established (a bug, or an unauthenticated path).
#            An RLS-scoped query MUST refuse rather than run.
#   ()    -> an authenticated caller who belongs to no group. A legitimate
#            state; RLS will match only rows readable without membership.
# Collapsing the two would turn a missing identity into "member of nothing",
# which fails closed today but silently becomes wrong the moment a policy grants
# access to some public tier.
_current_user_groups: ContextVar[tuple[str, ...] | None] = ContextVar(
    "lightrag_current_user_groups", default=None
)


# Whether the current task is serving an authenticated end-user request, as
# opposed to internal work (the ingestion pipeline, migrations, maintenance).
#
# This is NOT derivable from the group set. Both an internal task and a
# hypothetical mis-wired request would show no groups, and the two must be
# treated in opposite ways: internal work legitimately runs unscoped, while a
# request that lost its identity must be refused. A separate, explicitly-set
# marker keeps "unscoped" impossible to reach by accident -- it is only ever
# true when nothing set it, and only the API layer sets it.
_is_user_request: ContextVar[bool] = ContextVar(
    "lightrag_is_user_request", default=False
)


def mark_user_request() -> object:
    """Mark this task as serving an authenticated end-user request."""
    return _is_user_request.set(True)


def is_user_request() -> bool:
    return _is_user_request.get()


def set_user_groups(groups: Iterable[str] | None) -> object:
    """Establish the caller's group set for this task.

    Returns the token needed to restore the previous value; callers that are not
    using :func:`user_groups_scope` are responsible for the reset.
    """
    if groups is None:
        return _current_user_groups.set(None)
    # Normalized once, here, so every consumer sees the same canonical form:
    # blanks dropped, duplicates removed, order stable. The cache key derived
    # from this must not vary with the order the identity provider happened to
    # return groups in, or two identical entitlements would produce two cache
    # entries.
    cleaned = sorted({g.strip() for g in groups if g and g.strip()})
    return _current_user_groups.set(tuple(cleaned))


def get_user_groups() -> tuple[str, ...] | None:
    """Return the caller's group set, or ``None`` if no identity is established."""
    return _current_user_groups.get()


def reset_user_groups(token: object) -> None:
    """Restore the value replaced by :func:`set_user_groups`."""
    _current_user_groups.reset(token)  # type: ignore[arg-type]


@contextmanager
def user_groups_scope(groups: Iterable[str] | None) -> Iterator[None]:
    """Bind ``groups`` for the duration of the block, then restore.

    Preferred over bare :func:`set_user_groups` anywhere the scope is known --
    tests, background tasks, and any code that reuses a task for more than one
    caller.
    """
    token = set_user_groups(groups)
    try:
        yield
    finally:
        reset_user_groups(token)


def to_pg_text_array(groups: Iterable[str]) -> str:
    """Render a group set as a PostgreSQL ``text[]`` literal.

    Produced for a **bind parameter**, never for interpolation into SQL. Group
    names originate in an external directory, so they are untrusted input for
    this purpose even though the directory itself is trusted: a display name
    containing a quote or a brace is enough to corrupt the literal, so both are
    escaped here as the array syntax requires.
    """
    escaped = []
    for g in groups:
        # Backslash first, or the escaping of the quote is itself re-escaped.
        e = g.replace("\\", "\\\\").replace('"', '\\"')
        escaped.append(f'"{e}"')
    return "{" + ",".join(escaped) + "}"


def acl_fingerprint(groups: tuple[str, ...] | None) -> str:
    """Return a stable, opaque fingerprint of a group set, for cache keys.

    Two callers with identical entitlements must share cache entries; two with
    different entitlements must not. Hashed rather than embedded verbatim so
    that group names -- which can disclose organizational structure -- are not
    recoverable from a cache key that may be logged or persisted.

    ``None`` (no identity) is deliberately given its own fingerprint distinct
    from the empty group set, mirroring the distinction documented above.
    """
    import hashlib

    if groups is None:
        return "noidentity"
    # The input is already sorted and de-duplicated by set_user_groups; the
    # separator is a character that cannot appear in a directory group name, so
    # ("a","bc") and ("ab","c") cannot collide.
    joined = "\x1f".join(groups)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32]
