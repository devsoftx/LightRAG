"""Third-party SSO provider discovery (``lightrag.sso_providers`` entry points).

A third-party package exposes an identity provider by declaring an entry point
in the ``lightrag.sso_providers`` group::

    # pyproject.toml of the third-party package
    [project.entry-points."lightrag.sso_providers"]
    okta = "my_pkg.lightrag_sso:register"

Each entry point must resolve to a **zero-argument callable** that performs its
own :func:`lightrag.api.sso.registry.register_provider` call(s).  Keep it
import-cheap: defer the implementation import to the ``SSOProviderSpec.impl``
string, which the registry loads lazily.

**Why this loader fails hard.**  :func:`lightrag.parser.plugins.load_third_party_parsers`
deliberately logs and skips a broken plugin, because a missing parser engine
degrades one document.  The same behaviour here would be a security fault: a
deployment configured with ``SSO_ENABLED=true`` whose provider failed to load
would start *without* the authentication its operator asked for.  A failure to
load a plugin is therefore logged and re-raised, so the server refuses to start
rather than serving an unexpectedly open instance.
"""

from __future__ import annotations

from importlib.metadata import entry_points

from lightrag.utils import logger

ENTRY_POINT_GROUP = "lightrag.sso_providers"

_loaded = False


class SSOPluginLoadError(RuntimeError):
    """A ``lightrag.sso_providers`` entry point failed to load."""


def load_sso_providers(*, force: bool = False) -> list[str]:
    """Discover and run all ``lightrag.sso_providers`` entry points.

    Idempotent per process (``force=True`` re-runs, for tests).  Returns the
    names of the entry points that registered successfully.

    Raises :class:`SSOPluginLoadError` if any entry point raises -- see the
    module docstring for why this does not degrade gracefully.
    """
    global _loaded
    if _loaded and not force:
        return []
    _loaded = True

    loaded: list[str] = []
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            register = ep.load()
            register()
        except Exception as exc:  # noqa: BLE001 - re-raised below
            logger.error(
                "[sso-plugins] failed to load SSO provider plugin %r (%s): %s",
                ep.name,
                ep.value,
                exc,
            )
            raise SSOPluginLoadError(
                f"SSO provider plugin {ep.name!r} ({ep.value}) failed to load: {exc}. "
                "Refusing to start: a server configured for SSO must not fall back "
                "to an unauthenticated profile."
            ) from exc
        loaded.append(ep.name)
        logger.info(
            "[sso-plugins] loaded SSO provider plugin %r (%s)", ep.name, ep.value
        )
    return loaded


def reset_loaded_flag_for_tests() -> None:
    global _loaded
    _loaded = False
