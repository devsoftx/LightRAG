"""Registry and entry-point loader tests.

The loader deliberately diverges from
:func:`lightrag.parser.plugins.load_third_party_parsers`, which logs and skips a
broken plugin.  Doing that here would let a server configured with
``SSO_ENABLED=true`` start *without* the authentication its operator asked for,
so a failure must abort startup instead.  That difference is pinned below.
"""

from __future__ import annotations

import pytest

from lightrag.api.sso import plugins, registry
from lightrag.api.sso.spec import SSOProviderSpec


@pytest.fixture(autouse=True)
def _clean_registry():
    registry.reset_registry_for_tests()
    plugins.reset_loaded_flag_for_tests()
    yield
    registry.reset_registry_for_tests()
    plugins.reset_loaded_flag_for_tests()


class _FakeEntryPoint:
    """Stand-in for importlib.metadata.EntryPoint (name/value/load)."""

    def __init__(self, name, value, result):
        self.name = name
        self.value = value
        self._result = result

    def load(self):
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def _install_eps(monkeypatch, eps):
    monkeypatch.setattr(plugins, "entry_points", lambda group=None: list(eps))


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


def test_entra_is_registered_by_default():
    assert "entra" in registry.supported_providers()


def test_unknown_provider_raises():
    with pytest.raises(registry.SSOProviderError, match="Unknown SSO provider"):
        registry.get_provider("does-not-exist")


def test_incompatible_api_version_refused():
    """A drifted provider must fail at registration, not mid-login."""
    with pytest.raises(registry.SSOProviderError, match="api_version"):
        registry.register_provider(
            SSOProviderSpec(name="old", impl="x:Y", api_version=999)
        )


def test_malformed_impl_raises():
    registry.register_provider(SSOProviderSpec(name="bad", impl="no-colon"))
    with pytest.raises(registry.SSOProviderError, match="malformed impl"):
        registry.get_provider("bad")


def test_unimportable_provider_raises():
    registry.register_provider(
        SSOProviderSpec(name="ghost", impl="lightrag.does.not.exist:Provider")
    )
    with pytest.raises(registry.SSOProviderError, match="Failed to import"):
        registry.get_provider("ghost")


def test_provider_instances_are_cached():
    assert registry.get_provider("entra") is registry.get_provider("entra")


def test_third_party_override_of_builtin_is_logged(monkeypatch):
    """Shadowing a built-in identity provider must never be silent.

    Asserted against the logger directly rather than via ``caplog``: the
    ``lightrag`` logger does not propagate to the root handler pytest captures.
    """
    warnings: list[str] = []
    monkeypatch.setattr(
        registry.logger,
        "warning",
        lambda msg, *args, **kw: warnings.append(msg % args if args else msg),
    )
    registry.register_provider(
        SSOProviderSpec(name="entra", impl="some.other:Provider")
    )
    assert any("overrides the built-in" in w for w in warnings)


def test_registering_same_builtin_impl_is_not_flagged(monkeypatch):
    """Re-registering the identical built-in is a no-op, not an override."""
    warnings: list[str] = []
    monkeypatch.setattr(
        registry.logger, "warning", lambda msg, *a, **kw: warnings.append(msg)
    )
    registry.register_provider(
        SSOProviderSpec(
            name="entra", impl="lightrag.api.sso.providers.entra:EntraProvider"
        )
    )
    assert warnings == []


# --------------------------------------------------------------------------
# Entry-point loader
# --------------------------------------------------------------------------


def test_loader_registers_plugin(monkeypatch):
    def _register():
        registry.register_provider(
            SSOProviderSpec(name="okta", impl="my_pkg.sso:OktaProvider")
        )

    _install_eps(
        monkeypatch, [_FakeEntryPoint("okta", "my_pkg.sso:register", _register)]
    )
    assert plugins.load_sso_providers() == ["okta"]
    assert "okta" in registry.supported_providers()


def test_loader_is_idempotent(monkeypatch):
    calls = []

    def _register():
        calls.append(1)
        registry.register_provider(SSOProviderSpec(name="okta", impl="a:B"))

    _install_eps(monkeypatch, [_FakeEntryPoint("okta", "a:register", _register)])
    plugins.load_sso_providers()
    plugins.load_sso_providers()
    assert len(calls) == 1
    assert plugins.load_sso_providers(force=True) == ["okta"]


def test_broken_plugin_aborts_startup(monkeypatch):
    """The security-critical divergence from the parser loader.

    A parser plugin that fails is skipped; an SSO provider that fails must stop
    the server, or it would come up unauthenticated.
    """
    _install_eps(
        monkeypatch,
        [_FakeEntryPoint("broken", "bad.mod:register", ImportError("boom"))],
    )
    with pytest.raises(plugins.SSOPluginLoadError, match="Refusing to start"):
        plugins.load_sso_providers()
