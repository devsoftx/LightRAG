"""Central registry for SSO identity providers.

Follows the storage/parser convention: a module-level literal table of
lightweight :class:`~lightrag.api.sso.spec.SSOProviderSpec` metadata, with the
implementation imported lazily via :func:`get_provider`.  Built-ins are
registered statically here; third parties overlay through the
``lightrag.sso_providers`` entry point group (see
:mod:`lightrag.api.sso.plugins`).
"""

from __future__ import annotations

import importlib

from lightrag.utils import logger

from .spec import SSO_PROVIDER_API_VERSION, SSOProvider, SSOProviderSpec

_BUILTIN_SPECS: dict[str, SSOProviderSpec] = {
    "entra": SSOProviderSpec(
        name="entra",
        impl="lightrag.api.sso.providers.entra:EntraProvider",
        required_env=("SSO_TENANT_ID", "SSO_CLIENT_ID", "SSO_CLIENT_SECRET"),
        description="Microsoft Entra ID (single tenant)",
    ),
}

_REGISTRY: dict[str, SSOProviderSpec] = dict(_BUILTIN_SPECS)

# Provider instances are stateless and cheap to keep; cache by (name, impl) so a
# re-registration under the same name with a different impl is not served stale.
_INSTANCE_CACHE: dict[tuple[str, str], SSOProvider] = {}


class SSOProviderError(RuntimeError):
    """Raised when a provider cannot be registered or resolved."""


def register_provider(spec: SSOProviderSpec) -> None:
    """Register (or override) an identity provider spec.

    Unlike the parser registry this refuses an incompatible ``api_version``.
    A provider whose protocol has drifted would fail somewhere inside a login
    handshake, where the symptom is an opaque authentication error; rejecting
    it here turns that into a clear startup failure.
    """
    if spec.api_version != SSO_PROVIDER_API_VERSION:
        raise SSOProviderError(
            f"SSO provider {spec.name!r} declares api_version={spec.api_version}, "
            f"but this LightRAG expects {SSO_PROVIDER_API_VERSION}."
        )
    if not spec.name or not spec.impl:
        raise SSOProviderError("SSO provider spec requires both 'name' and 'impl'.")
    if spec.name in _BUILTIN_SPECS and spec.impl != _BUILTIN_SPECS[spec.name].impl:
        # Allowed, but never silently: a third party shadowing a built-in
        # identity provider is a security-relevant change to how users
        # authenticate, so it must be visible in the startup log.
        logger.warning(
            "[sso] third-party provider %r overrides the built-in implementation "
            "(%s -> %s)",
            spec.name,
            _BUILTIN_SPECS[spec.name].impl,
            spec.impl,
        )
    _REGISTRY[spec.name] = spec
    _INSTANCE_CACHE.pop((spec.name, spec.impl), None)


def provider_specs_snapshot() -> dict[str, SSOProviderSpec]:
    """Return a shallow snapshot of the registry."""
    return dict(_REGISTRY)


def supported_providers() -> list[str]:
    return sorted(_REGISTRY)


def get_spec(name: str) -> SSOProviderSpec | None:
    return _REGISTRY.get(name)


def get_provider(name: str) -> SSOProvider:
    """Return a cached provider instance, importing its module lazily.

    Raises :class:`SSOProviderError` when the name is unknown or the
    implementation cannot be imported.  Callers must not degrade to
    "no SSO" on failure -- a deployment configured for SSO that silently
    starts without it is an availability *and* security regression.
    """
    spec = _REGISTRY.get(name)
    if spec is None:
        raise SSOProviderError(
            f"Unknown SSO provider {name!r}. Available: {', '.join(supported_providers())}"
        )

    cache_key = (spec.name, spec.impl)
    instance = _INSTANCE_CACHE.get(cache_key)
    if instance is not None:
        return instance

    module_path, _, attr = spec.impl.partition(":")
    if not attr:
        raise SSOProviderError(
            f"SSO provider {name!r} has a malformed impl {spec.impl!r}; "
            "expected 'module:Class'."
        )
    try:
        module = importlib.import_module(module_path)
        cls = getattr(module, attr)
    except Exception as exc:  # noqa: BLE001 - surfaced verbatim to the operator
        raise SSOProviderError(
            f"Failed to import SSO provider {name!r} from {spec.impl!r}: {exc}"
        ) from exc

    instance = cls()
    _INSTANCE_CACHE[cache_key] = instance
    return instance


def reset_registry_for_tests() -> None:
    """Restore the built-in table. Test helper only."""
    _REGISTRY.clear()
    _REGISTRY.update(_BUILTIN_SPECS)
    _INSTANCE_CACHE.clear()
