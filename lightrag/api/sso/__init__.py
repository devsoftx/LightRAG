"""Pluggable single sign-on (OIDC authorization code + PKCE).

Enabled entirely by configuration (``SSO_ENABLED`` and the ``SSO_*`` variables
in ``.env``).  When disabled nothing here is imported and authentication
behaves exactly as it did before.

Layering, and why it is split this way:

- :mod:`.spec` / :mod:`.registry` / :mod:`.plugins` -- the pluggable surface.
  A provider describes one identity provider's endpoints and claim shape.
- :mod:`.core` -- the security core.  **Not pluggable.**  PKCE, state/nonce,
  JWKS, signature/issuer/audience/nonce verification, group authorization,
  role mapping and session minting all live here.

A third-party provider can therefore cause a failed login but can never mint a
session or weaken its validation.  See ``docs/EntraIDSSO.md``.
"""

from .core import SSOError, SSOFlow, SSOSettings
from .plugins import SSOPluginLoadError, load_sso_providers
from .registry import (
    SSOProviderError,
    get_provider,
    provider_specs_snapshot,
    register_provider,
    supported_providers,
)
from .routes import create_sso_router, sso_whitelist_paths
from .spec import IdentityClaims, SSOProvider, SSOProviderSpec

__all__ = [
    "IdentityClaims",
    "SSOError",
    "SSOFlow",
    "SSOPluginLoadError",
    "SSOProvider",
    "SSOProviderError",
    "SSOProviderSpec",
    "SSOSettings",
    "create_sso_router",
    "get_provider",
    "load_sso_providers",
    "provider_specs_snapshot",
    "register_provider",
    "sso_whitelist_paths",
    "supported_providers",
]
