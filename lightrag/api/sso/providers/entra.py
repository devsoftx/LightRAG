"""Microsoft Entra ID (single tenant) identity provider.

Adapts Entra's dialect of OIDC: the v2.0 endpoints, and the claim names Entra
uses for identity and group membership.  It makes no security decisions --
see :mod:`lightrag.api.sso.core`.

Stateless by contract: every method takes the resolved ``settings`` rather than
reading global configuration, so the provider is unit-testable in isolation and
cannot depend on ambient state the core did not validate.
"""

from __future__ import annotations

from typing import Any, Mapping

from lightrag.api.sso.spec import IdentityClaims

_AUTHORITY = "https://login.microsoftonline.com"


class EntraProvider:
    """Single-tenant Entra ID.

    Single tenant is deliberate: :meth:`issuer` embeds the tenant id, and the
    core pins the token's ``iss`` claim to it.  A token issued by Entra for a
    *different* tenant carries a valid Microsoft signature, so without that pin
    any Microsoft account in the world would authenticate here.  Supporting
    multi-tenant would mean replacing the pin with an explicit tenant
    allow-list -- never with the ``organizations`` / ``common`` wildcard
    issuers.
    """

    @staticmethod
    def _tenant(settings: Any) -> str:
        tenant = (getattr(settings, "tenant_id", None) or "").strip()
        if not tenant:
            raise ValueError("SSO_TENANT_ID must be set for the 'entra' SSO provider.")
        return tenant

    def issuer(self, settings: Any) -> str:
        return f"{_AUTHORITY}/{self._tenant(settings)}/v2.0"

    def discovery_url(self, settings: Any) -> str:
        return (
            f"{_AUTHORITY}/{self._tenant(settings)}"
            "/v2.0/.well-known/openid-configuration"
        )

    def authorize_params(self, settings: Any) -> dict[str, str]:
        # Restrict the account picker to this tenant's directory. Defence in
        # depth only: the issuer pin in the core is what actually enforces it.
        return {"prompt": "select_account"}

    def map_claims(self, claims: Mapping[str, Any]) -> IdentityClaims:
        # 'oid' is the immutable per-tenant object id; 'sub' is pairwise and
        # differs per application, so 'oid' is the stable identity to record.
        subject = str(claims.get("oid") or claims.get("sub") or "").strip()
        if not subject:
            raise ValueError("Entra id_token contained neither 'oid' nor 'sub'.")

        username = str(
            claims.get("preferred_username")
            or claims.get("email")
            or claims.get("upn")
            or subject
        ).strip()

        # Entra emits 'groups' only when the app registration requests the
        # groups claim. Above the token-size limit it substitutes
        # '_claim_names'/'_claim_sources' (the Graph overage indicator) and
        # omits 'groups' entirely -- so an unconfigured or overflowing app
        # yields no groups, and any SSO_ALLOWED_GROUPS check will correctly
        # deny rather than silently admit. 'roles' (app roles) is accepted as
        # an equivalent, and is the recommended shape for large directories.
        raw_groups = claims.get("groups") or claims.get("roles") or []
        if isinstance(raw_groups, str):
            raw_groups = [raw_groups]
        groups = tuple(str(g).strip() for g in raw_groups if str(g).strip())

        return IdentityClaims(
            subject=subject, username=username, groups=groups, raw=dict(claims)
        )
