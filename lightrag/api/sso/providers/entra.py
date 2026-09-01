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

        # Entitlements are the UNION of app roles and group memberships, not a
        # choice between them. Preferring one claim over the other silently
        # drops half a user's access when both are configured -- and because
        # 'groups' emits opaque object IDs while 'roles' emits the string
        # values chosen on the app registration, picking 'groups' first would
        # shadow readable role names with GUIDs that match no ACL.
        #
        # Claim availability differs sharply between the two:
        #
        # - 'roles' appears only for app roles ASSIGNED to this user under
        #   Enterprise applications > Users and groups. Defining a role is not
        #   enough. Values are whatever the registration declares, so ACLs can
        #   read 'Sec-Fin-Admins' rather than a GUID, and they do not overflow.
        # - 'groups' appears only when the registration requests it under Token
        #   configuration, per token type -- it must be enabled for the ID
        #   token, which is what is verified here. Above the token size limit
        #   Entra substitutes '_claim_names'/'_claim_sources' (the Graph
        #   overage indicator) and omits 'groups' entirely.
        #
        # Either way an unconfigured or overflowing app yields nothing, so an
        # SSO_ALLOWED_GROUPS check correctly denies rather than silently
        # admitting.
        collected: list[str] = []
        for claim_name in ("roles", "groups"):
            raw = claims.get(claim_name) or []
            if isinstance(raw, str):
                raw = [raw]
            if isinstance(raw, (list, tuple)):
                collected.extend(str(g).strip() for g in raw if str(g).strip())
        # De-duplicated but order-insensitive; set_user_groups sorts downstream.
        groups = tuple(dict.fromkeys(collected))

        return IdentityClaims(
            subject=subject, username=username, groups=groups, raw=dict(claims)
        )
