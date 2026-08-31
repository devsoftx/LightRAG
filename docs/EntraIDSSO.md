# Single Sign-On with Microsoft Entra ID

LightRAG supports OIDC single sign-on using the authorization code flow with
PKCE. It is enabled entirely by configuration — no code changes — and the
identity provider is pluggable. Entra ID (single tenant) ships built in.

## 1. Quick start

Register an application in Entra ID, then set the following in `.env`:

```bash
SSO_ENABLED=true
SSO_PROVIDER=entra
SSO_TENANT_ID=<directory (tenant) ID>
SSO_CLIENT_ID=<application (client) ID>
SSO_CLIENT_SECRET=<client secret value>
SSO_REDIRECT_URI=https://lightrag.example.com/auth/sso/callback

# Required: SSO signs real sessions, so the default JWT secret is refused.
TOKEN_SECRET=<a long random string>
```

In the Entra app registration:

- **Redirect URI** (type *Web*) must exactly equal `SSO_REDIRECT_URI`.
- **Implicit grant**: leave both checkboxes off. LightRAG uses the code flow.
- **Token configuration**: add the optional **groups** claim only if you intend
  to use `SSO_ALLOWED_GROUPS` or `SSO_ROLE_MAPPING`.

Restart the server. The login page shows **Sign in with Microsoft**.

## 2. How the flow works

```
Browser ──1── GET /auth/sso/login ──► 303 to Entra (PKCE challenge + state + nonce)
        ◄─2── user authenticates at Microsoft
        ──3── GET /auth/sso/callback?code=…&state=… ──► LightRAG
                 ├─ consume state (single use, TTL bounded)
                 ├─ exchange code + PKCE verifier for an id_token
                 ├─ verify signature (JWKS), iss, aud, exp, nonce
                 ├─ apply SSO_ALLOWED_GROUPS, then SSO_ROLE_MAPPING
                 └─ mint the ordinary LightRAG session JWT
        ◄─4── 303 to /webui/#access_token=…
```

Two consequences worth knowing:

- **The browser never receives Entra's `id_token`.** It is redeemed
  server-side and exchanged for the same LightRAG JWT that password login
  issues, so every existing route keeps its single `combined_auth` dependency
  and the blast radius of a stolen browser token is unchanged.
- **The session token arrives in the URL fragment**, not a query string.
  Fragments are never sent to a server, so the token stays out of access logs
  and `Referer` headers. The WebUI consumes it on load and strips it from the
  address bar.

## 3. Authorization

Authentication (*who are you*) is Entra's job. Authorization (*may you use this
deployment*) is LightRAG's:

```bash
# A user must hold at least one of these group object IDs.
SSO_ALLOWED_GROUPS=<group-oid>,<group-oid>

# First match wins; unmatched users get SSO_DEFAULT_ROLE.
SSO_ROLE_MAPPING=<admins-group-oid>:admin,<users-group-oid>:user
SSO_DEFAULT_ROLE=user
```

Leaving `SSO_ALLOWED_GROUPS` empty admits **any** user the tenant
authenticates. On a tenant with external guests, that is probably not what you
want.

> **Groups claim caveat.** Entra emits `groups` only when the app registration
> requests it, and above the token size limit it replaces the claim with a
> Graph overage indicator and omits `groups` entirely. Either way the user
> arrives with *no* groups, and any `SSO_ALLOWED_GROUPS` check will deny them.
> Failing closed is deliberate. For large directories prefer **app roles**
> (the `roles` claim), which LightRAG accepts identically and which do not
> overflow.

## 4. Security properties

| Control | Where |
|---|---|
| PKCE (S256) | `sso/core.py` — code is useless without the verifier |
| `state`, single-use + TTL | `TransactionStore.consume` deletes before returning |
| `nonce` | compared in constant time against the authorize request |
| Signature | JWKS, **RS256 only** — `none` and symmetric algorithms refused |
| Issuer pinned | `https://login.microsoftonline.com/<tenant>/v2.0` |
| Audience pinned | `SSO_CLIENT_ID` |
| Brute force | callback shares `/login`'s `LoginRateLimiter` |
| Open redirect | `return_to` accepts same-origin relative paths only |

**Why the issuer pin matters.** A token minted by Entra for a *different*
tenant carries a valid Microsoft signature. Without pinning `iss` to your
tenant, any Microsoft account in the world would authenticate. This is the
reason the built-in provider is single-tenant; supporting multi-tenant means an
explicit tenant allow-list, never the `common` / `organizations` wildcard
issuers.

**Enabling SSO changes the guest profile.** Without `AUTH_ACCOUNTS`, LightRAG
normally issues a *guest* token signed with a public default secret. That is
fine on a deliberately open instance and catastrophic next to SSO, so
`SSO_ENABLED=true` makes the server count as authenticated: `/auth-status`
stops issuing guest tokens, `/login` refuses password auth when no local
accounts exist, and startup fails if `TOKEN_SECRET` is unset or default.

## 5. Deployment notes

**Multi-worker.** In-flight logins live in process memory. Under gunicorn with
several workers the callback must reach the worker that started the login —
use sticky sessions, or run a single worker. Otherwise sign-in fails with
*"Login session is invalid or has already been used."*

**Break-glass.** Keep `AUTH_ACCOUNTS` set alongside SSO so you can still sign
in if the identity provider is unreachable. With it empty, SSO is the only way
in.

**Client secret.** `SSO_CLIENT_SECRET` sits in `.env` at rest and expires on
Entra's schedule. For production prefer a secret manager, or
**workload identity federation**, which removes the secret entirely.

## 6. Adding another identity provider

Providers are discovered through the `lightrag.sso_providers` entry point
group, the same mechanism as third-party parsers:

```toml
# pyproject.toml of your package
[project.entry-points."lightrag.sso_providers"]
okta = "my_pkg.lightrag_sso:register"
```

```python
# my_pkg/lightrag_sso.py — keep this import-cheap
from lightrag.api.sso import SSOProviderSpec, register_provider

def register() -> None:
    register_provider(SSOProviderSpec(
        name="okta",
        impl="my_pkg.okta_provider:OktaProvider",   # imported lazily
        required_env=("SSO_TENANT_ID", "SSO_CLIENT_ID", "SSO_CLIENT_SECRET"),
    ))
```

A provider implements four pure methods — `issuer(settings)`,
`discovery_url(settings)`, `authorize_params(settings)` and
`map_claims(claims)` — and is otherwise stateless.

### What a provider deliberately cannot do

Providers describe *where* an identity provider lives and *how its claims are
shaped*. They make no security decisions: PKCE, state/nonce, JWKS, signature
and issuer/audience/expiry verification, group authorization, role mapping and
session minting all live in `lightrag/api/sso/core.py`, which is not pluggable.

A defective or hostile provider can therefore cause a **failed login**, but can
never mint a session or weaken the validation of one. This is why the loader —
unlike `lightrag.parser.plugins`, which logs and skips broken plugins — **fails
hard**: a server told to use SSO must never start without it.

## 7. Troubleshooting

| Symptom | Cause |
|---|---|
| Startup: `TOKEN_SECRET must be explicitly set…` | Set a real `TOKEN_SECRET`. |
| Startup: `SSO_REDIRECT_URI must use https://` | Only loopback may use http. |
| `AADSTS50011: redirect URI mismatch` | Entra's registered URI ≠ `SSO_REDIRECT_URI`, exactly. |
| `Login session is invalid or has already been used` | Replayed callback, expired state, server restart, or multi-worker without sticky sessions. |
| `Your account is not authorized` | Not in `SSO_ALLOWED_GROUPS` — or the groups claim is not being emitted (see §3). |
| `Identity token failed validation: Invalid audience` | `SSO_CLIENT_ID` does not match the app the token was issued for. |
