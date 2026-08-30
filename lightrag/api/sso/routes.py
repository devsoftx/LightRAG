"""SSO HTTP routes: ``/auth/sso/login``, ``/auth/sso/callback``, ``/auth/sso/logout``.

These endpoints must be reachable *before* the caller holds a session, so they
are added to the auth whitelist by :func:`sso_whitelist_paths`.  That is safe
because neither one grants anything on its own: ``/login`` only issues a
redirect, and ``/callback`` mints a session solely after the core has fully
verified an ``id_token``.
"""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import RedirectResponse

from lightrag.utils import logger

from .core import SSOError, SSOFlow, SSOSettings

# Unauthenticated by necessity; see module docstring.
SSO_LOGIN_PATH = "/auth/sso/login"
SSO_CALLBACK_PATH = "/auth/sso/callback"
SSO_LOGOUT_PATH = "/auth/sso/logout"


def sso_whitelist_paths() -> tuple[str, ...]:
    return (SSO_LOGIN_PATH, SSO_CALLBACK_PATH, SSO_LOGOUT_PATH)


def _safe_return_to(value: str | None) -> str | None:
    """Allow only same-origin relative paths as a post-login destination.

    ``return_to`` is attacker-controllable, so anything absolute or
    protocol-relative is discarded: echoing it into a redirect would turn this
    endpoint into an open redirect, and a convincing one, because the hop
    starts at the customer's real login URL.
    """
    if not value:
        return None
    if not value.startswith("/") or value.startswith("//"):
        return None
    return value


def create_sso_router(args, auth_handler, *, login_rate_limiter=None) -> APIRouter:
    """Build the SSO router. Called only when SSO_ENABLED is true."""
    router = APIRouter(tags=["authentication"])
    settings = SSOSettings.from_args(args)
    # Constructed once: resolves the provider (failing fast on an unknown name)
    # and holds the discovery/JWKS caches and the transaction store.
    flow = SSOFlow(settings)

    logger.info(
        "[sso] enabled provider=%s redirect_uri=%s groups_enforced=%s",
        settings.provider,
        settings.redirect_uri,
        bool(settings.allowed_groups),
    )

    def _failure_redirect(message: str) -> RedirectResponse:
        # Errors go back to the login page as a query parameter rather than a
        # raw 4xx body, so a browser mid-redirect lands somewhere usable.
        return RedirectResponse(
            url=f"/webui/?{urlencode({'sso_error': message})}", status_code=303
        )

    @router.get(SSO_LOGIN_PATH, include_in_schema=False)
    async def sso_login(return_to: str | None = Query(default=None)):
        try:
            url = await flow.build_authorize_url(return_to=_safe_return_to(return_to))
        except SSOError as exc:
            logger.error("[sso] could not start login: %s", exc)
            return _failure_redirect(str(exc))
        return RedirectResponse(url=url, status_code=303)

    @router.get(SSO_CALLBACK_PATH, include_in_schema=False)
    async def sso_callback(
        request: Request,
        code: str | None = Query(default=None),
        state: str | None = Query(default=None),
        error: str | None = Query(default=None),
        error_description: str | None = Query(default=None),
    ):
        if error:
            logger.warning("[sso] provider returned error=%s", error)
            return _failure_redirect(error_description or error)
        if not code or not state:
            return _failure_redirect("Malformed sign-in response.")

        # Same brute-force protection as /login, using the identical
        # reserve -> commit_failure/reset -> release contract. The callback
        # performs network calls and public-key cryptography, so it is a usable
        # amplification target even though no password is involved (CWE-307).
        # Keyed by client IP only: unlike /login there is no attacker-supplied
        # username, and the state parameter is single-use by construction.
        client_ip = request.client.host if request.client else "unknown"
        rate_limit_key = f"{client_ip}:sso"

        if login_rate_limiter is not None:
            retry_after = login_rate_limiter.retry_after(rate_limit_key)
            if retry_after is not None:
                return _failure_redirect(
                    "Too many sign-in attempts. Please try again later."
                )
            # Reserved before the awaits below, for the same TOCTOU reason as
            # /login: without it, concurrent callbacks would all pass the check
            # above before any of them resolved.
            login_rate_limiter.reserve_attempt(rate_limit_key)

        try:
            identity, role, return_to = await flow.complete(code=code, state=state)
        except SSOError as exc:
            if login_rate_limiter is not None:
                login_rate_limiter.commit_failure(rate_limit_key)
            logger.warning("[sso] sign-in failed: %s", exc)
            return _failure_redirect(str(exc))
        else:
            if login_rate_limiter is not None:
                login_rate_limiter.reset(rate_limit_key)
        finally:
            if login_rate_limiter is not None:
                login_rate_limiter.release(rate_limit_key)

        token = auth_handler.create_token(
            username=identity.username,
            role=role,
            custom_expire_hours=settings.session_ttl_hours,
            metadata={
                "auth_mode": "sso",
                "sso_provider": settings.provider,
                "sso_subject": identity.subject,
            },
        )
        logger.info("[sso] sign-in succeeded for %r role=%s", identity.username, role)

        destination = return_to or settings.post_login_redirect
        # The token rides in the fragment: fragments are not sent to servers and
        # do not appear in access logs or Referer headers, unlike a query string.
        # The WebUI reads it on load and moves it into localStorage, matching how
        # the password flow already stores its token.
        return RedirectResponse(
            url=f"{destination}#{urlencode({'access_token': token, 'token_type': 'bearer'})}",
            status_code=303,
        )

    @router.get(SSO_LOGOUT_PATH, include_in_schema=False)
    async def sso_logout():
        # LightRAG sessions are stateless JWTs, so there is nothing server-side
        # to revoke; the WebUI clears its stored token. The redirect ends the
        # identity provider's own session so the next sign-in re-authenticates
        # instead of silently reusing it.
        try:
            metadata = await flow._discovery()  # noqa: SLF001 - same package
            end_session = metadata.get("end_session_endpoint")
        except SSOError:
            end_session = None
        if not end_session:
            return RedirectResponse(url="/webui/", status_code=303)
        return RedirectResponse(
            url=f"{end_session}?{urlencode({'post_logout_redirect_uri': settings.redirect_uri.rsplit('/auth/', 1)[0] + '/webui/'})}",
            status_code=303,
        )

    return router
