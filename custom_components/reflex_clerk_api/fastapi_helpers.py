"""FastAPI integration helpers for token and passcode verification.

Provides ``Depends()``-compatible dependency functions, a pre-built router
factory, and a one-line registration helper for Reflex apps.

Quick start — protect a single endpoint::

    from reflex_clerk_api import validate_api_token, TokenVerification
    from fastapi import Depends

    @router.get("/protected")
    def my_endpoint(auth: TokenVerification = Depends(validate_api_token)):
        print(auth.user_id)

Quick start — register pre-built endpoints on a Reflex app::

    import reflex_clerk_api as clerk

    app = rx.App()
    clerk.wrap_app(app, publishable_key=..., token_prefix="myapp_", register_api=True)
    # Endpoints available: POST /auth/tokens/verify, POST /auth/passcodes/verify
"""

from __future__ import annotations

import reflex as rx
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from .clerk_provider import verify_passcode, verify_token
from .token_config import (
    PasscodeError,
    PasscodeVerification,
    TokenError,
    TokenVerification,
)

_bearer_scheme = HTTPBearer()


def validate_api_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> TokenVerification:
    """FastAPI dependency: validate an API token from the Authorization header.

    Extracts the Bearer token from the ``Authorization`` header and verifies it
    using :func:`verify_token`.

    Args:
        credentials: Automatically injected by FastAPI from the Authorization header.

    Returns:
        TokenVerification with ``user_id``, ``token_id``, and ``name``.

    Raises:
        HTTPException: 401 if the token is invalid, expired, revoked, or missing.

    Examples::

        @router.get("/protected")
        def my_endpoint(
            auth: TokenVerification = Depends(clerk.validate_api_token),
        ):
            return {"user_id": auth.user_id}
    """
    try:
        return verify_token(credentials.credentials)
    except TokenError as e:
        raise HTTPException(status_code=401, detail=str(e)) from e


class PasscodeBody(BaseModel):
    """Request body for passcode verification.

    Used by :func:`validate_passcode` to parse the incoming JSON body.

    Attributes:
        code: The passcode digits provided by the user.
        user_identifier: Email, phone, or other identifier used when issued.
        channel: The channel the passcode was issued for (default ``"default"``).
    """

    code: str
    user_identifier: str
    channel: str = "default"


def validate_passcode(
    body: PasscodeBody,
) -> PasscodeVerification:
    """FastAPI dependency: validate a passcode from the request body.

    Parses ``code``, ``user_identifier``, and ``channel`` from the JSON body
    and verifies using :func:`verify_passcode`.

    Args:
        body: Automatically parsed by FastAPI from the request JSON body.

    Returns:
        PasscodeVerification with ``user_id``, ``passcode_id``,
        ``user_identifier``, ``channel``.

    Raises:
        HTTPException: 401 if the passcode is invalid, expired, or not found.

    Examples::

        @router.post("/verify-code")
        def verify_code(
            v: PasscodeVerification = Depends(clerk.validate_passcode),
        ):
            return {"user_id": v.user_id}
    """
    try:
        return verify_passcode(
            code=body.code,
            user_identifier=body.user_identifier,
            channel=body.channel,
        )
    except PasscodeError as e:
        raise HTTPException(status_code=401, detail=str(e)) from e


def create_token_router(
    prefix: str = "/auth",
    tags: list[str] | None = None,
) -> APIRouter:
    """Create a FastAPI APIRouter with token and passcode verification endpoints.

    This is a convenience factory.  Consumers can also use
    :func:`validate_api_token` and :func:`validate_passcode` directly as
    dependencies on their own routes.

    Args:
        prefix: URL prefix for the router (default ``"/auth"``).
        tags: OpenAPI tags for the router (default ``["auth"]``).

    Returns:
        A FastAPI ``APIRouter`` with:

        - ``POST {prefix}/tokens/verify`` — verify a Bearer token
        - ``POST {prefix}/passcodes/verify`` — verify a passcode from body

    Examples::

        from reflex_clerk_api import create_token_router

        router = create_token_router(prefix="/auth")
        fastapi_app.include_router(router)
        # Endpoints: POST /auth/tokens/verify, POST /auth/passcodes/verify
    """
    if tags is None:
        tags = ["auth"]
    router = APIRouter(prefix=prefix, tags=tags)

    @router.post("/tokens/verify")
    def verify_token_endpoint(
        verification: TokenVerification = Depends(validate_api_token),
    ) -> dict:
        """Verify an API token from the Authorization: Bearer header."""
        return {
            "user_id": verification.user_id,
            "token_id": verification.token_id,
            "name": verification.name,
        }

    @router.post("/passcodes/verify")
    def verify_passcode_endpoint(
        verification: PasscodeVerification = Depends(validate_passcode),
    ) -> dict:
        """Verify a passcode from the request body."""
        return {
            "user_id": verification.user_id,
            "passcode_id": verification.passcode_id,
            "user_identifier": verification.user_identifier,
            "channel": verification.channel,
        }

    return router


def register_auth_api(
    app: rx.App,
    prefix: str = "/auth",
    tags: list[str] | None = None,
) -> APIRouter:
    """Register token/passcode verification endpoints on a Reflex app.

    Adds auth API routes to the app's ``api_transformer``.  If the app already
    has a ``FastAPI`` instance as its ``api_transformer``, routes are added to
    it.  Otherwise, a new ``FastAPI`` instance is created and set as the
    ``api_transformer``.

    Must be called **after** ``rx.App()`` creation and **before** the app
    starts serving (i.e., before ``reflex run``).

    Args:
        app: The Reflex app instance.
        prefix: URL prefix for auth routes (default ``"/auth"``).
        tags: OpenAPI tags (default ``["auth"]``).

    Returns:
        The ``APIRouter`` that was registered (for further customisation).

    Examples::

        app = rx.App()
        clerk.register_auth_api(app)
        # Endpoints: POST /auth/tokens/verify, POST /auth/passcodes/verify

    For apps that already use ``api_transformer``::

        fastapi_app = FastAPI()
        fastapi_app.include_router(my_other_router)
        app = rx.App(api_transformer=fastapi_app)
        clerk.register_auth_api(app)  # adds to existing FastAPI instance
    """
    router = create_token_router(prefix=prefix, tags=tags)

    if isinstance(app.api_transformer, FastAPI):
        app.api_transformer.include_router(router)
    else:
        fastapi_app = FastAPI()
        fastapi_app.include_router(router)
        app.api_transformer = fastapi_app

    return router
