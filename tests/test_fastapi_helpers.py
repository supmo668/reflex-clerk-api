"""Tests for FastAPI integration helpers.

These tests verify:
- PasscodeBody model construction and validation
- validate_api_token exception → HTTPException mapping (mocked verify_token)
- validate_passcode exception → HTTPException mapping (mocked verify_passcode)
- create_token_router structure and configuration
- register_auth_api app integration
- End-to-end HTTP via FastAPI TestClient (mocked verify functions)
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from custom_components.reflex_clerk_api.fastapi_helpers import (
    PasscodeBody,
    create_token_router,
    register_auth_api,
    validate_api_token,
    validate_passcode,
)
from custom_components.reflex_clerk_api.token_config import (
    ExpiredPasscodeError,
    ExpiredTokenError,
    InvalidPasscodeError,
    InvalidTokenError,
    PasscodeError,
    PasscodeVerification,
    RevokedTokenError,
    TokenError,
    TokenVerification,
)

# ---------------------------------------------------------------------------
# PasscodeBody model tests
# ---------------------------------------------------------------------------


class TestPasscodeBody:
    """Tests for the PasscodeBody Pydantic model."""

    def test_construction(self):
        body = PasscodeBody(
            code="847291",
            user_identifier="jane@example.com",
            channel="email",
        )
        assert body.code == "847291"
        assert body.user_identifier == "jane@example.com"
        assert body.channel == "email"

    def test_default_channel(self):
        body = PasscodeBody(code="123456", user_identifier="user@test.com")
        assert body.channel == "default"

    def test_model_fields(self):
        fields = set(PasscodeBody.model_fields.keys())
        assert fields == {"code", "user_identifier", "channel"}


# ---------------------------------------------------------------------------
# validate_api_token tests (mocked verify_token)
# ---------------------------------------------------------------------------


class TestValidateApiToken:
    """Tests for validate_api_token FastAPI dependency."""

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_token")
    def test_success(self, mock_verify):
        """Successful verification returns TokenVerification."""
        expected = TokenVerification(
            user_id="user_abc", token_id="tok-1", name="My Key"
        )
        mock_verify.return_value = expected
        creds = MagicMock()
        creds.credentials = "myapp_abc123_secretpart"

        result = validate_api_token(credentials=creds)
        assert result == expected
        mock_verify.assert_called_once_with("myapp_abc123_secretpart")

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_token")
    def test_token_error_raises_401(self, mock_verify):
        mock_verify.side_effect = TokenError("Token issuance not configured.")
        creds = MagicMock()
        creds.credentials = "bad_token"

        with pytest.raises(Exception) as exc_info:
            validate_api_token(credentials=creds)
        assert exc_info.value.status_code == 401
        assert "not configured" in exc_info.value.detail

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_token")
    def test_invalid_token_raises_401(self, mock_verify):
        mock_verify.side_effect = InvalidTokenError("Token prefix does not match")
        creds = MagicMock()
        creds.credentials = "wrong_prefix"

        with pytest.raises(Exception) as exc_info:
            validate_api_token(credentials=creds)
        assert exc_info.value.status_code == 401
        assert "prefix" in exc_info.value.detail

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_token")
    def test_expired_token_raises_401(self, mock_verify):
        mock_verify.side_effect = ExpiredTokenError("Token has expired")
        creds = MagicMock()
        creds.credentials = "expired_token"

        with pytest.raises(Exception) as exc_info:
            validate_api_token(credentials=creds)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_token")
    def test_revoked_token_raises_401(self, mock_verify):
        mock_verify.side_effect = RevokedTokenError("Token has been revoked")
        creds = MagicMock()
        creds.credentials = "revoked_token"

        with pytest.raises(Exception) as exc_info:
            validate_api_token(credentials=creds)
        assert exc_info.value.status_code == 401
        assert "revoked" in exc_info.value.detail

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_token")
    def test_exception_chaining(self, mock_verify):
        """HTTPException should chain the original exception."""
        original = InvalidTokenError("Token not found")
        mock_verify.side_effect = original
        creds = MagicMock()
        creds.credentials = "unknown"

        with pytest.raises(Exception) as exc_info:
            validate_api_token(credentials=creds)
        assert exc_info.value.__cause__ is original


# ---------------------------------------------------------------------------
# validate_passcode tests (mocked verify_passcode)
# ---------------------------------------------------------------------------


class TestValidatePasscode:
    """Tests for validate_passcode FastAPI dependency."""

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_passcode")
    def test_success(self, mock_verify):
        expected = PasscodeVerification(
            user_id="user_abc",
            passcode_id="pc-1",
            user_identifier="jane@example.com",
            channel="email",
        )
        mock_verify.return_value = expected
        body = PasscodeBody(
            code="847291", user_identifier="jane@example.com", channel="email"
        )

        result = validate_passcode(body=body)
        assert result == expected
        mock_verify.assert_called_once_with(
            code="847291", user_identifier="jane@example.com", channel="email"
        )

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_passcode")
    def test_passcode_error_raises_401(self, mock_verify):
        mock_verify.side_effect = PasscodeError("Passcode system not configured.")
        body = PasscodeBody(code="000000", user_identifier="user@test.com")

        with pytest.raises(Exception) as exc_info:
            validate_passcode(body=body)
        assert exc_info.value.status_code == 401
        assert "not configured" in exc_info.value.detail

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_passcode")
    def test_invalid_passcode_raises_401(self, mock_verify):
        mock_verify.side_effect = InvalidPasscodeError("No valid passcode found")
        body = PasscodeBody(code="999999", user_identifier="user@test.com")

        with pytest.raises(Exception) as exc_info:
            validate_passcode(body=body)
        assert exc_info.value.status_code == 401
        assert "No valid passcode" in exc_info.value.detail

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_passcode")
    def test_expired_passcode_raises_401(self, mock_verify):
        mock_verify.side_effect = ExpiredPasscodeError("Passcode has expired")
        body = PasscodeBody(code="111111", user_identifier="user@test.com")

        with pytest.raises(Exception) as exc_info:
            validate_passcode(body=body)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_passcode")
    def test_exception_chaining(self, mock_verify):
        original = InvalidPasscodeError("verification failed")
        mock_verify.side_effect = original
        body = PasscodeBody(code="000000", user_identifier="user@test.com")

        with pytest.raises(Exception) as exc_info:
            validate_passcode(body=body)
        assert exc_info.value.__cause__ is original


# ---------------------------------------------------------------------------
# create_token_router tests
# ---------------------------------------------------------------------------


class TestCreateTokenRouter:
    """Tests for the create_token_router factory."""

    def test_returns_api_router(self):
        from fastapi import APIRouter

        router = create_token_router()
        assert isinstance(router, APIRouter)

    def test_default_prefix(self):
        router = create_token_router()
        assert router.prefix == "/auth"

    def test_custom_prefix(self):
        router = create_token_router(prefix="/api/v1/auth")
        assert router.prefix == "/api/v1/auth"

    def test_custom_tags(self):
        router = create_token_router(tags=["custom-auth"])
        assert router.tags == ["custom-auth"]

    def test_has_token_verify_route(self):
        router = create_token_router()
        paths = [route.path for route in router.routes]
        assert "/auth/tokens/verify" in paths

    def test_has_passcode_verify_route(self):
        router = create_token_router()
        paths = [route.path for route in router.routes]
        assert "/auth/passcodes/verify" in paths

    def test_routes_are_post(self):
        router = create_token_router()
        for route in router.routes:
            if hasattr(route, "methods"):
                assert "POST" in route.methods


# ---------------------------------------------------------------------------
# register_auth_api tests
# ---------------------------------------------------------------------------


class TestRegisterAuthApi:
    """Tests for register_auth_api Reflex app integration."""

    def test_creates_fastapi_when_no_transformer(self):
        app = MagicMock()
        app.api_transformer = None

        router = register_auth_api(app)

        assert isinstance(app.api_transformer, FastAPI)
        assert router is not None

    def test_adds_to_existing_fastapi(self):
        app = MagicMock()
        existing_fastapi = FastAPI()
        app.api_transformer = existing_fastapi

        router = register_auth_api(app)

        # Should not have replaced the existing FastAPI instance
        assert app.api_transformer is existing_fastapi
        assert router is not None

    def test_custom_prefix(self):
        app = MagicMock()
        app.api_transformer = None

        router = register_auth_api(app, prefix="/api/v1/auth")

        assert router.prefix == "/api/v1/auth"

    def test_returns_router(self):
        from fastapi import APIRouter

        app = MagicMock()
        app.api_transformer = None

        router = register_auth_api(app)
        assert isinstance(router, APIRouter)


# ---------------------------------------------------------------------------
# TestClient integration tests (mocked verify functions)
# ---------------------------------------------------------------------------


class TestTokenRouterIntegration:
    """End-to-end HTTP tests using FastAPI TestClient with mocked verify functions."""

    def _make_app(self) -> FastAPI:
        app = FastAPI()
        router = create_token_router(prefix="/auth")
        app.include_router(router)
        return app

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_token")
    def test_token_verify_success(self, mock_verify):
        mock_verify.return_value = TokenVerification(
            user_id="user_abc", token_id="tok-1", name="My Key"
        )
        client = TestClient(self._make_app())

        response = client.post(
            "/auth/tokens/verify",
            headers={"Authorization": "Bearer myapp_abc123_secret"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user_abc"
        assert data["token_id"] == "tok-1"
        assert data["name"] == "My Key"

    def test_token_verify_no_header_returns_401(self):
        """HTTPBearer returns 401 when Authorization header is missing."""
        client = TestClient(self._make_app())

        response = client.post("/auth/tokens/verify")

        assert response.status_code == 401

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_token")
    def test_token_verify_invalid_returns_401(self, mock_verify):
        mock_verify.side_effect = InvalidTokenError("Token not found")
        client = TestClient(self._make_app())

        response = client.post(
            "/auth/tokens/verify",
            headers={"Authorization": "Bearer invalid_token"},
        )

        assert response.status_code == 401
        assert "Token not found" in response.json()["detail"]

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_passcode")
    def test_passcode_verify_success(self, mock_verify):
        mock_verify.return_value = PasscodeVerification(
            user_id="user_abc",
            passcode_id="pc-1",
            user_identifier="jane@example.com",
            channel="email",
        )
        client = TestClient(self._make_app())

        response = client.post(
            "/auth/passcodes/verify",
            json={
                "code": "847291",
                "user_identifier": "jane@example.com",
                "channel": "email",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user_abc"
        assert data["passcode_id"] == "pc-1"
        assert data["user_identifier"] == "jane@example.com"
        assert data["channel"] == "email"

    def test_passcode_verify_invalid_body_returns_422(self):
        """Missing required fields in body → 422 Unprocessable Entity."""
        client = TestClient(self._make_app())

        response = client.post(
            "/auth/passcodes/verify",
            json={"code": "123456"},  # missing user_identifier
        )

        assert response.status_code == 422

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_passcode")
    def test_passcode_verify_invalid_returns_401(self, mock_verify):
        mock_verify.side_effect = InvalidPasscodeError("No valid passcode found")
        client = TestClient(self._make_app())

        response = client.post(
            "/auth/passcodes/verify",
            json={
                "code": "000000",
                "user_identifier": "user@test.com",
                "channel": "default",
            },
        )

        assert response.status_code == 401
        assert "No valid passcode" in response.json()["detail"]

    @patch("custom_components.reflex_clerk_api.fastapi_helpers.verify_passcode")
    def test_passcode_verify_default_channel(self, mock_verify):
        """Channel defaults to 'default' when omitted."""
        mock_verify.return_value = PasscodeVerification(
            user_id="user_abc",
            passcode_id="pc-1",
            user_identifier="user@test.com",
            channel="default",
        )
        client = TestClient(self._make_app())

        response = client.post(
            "/auth/passcodes/verify",
            json={"code": "123456", "user_identifier": "user@test.com"},
        )

        assert response.status_code == 200
        mock_verify.assert_called_once_with(
            code="123456", user_identifier="user@test.com", channel="default"
        )
