"""Tests for token database model definitions.

These tests verify model schema correctness without requiring a running database.
They use SQLModel/SQLAlchemy introspection to check table definitions.
"""

import uuid
from datetime import datetime, timezone

from custom_components.reflex_clerk_api.token_models import ApiToken, Passcode


class TestApiTokenModel:
    """Tests for ApiToken model definition."""

    def test_tablename(self):
        assert ApiToken.__tablename__ == "clerk_api_tokens"

    def test_has_required_columns(self):
        columns = {c.name for c in ApiToken.__table__.columns}
        expected = {
            "id",
            "user_id",
            "name",
            "prefix",
            "short_token",
            "long_token_hash",
            "is_active",
            "expires_at",
            "last_used_at",
            "revoked_at",
            "revocation_reason",
            "created_at",
            "updated_at",
        }
        assert expected.issubset(columns)

    def test_primary_key(self):
        pk_cols = [c.name for c in ApiToken.__table__.primary_key.columns]
        assert pk_cols == ["id"]

    def test_short_token_unique(self):
        col = ApiToken.__table__.c.short_token
        assert col.unique is True

    def test_default_is_active(self):
        token = ApiToken(
            user_id="user_123",
            name="Test",
            prefix="test_",
            short_token="abc123",
            long_token_hash="hash123",
        )
        assert token.is_active is True

    def test_default_id_generated(self):
        token = ApiToken(
            user_id="user_123",
            name="Test",
            prefix="test_",
            short_token="abc123",
            long_token_hash="hash123",
        )
        assert token.id is not None
        # Should be a valid UUID string
        uuid.UUID(token.id)

    def test_nullable_fields(self):
        token = ApiToken(
            user_id="user_123",
            name="Test",
            prefix="test_",
            short_token="abc123",
            long_token_hash="hash123",
        )
        assert token.expires_at is None
        assert token.last_used_at is None
        assert token.revoked_at is None
        assert token.revocation_reason is None


class TestPasscodeModel:
    """Tests for Passcode model definition."""

    def test_tablename(self):
        assert Passcode.__tablename__ == "clerk_passcodes"

    def test_has_required_columns(self):
        columns = {c.name for c in Passcode.__table__.columns}
        expected = {
            "id",
            "user_id",
            "code_hash",
            "user_identifier",
            "channel",
            "expires_at",
            "is_used",
            "created_at",
        }
        assert expected.issubset(columns)

    def test_primary_key(self):
        pk_cols = [c.name for c in Passcode.__table__.primary_key.columns]
        assert pk_cols == ["id"]

    def test_default_channel(self):
        passcode = Passcode(
            user_id="user_123",
            code_hash="hash123",
            user_identifier="user@example.com",
            expires_at=datetime.now(timezone.utc),
        )
        assert passcode.channel == "default"

    def test_default_is_used(self):
        passcode = Passcode(
            user_id="user_123",
            code_hash="hash123",
            user_identifier="user@example.com",
            expires_at=datetime.now(timezone.utc),
        )
        assert passcode.is_used is False

    def test_default_id_generated(self):
        passcode = Passcode(
            user_id="user_123",
            code_hash="hash123",
            user_identifier="user@example.com",
            expires_at=datetime.now(timezone.utc),
        )
        assert passcode.id is not None
        uuid.UUID(passcode.id)
