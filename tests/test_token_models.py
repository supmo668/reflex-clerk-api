"""Tests for token database model definitions.

These tests verify model schema correctness without requiring a running database.
They use SQLModel/SQLAlchemy introspection to check table definitions.
"""

import uuid
from datetime import datetime, timezone

from custom_components.reflex_clerk_api.token_models import Passcode


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
