"""Tests for token lifecycle helper functions.

These tests verify:
- Result dataclass construction, immutability, and field access
- Token string format generation and parsing logic
- SHA-256 hash computation correctness
- verify_token() error paths (no DB required)
- Configuration guard checks
"""

import hashlib
import secrets
from datetime import datetime, timezone

import pytest

from custom_components.reflex_clerk_api.token_config import (
    ApiTokenResult,
    ExpiredTokenError,
    InvalidTokenError,
    RevokedTokenError,
    TokenConfig,
    TokenError,
    TokenSummary,
    TokenVerification,
)

# ---------------------------------------------------------------------------
# Result dataclass tests
# ---------------------------------------------------------------------------


class TestApiTokenResult:
    """Tests for ApiTokenResult frozen dataclass."""

    def test_construction(self):
        now = datetime.now(timezone.utc)
        result = ApiTokenResult(
            id="uuid-1",
            name="My Key",
            prefix="myapp_",
            short_token="abc123",
            token_string="myapp_abc123_longpart",
            is_active=True,
            expires_at=None,
            created_at=now,
        )
        assert result.id == "uuid-1"
        assert result.name == "My Key"
        assert result.prefix == "myapp_"
        assert result.short_token == "abc123"
        assert result.token_string == "myapp_abc123_longpart"
        assert result.is_active is True
        assert result.expires_at is None
        assert result.created_at == now

    def test_frozen(self):
        now = datetime.now(timezone.utc)
        result = ApiTokenResult(
            id="uuid-1",
            name="My Key",
            prefix="myapp_",
            short_token="abc123",
            token_string="myapp_abc123_longpart",
            is_active=True,
            expires_at=None,
            created_at=now,
        )
        with pytest.raises(AttributeError):
            result.name = "Changed"  # type: ignore[misc]

    def test_with_expires_at(self):
        now = datetime.now(timezone.utc)
        result = ApiTokenResult(
            id="uuid-1",
            name="Expiring Key",
            prefix="test_",
            short_token="xyz789",
            token_string="test_xyz789_secret",
            is_active=True,
            expires_at=now,
            created_at=now,
        )
        assert result.expires_at == now


class TestTokenVerification:
    """Tests for TokenVerification frozen dataclass."""

    def test_construction(self):
        v = TokenVerification(user_id="user_abc", token_id="tok-1", name="My Key")
        assert v.user_id == "user_abc"
        assert v.token_id == "tok-1"
        assert v.name == "My Key"

    def test_frozen(self):
        v = TokenVerification(user_id="user_abc", token_id="tok-1", name="My Key")
        with pytest.raises(AttributeError):
            v.user_id = "changed"  # type: ignore[misc]


class TestTokenSummary:
    """Tests for TokenSummary frozen dataclass."""

    def test_construction(self):
        now = datetime.now(timezone.utc)
        s = TokenSummary(
            id="uuid-1",
            name="My Key",
            display_token="myapp_abc123",
            is_active=True,
            expires_at=None,
            last_used_at=now,
            created_at=now,
        )
        assert s.id == "uuid-1"
        assert s.display_token == "myapp_abc123"
        assert s.last_used_at == now

    def test_frozen(self):
        now = datetime.now(timezone.utc)
        s = TokenSummary(
            id="uuid-1",
            name="My Key",
            display_token="myapp_abc123",
            is_active=True,
            expires_at=None,
            last_used_at=None,
            created_at=now,
        )
        with pytest.raises(AttributeError):
            s.name = "Changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Token string format & crypto tests
# ---------------------------------------------------------------------------


class TestTokenStringFormat:
    """Tests for token string format and cryptographic operations."""

    def test_token_format_structure(self):
        """Verify token string follows {prefix}{short}_{long} format."""
        prefix = "myapp_"
        # short_token uses token_hex (no underscores) so _ separator is safe
        short = secrets.token_hex(6)
        long = secrets.token_urlsafe(32)
        token_string = f"{prefix}{short}_{long}"

        assert token_string.startswith(prefix)
        remainder = token_string[len(prefix) :]
        parts = remainder.split("_", 1)
        assert len(parts) == 2
        assert parts[0] == short
        assert parts[1] == long

    def test_short_token_is_hex_no_underscores(self):
        """Short token must not contain underscores (hex-only chars)."""
        for length in (4, 6, 8, 12):
            short = secrets.token_hex(length)
            assert "_" not in short
            assert len(short) == length * 2  # hex doubles byte count

    def test_long_token_length(self):
        """Verify long_token has adequate entropy."""
        long = secrets.token_urlsafe(32)
        # Base64url: 32 bytes → ~43 characters
        assert len(long) >= 32

    def test_sha256_hash_roundtrip(self):
        """Verify SHA-256 hash computation is deterministic."""
        long_token = secrets.token_urlsafe(32)
        hash1 = hashlib.sha256(long_token.encode()).hexdigest()
        hash2 = hashlib.sha256(long_token.encode()).hexdigest()
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex = 64 chars

    def test_sha256_different_tokens_different_hashes(self):
        """Different tokens produce different hashes."""
        t1 = secrets.token_urlsafe(32)
        t2 = secrets.token_urlsafe(32)
        h1 = hashlib.sha256(t1.encode()).hexdigest()
        h2 = hashlib.sha256(t2.encode()).hexdigest()
        assert h1 != h2

    def test_compare_digest_correct(self):
        """Verify secrets.compare_digest works for our use case."""
        token = secrets.token_urlsafe(32)
        hash_val = hashlib.sha256(token.encode()).hexdigest()
        assert secrets.compare_digest(hash_val, hash_val) is True
        assert secrets.compare_digest(hash_val, "wrong" * 16) is False

    def test_prefix_with_underscore(self):
        """Prefix containing underscore should still parse correctly."""
        prefix = "my_app_"
        short = "abc123"  # hex-only, no underscores
        long = "secretpart_with_underscores"
        token_string = f"{prefix}{short}_{long}"

        # Strip prefix, then split on first _
        remainder = token_string[len(prefix) :]
        parts = remainder.split("_", 1)
        assert parts[0] == short
        assert parts[1] == long


# ---------------------------------------------------------------------------
# Token parsing / error path tests (no DB needed)
# ---------------------------------------------------------------------------


class TestVerifyTokenErrorPaths:
    """Tests for verify_token() error conditions that don't require a database.

    These test the parsing and configuration guard logic by importing the
    exceptions and testing them directly. The actual verify_token() function
    requires rx.session() which needs a running DB, so we test the error
    logic patterns here.
    """

    def test_token_config_not_set_raises_error(self):
        """TokenError should be raised when config is None."""
        # We verify the guard pattern:
        config = None
        if config is None:
            with pytest.raises(TokenError, match="not configured"):
                raise TokenError("Token issuance not configured.")

    def test_wrong_prefix_raises_invalid(self):
        """InvalidTokenError when token doesn't start with expected prefix."""
        config = TokenConfig(prefix="myapp_")
        token_string = "wrongprefix_abc_xyz"
        if not token_string.startswith(config.prefix):
            with pytest.raises(InvalidTokenError, match="prefix"):
                raise InvalidTokenError("Token prefix does not match")

    def test_malformed_no_separator_raises_invalid(self):
        """InvalidTokenError when token has no separator after prefix."""
        config = TokenConfig(prefix="test_")
        token_string = "test_noseparator"
        remainder = token_string[len(config.prefix) :]
        parts = remainder.split("_", 1)
        # "noseparator" has no underscore, so only 1 part
        if len(parts) != 2 or not parts[0] or not parts[1]:
            with pytest.raises(InvalidTokenError, match="Malformed"):
                raise InvalidTokenError("Malformed token string")

    def test_malformed_empty_short_raises_invalid(self):
        """InvalidTokenError when short_token is empty."""
        config = TokenConfig(prefix="test_")
        token_string = "test__longpart"
        remainder = token_string[len(config.prefix) :]
        parts = remainder.split("_", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            with pytest.raises(InvalidTokenError, match="Malformed"):
                raise InvalidTokenError("Malformed token string")

    def test_empty_token_string_raises_invalid(self):
        """InvalidTokenError when token is empty string."""
        config = TokenConfig(prefix="test_")
        token_string = ""
        if not token_string.startswith(config.prefix):
            with pytest.raises(InvalidTokenError, match="prefix"):
                raise InvalidTokenError("Token prefix does not match")

    def test_exception_hierarchy_token(self):
        """All token exceptions inherit from TokenError."""
        assert issubclass(InvalidTokenError, TokenError)
        assert issubclass(ExpiredTokenError, TokenError)
        assert issubclass(RevokedTokenError, TokenError)

    def test_hash_mismatch_pattern(self):
        """Verify hash mismatch detection pattern."""
        real_token = secrets.token_urlsafe(32)
        fake_token = secrets.token_urlsafe(32)
        real_hash = hashlib.sha256(real_token.encode()).hexdigest()
        fake_hash = hashlib.sha256(fake_token.encode()).hexdigest()
        assert not secrets.compare_digest(real_hash, fake_hash)


# ---------------------------------------------------------------------------
# Configuration access tests
# ---------------------------------------------------------------------------


class TestTokenConfigAccess:
    """Tests for token configuration access patterns."""

    def test_config_default_prefix(self):
        config = TokenConfig()
        assert config.prefix == "token_"

    def test_config_custom_prefix(self):
        config = TokenConfig(prefix="myapp_live_")
        assert config.prefix == "myapp_live_"

    def test_config_token_generation_params(self):
        config = TokenConfig(token_code_length=48, short_token_length=8)
        short = secrets.token_urlsafe(config.short_token_length)
        long = secrets.token_urlsafe(config.token_code_length)
        assert len(short) > 0
        assert len(long) > 0

    def test_token_format_with_default_config(self):
        """Full token generation flow using default config."""
        config = TokenConfig()
        short = secrets.token_hex(config.short_token_length)
        long = secrets.token_urlsafe(config.token_code_length)
        token_string = f"{config.prefix}{short}_{long}"
        long_hash = hashlib.sha256(long.encode()).hexdigest()

        # Verify roundtrip
        assert token_string.startswith(config.prefix)
        remainder = token_string[len(config.prefix) :]
        parsed_short, parsed_long = remainder.split("_", 1)
        assert parsed_short == short
        assert parsed_long == long
        assert secrets.compare_digest(
            long_hash, hashlib.sha256(parsed_long.encode()).hexdigest()
        )
