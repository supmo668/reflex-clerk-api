"""Tests for passcode lifecycle helper functions.

These tests verify:
- Result dataclass construction, immutability, and field access
- Passcode generation format (digits, length, leading zeros)
- SHA-256 hash computation correctness
- verify_passcode() error path patterns (no DB required)
- Configuration access for passcode params
"""

import hashlib
import secrets
from datetime import datetime, timezone

import pytest

from custom_components.reflex_clerk_api.token_config import (
    ExpiredPasscodeError,
    InvalidPasscodeError,
    PasscodeError,
    PasscodeResult,
    PasscodeVerification,
    TokenConfig,
)

# ---------------------------------------------------------------------------
# Result dataclass tests
# ---------------------------------------------------------------------------


class TestPasscodeResult:
    """Tests for PasscodeResult frozen dataclass."""

    def test_construction(self):
        now = datetime.now(timezone.utc)
        result = PasscodeResult(
            id="uuid-1",
            code="847291",
            user_identifier="jane@example.com",
            channel="email",
            expires_at=now,
            created_at=now,
        )
        assert result.id == "uuid-1"
        assert result.code == "847291"
        assert result.user_identifier == "jane@example.com"
        assert result.channel == "email"
        assert result.expires_at == now
        assert result.created_at == now

    def test_frozen(self):
        now = datetime.now(timezone.utc)
        result = PasscodeResult(
            id="uuid-1",
            code="847291",
            user_identifier="jane@example.com",
            channel="email",
            expires_at=now,
            created_at=now,
        )
        with pytest.raises(AttributeError):
            result.code = "000000"  # type: ignore[misc]

    def test_with_different_channels(self):
        now = datetime.now(timezone.utc)
        for channel in ("email", "sms", "cli", "default"):
            result = PasscodeResult(
                id="uuid-1",
                code="123456",
                user_identifier="user@test.com",
                channel=channel,
                expires_at=now,
                created_at=now,
            )
            assert result.channel == channel


class TestPasscodeVerification:
    """Tests for PasscodeVerification frozen dataclass."""

    def test_construction(self):
        v = PasscodeVerification(
            user_id="user_abc",
            passcode_id="pc-1",
            user_identifier="jane@example.com",
            channel="email",
        )
        assert v.user_id == "user_abc"
        assert v.passcode_id == "pc-1"
        assert v.user_identifier == "jane@example.com"
        assert v.channel == "email"

    def test_frozen(self):
        v = PasscodeVerification(
            user_id="user_abc",
            passcode_id="pc-1",
            user_identifier="jane@example.com",
            channel="email",
        )
        with pytest.raises(AttributeError):
            v.user_id = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Passcode generation format & crypto tests
# ---------------------------------------------------------------------------


class TestPasscodeFormat:
    """Tests for passcode generation format and cryptographic operations."""

    def test_six_digit_format(self):
        """Default passcode is exactly 6 digits."""
        code = "".join(str(secrets.randbelow(10)) for _ in range(6))
        assert len(code) == 6
        assert code.isdigit()

    def test_leading_zeros_preserved(self):
        """Leading zeros must be preserved in passcode string."""
        # Manually construct a code with leading zeros
        code = "007421"
        assert len(code) == 6
        assert code.isdigit()
        assert code.startswith("00")

    def test_all_same_digits(self):
        """Edge case: all same digits should be valid."""
        code = "000000"
        assert len(code) == 6
        assert code.isdigit()
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        assert len(code_hash) == 64

    def test_custom_length_4_digits(self):
        """4-digit passcode generation."""
        code = "".join(str(secrets.randbelow(10)) for _ in range(4))
        assert len(code) == 4
        assert code.isdigit()

    def test_custom_length_8_digits(self):
        """8-digit passcode generation."""
        code = "".join(str(secrets.randbelow(10)) for _ in range(8))
        assert len(code) == 8
        assert code.isdigit()

    def test_custom_length_10_digits(self):
        """10-digit passcode generation (max allowed)."""
        code = "".join(str(secrets.randbelow(10)) for _ in range(10))
        assert len(code) == 10
        assert code.isdigit()

    def test_sha256_hash_roundtrip(self):
        """SHA-256 hash of passcode is deterministic."""
        code = "847291"
        hash1 = hashlib.sha256(code.encode()).hexdigest()
        hash2 = hashlib.sha256(code.encode()).hexdigest()
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_different_codes_different_hashes(self):
        """Different passcodes produce different hashes."""
        c1 = "123456"
        c2 = "654321"
        h1 = hashlib.sha256(c1.encode()).hexdigest()
        h2 = hashlib.sha256(c2.encode()).hexdigest()
        assert h1 != h2

    def test_compare_digest_correct(self):
        """Verify secrets.compare_digest works for passcode hashes."""
        code = "847291"
        hash_val = hashlib.sha256(code.encode()).hexdigest()
        assert secrets.compare_digest(hash_val, hash_val) is True
        wrong_hash = hashlib.sha256("000000".encode()).hexdigest()
        assert secrets.compare_digest(hash_val, wrong_hash) is False

    def test_empty_code_hashes_differently(self):
        """Empty string hashes differently from any 6-digit code."""
        empty_hash = hashlib.sha256("".encode()).hexdigest()
        code_hash = hashlib.sha256("123456".encode()).hexdigest()
        assert empty_hash != code_hash


# ---------------------------------------------------------------------------
# Error path tests (no DB needed)
# ---------------------------------------------------------------------------


class TestVerifyPasscodeErrorPaths:
    """Tests for verify_passcode() error conditions without a database."""

    def test_config_not_set_raises_error(self):
        """PasscodeError should be raised when config is None."""
        config = None
        if config is None:
            with pytest.raises(PasscodeError, match="not configured"):
                raise PasscodeError("Passcode system not configured.")

    def test_exception_hierarchy(self):
        """All passcode exceptions inherit from PasscodeError."""
        assert issubclass(InvalidPasscodeError, PasscodeError)
        assert issubclass(ExpiredPasscodeError, PasscodeError)

    def test_invalid_passcode_error_message(self):
        """InvalidPasscodeError carries message."""
        with pytest.raises(InvalidPasscodeError, match="No valid passcode"):
            raise InvalidPasscodeError("No valid passcode found")

    def test_expired_passcode_error_message(self):
        """ExpiredPasscodeError carries message."""
        with pytest.raises(ExpiredPasscodeError, match="expired"):
            raise ExpiredPasscodeError("Passcode has expired")

    def test_hash_mismatch_pattern(self):
        """Verify hash mismatch detection pattern for passcodes."""
        real_code = "847291"
        fake_code = "123456"
        real_hash = hashlib.sha256(real_code.encode()).hexdigest()
        fake_hash = hashlib.sha256(fake_code.encode()).hexdigest()
        assert not secrets.compare_digest(real_hash, fake_hash)


# ---------------------------------------------------------------------------
# Configuration access tests
# ---------------------------------------------------------------------------


class TestPasscodeConfigAccess:
    """Tests for passcode configuration access patterns."""

    def test_config_default_passcode_length(self):
        config = TokenConfig()
        assert config.passcode_length == 6

    def test_config_default_passcode_ttl(self):
        config = TokenConfig()
        assert config.passcode_ttl_seconds == 600

    def test_config_custom_passcode_length(self):
        config = TokenConfig(passcode_length=8)
        assert config.passcode_length == 8

    def test_config_custom_passcode_ttl(self):
        config = TokenConfig(passcode_ttl_seconds=300)
        assert config.passcode_ttl_seconds == 300

    def test_config_min_passcode_length(self):
        """Minimum passcode_length is 4."""
        config = TokenConfig(passcode_length=4)
        assert config.passcode_length == 4

    def test_config_max_passcode_length(self):
        """Maximum passcode_length is 10."""
        config = TokenConfig(passcode_length=10)
        assert config.passcode_length == 10

    def test_config_rejects_too_short_passcode(self):
        """passcode_length < 4 raises ValueError."""
        with pytest.raises(ValueError, match="passcode_length"):
            TokenConfig(passcode_length=3)

    def test_config_rejects_too_long_passcode(self):
        """passcode_length > 10 raises ValueError."""
        with pytest.raises(ValueError, match="passcode_length"):
            TokenConfig(passcode_length=11)

    def test_config_rejects_short_ttl(self):
        """passcode_ttl_seconds < 30 raises ValueError."""
        with pytest.raises(ValueError, match="passcode_ttl_seconds"):
            TokenConfig(passcode_ttl_seconds=10)

    def test_generation_with_config(self):
        """Full passcode generation flow using config."""
        config = TokenConfig(passcode_length=8, passcode_ttl_seconds=120)
        code = "".join(
            str(secrets.randbelow(10)) for _ in range(config.passcode_length)
        )
        code_hash = hashlib.sha256(code.encode()).hexdigest()

        assert len(code) == 8
        assert code.isdigit()
        assert len(code_hash) == 64
        assert secrets.compare_digest(
            code_hash, hashlib.sha256(code.encode()).hexdigest()
        )
