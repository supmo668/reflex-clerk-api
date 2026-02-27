"""Tests for token configuration and exception classes."""

import pytest

from custom_components.reflex_clerk_api.token_config import (
    ExpiredPasscodeError,
    ExpiredTokenError,
    InvalidPasscodeError,
    InvalidTokenError,
    PasscodeError,
    RevokedTokenError,
    TokenConfig,
    TokenError,
)


class TestTokenConfig:
    """Tests for TokenConfig dataclass."""

    def test_default_values(self):
        config = TokenConfig()
        assert config.prefix == "token_"
        assert config.token_code_length == 32
        assert config.short_token_length == 6
        assert config.passcode_length == 6
        assert config.passcode_ttl_seconds == 600

    def test_custom_values(self):
        config = TokenConfig(
            prefix="myapp_",
            token_code_length=48,
            short_token_length=8,
            passcode_length=8,
            passcode_ttl_seconds=300,
        )
        assert config.prefix == "myapp_"
        assert config.token_code_length == 48
        assert config.short_token_length == 8
        assert config.passcode_length == 8
        assert config.passcode_ttl_seconds == 300

    def test_frozen(self):
        config = TokenConfig()
        with pytest.raises(AttributeError):
            config.prefix = "changed_"  # type: ignore[misc]

    def test_empty_prefix_rejected(self):
        with pytest.raises(ValueError, match="prefix must not be empty"):
            TokenConfig(prefix="")

    def test_short_token_code_length_rejected(self):
        with pytest.raises(ValueError, match="token_code_length must be at least 16"):
            TokenConfig(token_code_length=8)

    def test_short_short_token_rejected(self):
        with pytest.raises(ValueError, match="short_token_length must be at least 4"):
            TokenConfig(short_token_length=2)

    def test_passcode_length_bounds(self):
        with pytest.raises(ValueError, match="passcode_length must be between 4 and 10"):
            TokenConfig(passcode_length=3)
        with pytest.raises(ValueError, match="passcode_length must be between 4 and 10"):
            TokenConfig(passcode_length=11)

    def test_passcode_ttl_minimum(self):
        with pytest.raises(ValueError, match="passcode_ttl_seconds must be at least 30"):
            TokenConfig(passcode_ttl_seconds=10)


class TestExceptionHierarchy:
    """Tests for exception class hierarchy."""

    def test_token_errors_inherit_token_error(self):
        assert issubclass(InvalidTokenError, TokenError)
        assert issubclass(ExpiredTokenError, TokenError)
        assert issubclass(RevokedTokenError, TokenError)

    def test_passcode_errors_inherit_passcode_error(self):
        assert issubclass(InvalidPasscodeError, PasscodeError)
        assert issubclass(ExpiredPasscodeError, PasscodeError)

    def test_token_error_is_exception(self):
        assert issubclass(TokenError, Exception)

    def test_passcode_error_is_exception(self):
        assert issubclass(PasscodeError, Exception)

    def test_errors_are_raisable_with_message(self):
        with pytest.raises(InvalidTokenError, match="bad token"):
            raise InvalidTokenError("bad token")
        with pytest.raises(ExpiredPasscodeError, match="expired"):
            raise ExpiredPasscodeError("expired")
