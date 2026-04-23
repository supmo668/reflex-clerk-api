"""Configuration, result types, and exceptions for the token issuance system."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


class TokenError(Exception):
    """Base exception for token-related errors."""

    pass


class InvalidTokenError(TokenError):
    """Token string is malformed or does not match any record."""

    pass


class ExpiredTokenError(TokenError):
    """Token exists but has passed its expiration date."""

    pass


class RevokedTokenError(TokenError):
    """Token exists but has been revoked."""

    pass


class PasscodeError(Exception):
    """Base exception for passcode-related errors."""

    pass


class InvalidPasscodeError(PasscodeError):
    """Passcode does not match or no matching record found."""

    pass


class ExpiredPasscodeError(PasscodeError):
    """Passcode has expired."""

    pass


@dataclass(frozen=True)
class TokenConfig:
    """Configuration for the token issuance system.

    Args:
        prefix: String prefix for generated API tokens (e.g., "myapp_").
            The full token format is: {prefix}{short_token}_{long_token}
        token_code_length: Number of bytes for the long token portion (default 32 = 256 bits).
            The long token is base64url-encoded, so the string length is ~4/3 of this value.
        short_token_length: Number of bytes for the short token identifier (default 6).
            Used for O(1) DB lookup. Hex-encoded to 2x characters (e.g., 6 bytes = 12 hex chars).
        passcode_length: Number of digits in generated passcodes (default 6).
        passcode_ttl_seconds: Time-to-live for passcodes in seconds (default 600 = 10 minutes).
    """

    prefix: str = "token_"
    token_code_length: int = 32
    short_token_length: int = 6
    passcode_length: int = 6
    passcode_ttl_seconds: int = 600

    def __post_init__(self) -> None:
        if not self.prefix:
            raise ValueError("token prefix must not be empty")
        if self.token_code_length < 16:
            raise ValueError("token_code_length must be at least 16 bytes (128 bits)")
        if self.short_token_length < 4:
            raise ValueError("short_token_length must be at least 4 bytes")
        if not 4 <= self.passcode_length <= 10:
            raise ValueError("passcode_length must be between 4 and 10 digits")
        if self.passcode_ttl_seconds < 30:
            raise ValueError("passcode_ttl_seconds must be at least 30 seconds")


@dataclass(frozen=True)
class ApiTokenResult:
    """Returned when a new API token is issued.

    ``token_string`` contains the full token and is only available at creation time.
    It must not be stored by the application — show it once to the user.
    """

    id: str
    name: str
    prefix: str
    short_token: str
    token_string: str
    is_active: bool
    expires_at: datetime | None
    created_at: datetime
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class TokenVerification:
    """Returned when an API token is successfully verified.

    ``scopes`` lists the permissions granted to this token. Consuming services
    check these to authorize actions (e.g., ``"health:read"``, ``"kg:write"``).
    """

    user_id: str
    token_id: str
    name: str
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class TokenSummary:
    """Returned by ``list_tokens()``. No secrets are exposed."""

    id: str
    name: str
    display_token: str
    is_active: bool
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PasscodeResult:
    """Returned when a new passcode is issued.

    ``code`` contains the plaintext passcode and is only available at creation time.
    The application must send it to the user via the appropriate channel.
    """

    id: str
    code: str
    user_identifier: str
    channel: str
    expires_at: datetime
    created_at: datetime


@dataclass(frozen=True)
class PasscodeVerification:
    """Returned when a passcode is successfully verified."""

    user_id: str
    passcode_id: str
    user_identifier: str
    channel: str
