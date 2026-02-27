# Feature: Database Models & Configuration (Phase 1)

## Summary

Establish the data layer and configuration surface for the token issuance system. This phase creates two database models (`ApiToken`, `Passcode`) using Reflex's native `rx.Model`/SQLModel, a `TokenConfig` dataclass for application-level configuration, custom exceptions, and integration into `ClerkState` via ClassVar + `wrap_app()`. No token lifecycle logic — just the foundation.

## User Story

As a developer using reflex-clerk-api,
I want database models and configuration for API tokens and passcodes available in the package,
So that I can configure token settings via `wrap_app()` and have the schema ready for lifecycle operations.

## Problem Statement

The reflex-clerk-api package has no database models or configuration for token/passcode management. Phase 2-4 helpers need these models and config to exist before they can be implemented.

## Solution Statement

Add `ApiToken` and `Passcode` as SQLModel tables (namespaced with `clerk_` prefix), a `TokenConfig` dataclass for configurable parameters, custom exception classes, and wire configuration through the existing `ClerkState` ClassVar + `wrap_app()` pattern. Follow the `reflex-local-auth` precedent for library-defined models.

## Metadata

| Field            | Value                                             |
| ---------------- | ------------------------------------------------- |
| Type             | NEW_CAPABILITY                                    |
| Complexity       | MEDIUM                                            |
| Systems Affected | models.py, clerk_provider.py, __init__.py, new token_models.py |
| Dependencies     | reflex>=0.8.0, sqlmodel (transitive via reflex), stdlib (secrets, hashlib, uuid, datetime) |
| Estimated Tasks  | 7                                                 |

---

## UX Design

### Before State

```
╔══════════════════════════════════════════════════════════════════╗
║                         BEFORE STATE                           ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                ║
║   Developer Code:                                              ║
║   ┌────────────────────────────────────────┐                   ║
║   │  clerk.wrap_app(                       │                   ║
║   │      app,                              │                   ║
║   │      publishable_key="pk_...",         │                   ║
║   │      secret_key="sk_...",              │                   ║
║   │  )                                     │                   ║
║   └────────────────────────────────────────┘                   ║
║                          │                                     ║
║                          ▼                                     ║
║   ClerkState provides: is_signed_in, user_id, claims           ║
║   ClerkUser provides: name, email, phone, image                ║
║                                                                ║
║   NO token config. NO database models. NO exceptions.          ║
║   Developer must build token system from scratch.              ║
║                                                                ║
╚══════════════════════════════════════════════════════════════════╝
```

### After State

```
╔══════════════════════════════════════════════════════════════════╗
║                          AFTER STATE                           ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                ║
║   Developer Code:                                              ║
║   ┌────────────────────────────────────────┐                   ║
║   │  clerk.wrap_app(                       │                   ║
║   │      app,                              │                   ║
║   │      publishable_key="pk_...",         │                   ║
║   │      secret_key="sk_...",              │                   ║
║   │      token_prefix="myapp_",      ◄─── NEW                 ║
║   │      token_code_length=32,       ◄─── NEW                 ║
║   │      passcode_length=6,          ◄─── NEW                 ║
║   │      passcode_ttl_seconds=600,   ◄─── NEW                 ║
║   │  )                                     │                   ║
║   └────────────────────────────────────────┘                   ║
║                          │                                     ║
║                          ▼                                     ║
║   ClerkState._token_config: TokenConfig  ◄── NEW ClassVar     ║
║                          │                                     ║
║                          ▼                                     ║
║   Database tables (after consumer runs migrations):            ║
║   ┌─────────────────────┐  ┌──────────────────┐               ║
║   │ clerk_api_tokens    │  │ clerk_passcodes   │               ║
║   │ - id (UUID PK)      │  │ - id (UUID PK)   │               ║
║   │ - user_id (indexed) │  │ - user_id        │               ║
║   │ - name              │  │ - code_hash      │               ║
║   │ - prefix            │  │ - user_identifier│               ║
║   │ - short_token (uniq)│  │ - channel        │               ║
║   │ - long_token_hash   │  │ - expires_at     │               ║
║   │ - is_active         │  │ - is_used        │               ║
║   │ - expires_at        │  │ - created_at     │               ║
║   │ - last_used_at      │  └──────────────────┘               ║
║   │ - revoked_at        │                                     ║
║   │ - revocation_reason │                                     ║
║   │ - created_at        │                                     ║
║   │ - updated_at        │                                     ║
║   └─────────────────────┘                                     ║
║                                                                ║
║   Exceptions available:                                        ║
║   InvalidTokenError, ExpiredTokenError, RevokedTokenError      ║
║   InvalidPasscodeError, ExpiredPasscodeError                   ║
║                                                                ║
╚══════════════════════════════════════════════════════════════════╝
```

### Interaction Changes

| Location | Before | After | User Impact |
|----------|--------|-------|-------------|
| `wrap_app()` | 4 params (publishable_key, secret_key, register_user_state, appearance) | 4 existing + 4 new token params | Can configure token system at app init |
| `ClerkState` | No token config | `_token_config: ClassVar[TokenConfig]` + `set_token_config()` | Framework stores token configuration |
| Database | No clerk tables | `clerk_api_tokens` + `clerk_passcodes` tables | Schema ready for token lifecycle |
| Exceptions | 3 errors (MissingSecretKey, MissingUser, NotRegistered) | 3 existing + 5 new token errors | Structured error handling for token ops |
| `__init__.py` | No token exports | Exports models, config, exceptions | Clean public API for consumers |

---

## Mandatory Reading

**CRITICAL: Implementation agent MUST read these files before starting any task:**

| Priority | File | Lines | Why Read This |
|----------|------|-------|---------------|
| P0 | `custom_components/reflex_clerk_api/clerk_provider.py` | 21-30 | Exception base class `ReflexClerkApiError` — MIRROR exactly |
| P0 | `custom_components/reflex_clerk_api/clerk_provider.py` | 46-61 | ClassVar pattern on ClerkState — MIRROR exactly |
| P0 | `custom_components/reflex_clerk_api/clerk_provider.py` | 170-191 | `_set_secret_key()` and `_set_client()` classmethods — MIRROR pattern |
| P0 | `custom_components/reflex_clerk_api/clerk_provider.py` | 704-766 | `clerk_provider()` and `wrap_app()` — UPDATE these |
| P1 | `custom_components/reflex_clerk_api/models.py` | 1-99 | Existing config model pattern (PropsBase) — understand style |
| P1 | `custom_components/reflex_clerk_api/__init__.py` | 1-54 | Export pattern — UPDATE this |
| P2 | `tests/test_demo.py` | 45-58 | Test fixture pattern for backend tests |

**External Documentation:**

| Source | Section | Why Needed |
|--------|---------|------------|
| [Reflex Database Overview](https://reflex.dev/docs/database/overview/) | Model definition | Confirm rx.Model patterns |
| [SQLModel Field docs](https://sqlmodel.tiangolo.com/tutorial/create-db-and-table/) | Field types | UUID, datetime, index patterns |
| [reflex-local-auth models](https://github.com/masenf/reflex-local-auth) | user.py, auth_session.py | Canonical example of library-defined rx.Model |
| [Reflex model.py source](https://github.com/reflex-dev/reflex/blob/main/reflex/model.py) | ModelRegistry.register | Future-proof model registration (0.8.15+ deprecation) |

---

## Patterns to Mirror

**EXCEPTION_PATTERN:**
```python
# SOURCE: custom_components/reflex_clerk_api/clerk_provider.py:21-30
# COPY THIS PATTERN:
class ReflexClerkApiError(Exception):
    """Base exception for reflex-clerk-api errors."""

    pass


class MissingSecretKeyError(ReflexClerkApiError):
    pass


class MissingUserError(ReflexClerkApiError):
    pass
```

**CLASSVAR_PATTERN:**
```python
# SOURCE: custom_components/reflex_clerk_api/clerk_provider.py:46-61
# COPY THIS PATTERN:
class ClerkState(rx.State):
    # NOTE: ClassVar tells reflex it doesn't need to include these in the persisted state per instance.
    _secret_key: ClassVar[str | None] = None
    """The Clerk secret_key set during clerk_provider creation."""
    _claims_options: ClassVar[dict[str, Any]] = {
        "exp": {"essential": True},
        "nbf": {"essential": True},
    }
```

**CLASSMETHOD_CONFIG_PATTERN:**
```python
# SOURCE: custom_components/reflex_clerk_api/clerk_provider.py:170-173
# COPY THIS PATTERN:
@classmethod
def _set_secret_key(cls, secret_key: str) -> None:
    if not secret_key:
        raise MissingSecretKeyError("secret_key must be set (and not empty)")
    cls._secret_key = secret_key
```

**PUBLIC_CLASSMETHOD_PATTERN:**
```python
# SOURCE: custom_components/reflex_clerk_api/clerk_provider.py:84-86
# COPY THIS PATTERN:
@classmethod
def set_claims_options(cls, claims_options: dict[str, Any]) -> None:
    """Set the claims options for the JWT claims validation."""
    cls._claims_options = claims_options
```

**WRAP_APP_PATTERN:**
```python
# SOURCE: custom_components/reflex_clerk_api/clerk_provider.py:738-766
# COPY THIS PATTERN:
def wrap_app(
    app: rx.App,
    publishable_key: str,
    secret_key: str | None = None,
    register_user_state: bool = False,
    appearance: Appearance | None = None,
    **props,
) -> rx.App:
    app.app_wraps[(1, "ClerkProvider")] = lambda _: clerk_provider(
        publishable_key=publishable_key,
        secret_key=secret_key,
        register_user_state=register_user_state,
        appearance=appearance,
        **props,
    )
    return app
```

**RX_MODEL_PATTERN (from reflex-local-auth):**
```python
# SOURCE: reflex-local-auth/custom_components/reflex_local_auth/auth_session.py
# COPY THIS PATTERN:
import datetime
import reflex as rx
from sqlmodel import Field, Column
from sqlalchemy import DateTime, func, String

class LocalAuthSession(rx.Model, table=True):
    user_id: int = Field(index=True, nullable=False)
    session_id: str = Field(unique=True, index=True, nullable=False, sa_type=String(255))
    expiration: datetime.datetime = Field(
        sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False),
    )
```

**RX_SESSION_PATTERN (from Syntropy-Journals):**
```python
# SOURCE: app/models/admin/user.py:85-95
# COPY THIS PATTERN:
with rx.session() as session:
    key_row = UserApiKey(
        user_id=self.id,
        key=api_key_val,
        name=name or "Default API Key",
        created_at=created_at,
        expires_at=expires_at,
        is_active=True,
    )
    session.add(key_row)
    session.commit()
```

**IMPORT_STYLE:**
```python
# SOURCE: custom_components/reflex_clerk_api/clerk_provider.py:1-18
# COPY THIS STYLE:
import logging
import os
import uuid
from typing import Any, ClassVar

import reflex as rx
```

---

## Files to Change

| File | Action | Justification |
|------|--------|---------------|
| `custom_components/reflex_clerk_api/token_models.py` | CREATE | Database models (ApiToken, Passcode) — separate file because these are rx.Model (DB tables), distinct from config models in models.py |
| `custom_components/reflex_clerk_api/token_config.py` | CREATE | TokenConfig dataclass + token/passcode exception classes — keeps token concerns cohesive and avoids bloating clerk_provider.py |
| `custom_components/reflex_clerk_api/clerk_provider.py` | UPDATE | Add `_token_config` ClassVar, `set_token_config()` classmethod, update `clerk_provider()` and `wrap_app()` signatures |
| `custom_components/reflex_clerk_api/__init__.py` | UPDATE | Export new models, config, exceptions |

---

## NOT Building (Scope Limits)

- **Token lifecycle helpers** (issue, verify, revoke) — Phase 2
- **Passcode lifecycle helpers** (issue, verify) — Phase 3
- **FastAPI middleware/dependencies** — Phase 4
- **ClerkUser metadata fields** — Phase 5
- **Link tracking models** — Phase 6
- **Tests for token lifecycle** — Phase 7 (but we validate models compile and config flows)
- **Documentation** — Phase 8

---

## Step-by-Step Tasks

Execute in order. Each task is atomic and independently verifiable.

### Task 1: CREATE `custom_components/reflex_clerk_api/token_config.py`

- **ACTION**: Create the configuration dataclass and exception classes for the token system
- **IMPLEMENT**:

```python
"""Configuration and exceptions for the token issuance system."""

from __future__ import annotations

from dataclasses import dataclass, field


# Re-export base exception for subclassing
# Import at module level to avoid circular imports — clerk_provider.py defines the base
# We import it lazily or define token exceptions as standalone


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
            Used for O(1) DB lookup. Base64url-encoded to ~8 characters.
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
```

- **MIRROR**: Exception style from `clerk_provider.py:21-30` (simple class with docstring, inherits base)
- **DESIGN DECISIONS**:
  - `TokenError` and `PasscodeError` as separate base classes (not subclassing `ReflexClerkApiError`) to avoid coupling token module to clerk_provider. Consumers can catch `TokenError` or `PasscodeError` independently.
  - `@dataclass(frozen=True)` — config is immutable once set, matches the ClassVar pattern (set once at startup)
  - Validation in `__post_init__` — fail fast on bad config
  - `token_code_length` is in bytes (32 bytes = 256 bits of entropy), matching `secrets.token_urlsafe(32)`
- **IMPORTS**: Only stdlib (`dataclasses`)
- **GOTCHA**: Keep this file free of reflex/sqlmodel imports to avoid import-time side effects. Config is pure Python.
- **VALIDATE**: `cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && python -c "from custom_components.reflex_clerk_api.token_config import TokenConfig, InvalidTokenError; print(TokenConfig()); print('OK')"`

---

### Task 2: CREATE `custom_components/reflex_clerk_api/token_models.py`

- **ACTION**: Create database models for API tokens and passcodes
- **IMPLEMENT**:

```python
"""Database models for the token issuance system.

These models use Reflex's native rx.Model (SQLModel) and create tables
in the consuming application's database. After installing this package,
consumers must run:

    reflex db makemigrations --message "add clerk token tables"
    reflex db migrate
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import reflex as rx
import sqlalchemy
from sqlmodel import Column, Field
from sqlalchemy import DateTime, String


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ApiToken(rx.Model, table=True):
    """Represents a user-issued API token.

    Tokens use the split-token pattern:
    - short_token: stored plaintext, indexed for O(1) lookup
    - long_token_hash: SHA-256 hash of the secret portion

    The full token string ({prefix}{short_token}_{long_token}) is only
    available at creation time and must not be stored.
    """

    __tablename__ = "clerk_api_tokens"

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        primary_key=True,
        sa_type=String(36),
    )
    user_id: str = Field(index=True, nullable=False, sa_type=String(255))
    name: str = Field(nullable=False, sa_type=String(255))
    prefix: str = Field(nullable=False, sa_type=String(50))
    short_token: str = Field(
        unique=True, index=True, nullable=False, sa_type=String(50),
    )
    long_token_hash: str = Field(nullable=False, sa_type=String(64))
    is_active: bool = Field(default=True, nullable=False)
    expires_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column("expires_at", DateTime(timezone=True), nullable=True),
    )
    last_used_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column("last_used_at", DateTime(timezone=True), nullable=True),
    )
    revoked_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column("revoked_at", DateTime(timezone=True), nullable=True),
    )
    revocation_reason: Optional[str] = Field(default=None, sa_type=String(500))
    created_at: datetime = Field(
        default_factory=_utc_now,
        sa_column=Column(
            "created_at",
            DateTime(timezone=True),
            server_default=sqlalchemy.func.now(),
            nullable=False,
        ),
    )
    updated_at: datetime = Field(
        default_factory=_utc_now,
        sa_column=Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=sqlalchemy.func.now(),
            onupdate=sqlalchemy.func.now(),
            nullable=False,
        ),
    )


class Passcode(rx.Model, table=True):
    """Represents a short-lived passcode for channel authentication.

    Passcodes are single-use: once verified, is_used is set to True.
    Expired or used passcodes should be cleaned up periodically.
    """

    __tablename__ = "clerk_passcodes"

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        primary_key=True,
        sa_type=String(36),
    )
    user_id: str = Field(index=True, nullable=False, sa_type=String(255))
    code_hash: str = Field(nullable=False, sa_type=String(64))
    user_identifier: str = Field(
        index=True, nullable=False, sa_type=String(255),
    )
    channel: str = Field(default="default", nullable=False, sa_type=String(50))
    expires_at: datetime = Field(
        sa_column=Column(
            "expires_at", DateTime(timezone=True), nullable=False,
        ),
    )
    is_used: bool = Field(default=False, nullable=False)
    created_at: datetime = Field(
        default_factory=_utc_now,
        sa_column=Column(
            "created_at",
            DateTime(timezone=True),
            server_default=sqlalchemy.func.now(),
            nullable=False,
        ),
    )
```

- **MIRROR**: `reflex-local-auth` model pattern (rx.Model, table=True, Field with sa_type, sa_column for DateTime)
- **DESIGN DECISIONS**:
  - `id: str` with UUID string (not `uuid.UUID`) — compatible with both SQLite and PostgreSQL, matches existing Syntropy-Journals pattern (`ChatSession.id`)
  - `sa_type=String(N)` on all string fields — explicit column sizing for DB portability
  - `DateTime(timezone=True)` for all datetime columns — timezone-aware storage
  - `server_default=sqlalchemy.func.now()` on created_at — DB-level default as fallback
  - `onupdate=sqlalchemy.func.now()` on updated_at — auto-update on row modification
  - `__tablename__` with `clerk_` prefix — namespacing to avoid consumer table conflicts
  - `short_token` is `unique=True, index=True` — O(1) lookup for split-token verification
  - `user_identifier` on Passcode is indexed — needed for passcode lookup by email/username
- **IMPORTS**: `reflex`, `sqlmodel`, `sqlalchemy`, `uuid`, `datetime` (all already transitive deps)
- **GOTCHA**: `sa_column` and `sa_type` cannot be used together on the same Field. For datetime columns that need `server_default`, use `sa_column=Column(...)`. For simple string columns, use `sa_type=String(N)`.
- **GOTCHA**: Overriding the default `id` field on `rx.Model` emits a deprecation warning in Reflex 0.8.15+. This is expected and harmless until 0.9.0. When 0.9 ships, migrate to `@rx.ModelRegistry.register` + `sqlmodel.SQLModel` base class.
- **VALIDATE**: `cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && python -c "from custom_components.reflex_clerk_api.token_models import ApiToken, Passcode; print(ApiToken.__tablename__, Passcode.__tablename__); print('OK')"`

---

### Task 3: UPDATE `custom_components/reflex_clerk_api/clerk_provider.py` — Add ClassVar and classmethod

- **ACTION**: Add `_token_config` ClassVar and `set_token_config()` classmethod to `ClerkState`
- **IMPLEMENT**: Insert after line 61 (after `_claims_options` ClassVar block):

```python
    _token_config: ClassVar[TokenConfig | None] = None
    """Token issuance configuration. Set via wrap_app() or set_token_config()."""
```

- **IMPLEMENT**: Insert a new classmethod after `set_claims_options()` (after line 86):

```python
    @classmethod
    def set_token_config(
        cls,
        prefix: str = "token_",
        token_code_length: int = 32,
        short_token_length: int = 6,
        passcode_length: int = 6,
        passcode_ttl_seconds: int = 600,
    ) -> None:
        """Configure the token issuance system.

        Args:
            prefix: String prefix for generated API tokens.
            token_code_length: Bytes of entropy for the long token (default 32 = 256 bits).
            short_token_length: Bytes for the short token identifier (default 6).
            passcode_length: Number of digits in passcodes (default 6).
            passcode_ttl_seconds: Passcode time-to-live in seconds (default 600).
        """
        cls._token_config = TokenConfig(
            prefix=prefix,
            token_code_length=token_code_length,
            short_token_length=short_token_length,
            passcode_length=passcode_length,
            passcode_ttl_seconds=passcode_ttl_seconds,
        )
```

- **IMPLEMENT**: Add import at top of file (after existing imports, ~line 18):

```python
from .token_config import TokenConfig
```

- **MIRROR**: `set_claims_options()` at line 84-86 (public classmethod setting ClassVar)
- **MIRROR**: `_claims_options` ClassVar declaration at lines 56-61
- **GOTCHA**: Import `TokenConfig` from `token_config.py`, NOT from `token_models.py` — keep the import lightweight (no sqlmodel/sqlalchemy at import time for config)
- **VALIDATE**: `cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && python -c "from custom_components.reflex_clerk_api.clerk_provider import ClerkState; ClerkState.set_token_config(prefix='test_'); print(ClerkState._token_config); print('OK')"`

---

### Task 4: UPDATE `custom_components/reflex_clerk_api/clerk_provider.py` — Update wrap_app() and clerk_provider()

- **ACTION**: Add token config parameters to both `clerk_provider()` and `wrap_app()`
- **IMPLEMENT**: Update `clerk_provider()` signature (line 704-735) to add new parameters:

```python
def clerk_provider(
    *children,
    publishable_key: str,
    secret_key: str | None = None,
    register_user_state: bool = False,
    appearance: Appearance | None = None,
    token_prefix: str | None = None,
    token_code_length: int = 32,
    short_token_length: int = 6,
    passcode_length: int = 6,
    passcode_ttl_seconds: int = 600,
    **props,
) -> rx.Component:
```

- **IMPLEMENT**: Add token config logic inside `clerk_provider()` body, after the `register_user_state` block (after ~line 728):

```python
    if token_prefix is not None:
        ClerkState.set_token_config(
            prefix=token_prefix,
            token_code_length=token_code_length,
            short_token_length=short_token_length,
            passcode_length=passcode_length,
            passcode_ttl_seconds=passcode_ttl_seconds,
        )
```

- **IMPLEMENT**: Update `wrap_app()` signature (line 738-766) to add new parameters:

```python
def wrap_app(
    app: rx.App,
    publishable_key: str,
    secret_key: str | None = None,
    register_user_state: bool = False,
    appearance: Appearance | None = None,
    token_prefix: str | None = None,
    token_code_length: int = 32,
    short_token_length: int = 6,
    passcode_length: int = 6,
    passcode_ttl_seconds: int = 600,
    **props,
) -> rx.App:
```

- **IMPLEMENT**: Update the `wrap_app()` lambda (line 759-765) to pass new params:

```python
    app.app_wraps[(1, "ClerkProvider")] = lambda _: clerk_provider(
        publishable_key=publishable_key,
        secret_key=secret_key,
        register_user_state=register_user_state,
        appearance=appearance,
        token_prefix=token_prefix,
        token_code_length=token_code_length,
        short_token_length=short_token_length,
        passcode_length=passcode_length,
        passcode_ttl_seconds=passcode_ttl_seconds,
        **props,
    )
    return app
```

- **IMPLEMENT**: Update docstrings for both functions to document the new parameters
- **MIRROR**: Existing parameter passing pattern in `wrap_app()` — params forwarded 1:1 to `clerk_provider()`
- **DESIGN DECISION**: `token_prefix=None` as default means token system is opt-in. If `token_prefix` is not provided, `ClerkState._token_config` stays `None` and token operations will raise a clear error. This avoids side effects for existing users who don't need tokens.
- **GOTCHA**: The lambda in `wrap_app()` captures variables by closure. All new params must be passed explicitly (not via `**props`) to ensure correct binding.
- **VALIDATE**: `cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && python -c "
from custom_components.reflex_clerk_api.clerk_provider import ClerkState, wrap_app
import reflex as rx
# Verify config flows through
ClerkState.set_token_config(prefix='test_', passcode_ttl_seconds=300)
assert ClerkState._token_config is not None
assert ClerkState._token_config.prefix == 'test_'
assert ClerkState._token_config.passcode_ttl_seconds == 300
print('OK')
"`

---

### Task 5: UPDATE `custom_components/reflex_clerk_api/__init__.py` — Export new public API

- **ACTION**: Add imports and exports for token models, config, and exceptions
- **IMPLEMENT**: Add new import blocks after existing imports (after line 28):

```python
from .token_config import (
    ExpiredPasscodeError,
    ExpiredTokenError,
    InvalidPasscodeError,
    InvalidTokenError,
    PasscodeError,
    RevokedTokenError,
    TokenConfig,
    TokenError,
)
from .token_models import ApiToken, Passcode
```

- **IMPLEMENT**: Add to `__all__` list (alphabetically, matching existing convention):

```python
    "ApiToken",
    "ExpiredPasscodeError",
    "ExpiredTokenError",
    "InvalidPasscodeError",
    "InvalidTokenError",
    "Passcode",
    "PasscodeError",
    "RevokedTokenError",
    "TokenConfig",
    "TokenError",
```

- **MIRROR**: Existing import/export pattern at lines 3-54 — grouped by source module, alphabetical in `__all__`
- **GOTCHA**: Importing `token_models` triggers `rx.Model` registration. This is by design — models must be imported to be discovered by `reflex db makemigrations`. The import happens when consumers do `import reflex_clerk_api` or `from reflex_clerk_api import ClerkState`.
- **VALIDATE**: `cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && python -c "
from custom_components.reflex_clerk_api import (
    ApiToken, Passcode, TokenConfig,
    InvalidTokenError, ExpiredTokenError, RevokedTokenError,
    InvalidPasscodeError, ExpiredPasscodeError,
    TokenError, PasscodeError,
)
print('All exports available')
print(f'ApiToken table: {ApiToken.__tablename__}')
print(f'Passcode table: {Passcode.__tablename__}')
print(f'TokenConfig defaults: {TokenConfig()}')
print('OK')
"`

---

### Task 6: CREATE unit test for token_config.py

- **ACTION**: Create a test file for configuration and exception classes
- **IMPLEMENT**: Create `tests/test_token_config.py`:

```python
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
```

- **MIRROR**: Test style from `tests/test_demo.py` (pytest, descriptive names)
- **VALIDATE**: `cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && python -m pytest tests/test_token_config.py -v`

---

### Task 7: CREATE unit test for token_models.py

- **ACTION**: Create a test file verifying model definitions compile and have correct schema
- **IMPLEMENT**: Create `tests/test_token_models.py`:

```python
"""Tests for token database model definitions.

These tests verify model schema correctness without requiring a running database.
They use SQLModel/SQLAlchemy introspection to check table definitions.
"""

import uuid
from datetime import datetime, timezone

import pytest

from custom_components.reflex_clerk_api.token_models import ApiToken, Passcode


class TestApiTokenModel:
    """Tests for ApiToken model definition."""

    def test_tablename(self):
        assert ApiToken.__tablename__ == "clerk_api_tokens"

    def test_has_required_columns(self):
        columns = {c.name for c in ApiToken.__table__.columns}
        expected = {
            "id", "user_id", "name", "prefix", "short_token",
            "long_token_hash", "is_active", "expires_at", "last_used_at",
            "revoked_at", "revocation_reason", "created_at", "updated_at",
        }
        assert expected.issubset(columns)

    def test_primary_key(self):
        pk_cols = [c.name for c in ApiToken.__table__.primary_key.columns]
        assert pk_cols == ["id"]

    def test_short_token_unique_index(self):
        col = ApiToken.__table__.c.short_token
        assert col.unique is True
        assert col.index is True

    def test_user_id_indexed(self):
        col = ApiToken.__table__.c.user_id
        assert col.index is True

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
            "id", "user_id", "code_hash", "user_identifier",
            "channel", "expires_at", "is_used", "created_at",
        }
        assert expected.issubset(columns)

    def test_primary_key(self):
        pk_cols = [c.name for c in Passcode.__table__.primary_key.columns]
        assert pk_cols == ["id"]

    def test_user_id_indexed(self):
        col = Passcode.__table__.c.user_id
        assert col.index is True

    def test_user_identifier_indexed(self):
        col = Passcode.__table__.c.user_identifier
        assert col.index is True

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
```

- **MIRROR**: Schema introspection pattern — tests verify DDL correctness via `__table__.columns` without a live DB
- **GOTCHA**: SQLModel model instantiation without a session works for checking defaults. The models won't be persisted but field defaults are accessible.
- **VALIDATE**: `cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && python -m pytest tests/test_token_models.py -v`

---

## Testing Strategy

### Unit Tests to Write

| Test File | Test Cases | Validates |
|-----------|------------|-----------|
| `tests/test_token_config.py` | Default values, custom values, frozen, validation errors, exception hierarchy | TokenConfig dataclass, all 7 exceptions |
| `tests/test_token_models.py` | Table names, columns, PKs, indexes, unique constraints, defaults, nullable | ApiToken and Passcode model schemas |

### Edge Cases Checklist

- [x] Empty prefix rejected (TokenConfig validation)
- [x] Token code length below minimum rejected
- [x] Passcode length outside bounds rejected
- [x] TTL below minimum rejected
- [x] Frozen config cannot be mutated
- [x] UUID primary key auto-generated
- [x] Optional fields default to None
- [x] Boolean fields default correctly (is_active=True, is_used=False)
- [ ] Model import triggers table registration in SQLModel metadata (implicit, verified by model tests compiling)

---

## Validation Commands

### Level 1: STATIC_ANALYSIS

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && ruff check custom_components/reflex_clerk_api/token_config.py custom_components/reflex_clerk_api/token_models.py && pyright custom_components/reflex_clerk_api/token_config.py custom_components/reflex_clerk_api/token_models.py
```

**EXPECT**: Exit 0, no errors or warnings

### Level 2: UNIT_TESTS

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && python -m pytest tests/test_token_config.py tests/test_token_models.py -v
```

**EXPECT**: All tests pass

### Level 3: IMPORT_VERIFICATION

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && python -c "
from custom_components.reflex_clerk_api import (
    ApiToken, Passcode, TokenConfig,
    InvalidTokenError, ExpiredTokenError, RevokedTokenError,
    InvalidPasscodeError, ExpiredPasscodeError,
    ClerkState,
)
# Verify config integration
ClerkState.set_token_config(prefix='test_')
assert ClerkState._token_config is not None
assert ClerkState._token_config.prefix == 'test_'
print('All imports and config integration verified')
"
```

**EXPECT**: Prints success message, exit 0

### Level 4: EXISTING_TESTS_NOT_BROKEN

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && python -m pytest tests/ -v --ignore=tests/test_demo.py
```

**EXPECT**: All new tests pass, no regressions (test_demo.py ignored as it requires Clerk credentials)

---

## Acceptance Criteria

- [ ] `TokenConfig` dataclass created with all 5 fields and validation
- [ ] 7 exception classes created (TokenError, InvalidTokenError, ExpiredTokenError, RevokedTokenError, PasscodeError, InvalidPasscodeError, ExpiredPasscodeError)
- [ ] `ApiToken(rx.Model, table=True)` with 13 columns, correct types, indexes
- [ ] `Passcode(rx.Model, table=True)` with 8 columns, correct types, indexes
- [ ] `ClerkState._token_config: ClassVar[TokenConfig | None]` added
- [ ] `ClerkState.set_token_config()` classmethod works
- [ ] `clerk_provider()` accepts token params and calls `set_token_config()`
- [ ] `wrap_app()` accepts token params and forwards to `clerk_provider()`
- [ ] `__init__.py` exports all new public API (10 new exports)
- [ ] All Level 1-4 validation commands pass
- [ ] No regressions in existing package functionality

---

## Completion Checklist

- [ ] Task 1: token_config.py created and validates
- [ ] Task 2: token_models.py created and validates
- [ ] Task 3: ClerkState ClassVar and classmethod added
- [ ] Task 4: wrap_app() and clerk_provider() updated
- [ ] Task 5: __init__.py exports updated
- [ ] Task 6: test_token_config.py written and passes
- [ ] Task 7: test_token_models.py written and passes
- [ ] Level 1: ruff + pyright pass on new files
- [ ] Level 2: All unit tests pass
- [ ] Level 3: Import verification passes
- [ ] Level 4: No regressions

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| rx.Model deprecation warning for custom PK | HIGH | LOW | Expected in 0.8.15+; harmless. Document migration path to `@rx.ModelRegistry.register` for 0.9.0 |
| Circular import between token_models.py and clerk_provider.py | LOW | HIGH | token_models.py has NO imports from clerk_provider.py; token_config.py is pure stdlib. One-way dependency only. |
| sa_column + sa_type conflict in SQLModel Field | MEDIUM | MEDIUM | Use `sa_column` for datetime fields (need server_default), `sa_type` for string fields (no server default needed). Never both on same Field. |
| Model import side effects at package import time | LOW | LOW | Intentional — models must register with SQLModel metadata. No DB connection until rx.session() is called. |
| Existing tests break due to new imports | LOW | MEDIUM | New imports are additive; existing module structure unchanged. Run full test suite to verify. |

---

## Notes

- **Token config is opt-in**: `token_prefix=None` by default in `wrap_app()`. If not set, `ClerkState._token_config` stays `None`. Phase 2 helpers will check for `None` and raise a clear error ("Token system not configured. Pass token_prefix to wrap_app().").
- **Consumer migration required**: After installing the updated package, consumers must run `reflex db makemigrations` + `reflex db migrate` to create the new tables. This should be documented in Phase 8 and in the package's changelog.
- **Future-proofing for 0.9**: The rx.Model deprecation for custom PKs is tracked. When Reflex 0.9 ships, a migration PR should switch to `@rx.ModelRegistry.register` + `sqlmodel.SQLModel`. The models themselves won't change — only the base class and decorator.
