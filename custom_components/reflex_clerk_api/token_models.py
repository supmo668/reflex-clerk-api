"""Database models for the token issuance system.

These models use Reflex's native rx.Model (SQLModel) and create tables
in the consuming application's database. After installing this package,
consumers must run::

    reflex db makemigrations --message "add clerk token tables"
    reflex db migrate
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import reflex as rx
import sqlalchemy
from sqlalchemy import DateTime, String
from sqlmodel import Column, Field


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
    __table_args__ = {"extend_existing": True}

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        primary_key=True,
        sa_type=String(36),
    )
    user_id: str = Field(index=True, nullable=False, sa_type=String(255))
    name: str = Field(nullable=False, sa_type=String(255))
    prefix: str = Field(nullable=False, sa_type=String(50))
    short_token: str = Field(
        unique=True,
        index=True,
        nullable=False,
        sa_type=String(50),
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
    __table_args__ = {"extend_existing": True}

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        primary_key=True,
        sa_type=String(36),
    )
    user_id: str = Field(index=True, nullable=False, sa_type=String(255))
    code_hash: str = Field(nullable=False, sa_type=String(64))
    user_identifier: str = Field(
        index=True,
        nullable=False,
        sa_type=String(255),
    )
    channel: str = Field(default="default", nullable=False, sa_type=String(50))
    expires_at: datetime = Field(
        sa_column=Column(
            "expires_at",
            DateTime(timezone=True),
            nullable=False,
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
