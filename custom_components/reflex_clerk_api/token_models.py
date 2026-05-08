"""Database models for the token issuance system.

These models use Reflex's native rx.Model (SQLModel) and create tables
in the consuming application's database. After installing this package,
consumers must run::

    reflex db makemigrations --message "add clerk token tables"
    reflex db migrate

The legacy ``ApiToken`` model + its split-token issuance/verification
pipeline was retired by Syntropy-Journals issue #397 — the consuming
app moved to Unkey-managed tokens and the lib's ``clerk_api_tokens``
table created Alembic metadata drift on every autogenerate run.
``Passcode`` (below) is the only remaining model in this module.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import reflex as rx
import sqlalchemy
from sqlalchemy import DateTime, String
from sqlmodel import Column, Field


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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
