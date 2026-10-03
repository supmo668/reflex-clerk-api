"""``set_clerk_session`` must handle every claim-validation failure gracefully.

Regression: authlib's ``ExpiredTokenError`` is a sibling of ``InvalidTokenError``
(both subclass ``JoseError`` directly), NOT a subclass. ``set_clerk_session``
only caught ``InvalidTokenError``, so a stale Clerk JWT (e.g. a user returning
from Stripe checkout) raised out of the background event. The session was
neither set nor cleared, ``auth_checked`` never became True, and every page
waiting on auth hung behind Reflex's "An error occurred" toast.

The handler is driven directly through its underlying function with a minimal
stand-in for ``self``: the claim-failure branches return before any
``async with self`` block, so no live Reflex state proxy is needed.
"""

import asyncio
import time
from typing import Any

import pytest
from authlib.jose import JsonWebKey, jwt

from custom_components.reflex_clerk_api.clerk_provider import ClerkState

KID = "test-kid"
LEEWAY = 60  # mirrors ``decoded.validate(leeway=60)`` in set_clerk_session


@pytest.fixture(scope="module")
def rsa_key():
    return JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": KID})


class _FakeClerkState:
    """What ``set_clerk_session`` reads before its first ``async with self``."""

    def __init__(self, jwks: list[dict[str, Any]], claims_options: dict[str, Any]):
        self._jwks = jwks
        self._claims_options = claims_options

    async def _get_jwk_keys(self) -> list[dict[str, Any]]:
        return self._jwks


def _drive(
    rsa_key, claims: dict[str, Any], claims_options: dict[str, Any] | None = None
):
    token = jwt.encode({"alg": "RS256", "kid": KID}, claims, rsa_key).decode()
    public_jwk = rsa_key.as_dict(is_private=False)
    fake = _FakeClerkState(
        [public_jwk],
        claims_options if claims_options is not None else ClerkState._claims_options,
    )
    return asyncio.run(ClerkState.set_clerk_session.fn(fake, token))


def _claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base = {
        "sub": "user_123",
        "iss": "https://clerk.example.com",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }
    base.update(overrides)
    return base


def test_expired_token_beyond_leeway_clears_session(rsa_key):
    now = int(time.time())
    claims = _claims(iat=now - 900, nbf=now - 900, exp=now - LEEWAY - 240)
    assert _drive(rsa_key, claims) is ClerkState.clear_clerk_session


def test_not_yet_valid_token_clears_session(rsa_key):
    now = int(time.time())
    claims = _claims(nbf=now + LEEWAY + 240)
    assert _drive(rsa_key, claims) is ClerkState.clear_clerk_session


def test_iat_in_future_clears_session(rsa_key):
    now = int(time.time())
    claims = _claims(iat=now + LEEWAY + 240)
    assert _drive(rsa_key, claims) is ClerkState.clear_clerk_session


def test_missing_essential_claim_clears_session(rsa_key):
    claims = _claims()
    del claims["nbf"]
    assert _drive(rsa_key, claims) is ClerkState.clear_clerk_session


def test_wrong_issuer_clears_session(rsa_key):
    options = {
        **ClerkState._claims_options,
        "iss": {"essential": True, "value": "https://other.example.com"},
    }
    assert _drive(rsa_key, _claims(), options) is ClerkState.clear_clerk_session
