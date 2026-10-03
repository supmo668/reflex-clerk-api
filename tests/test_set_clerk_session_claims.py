"""``set_clerk_session`` must end every bad-token path without raising.

Regression: authlib's ``ExpiredTokenError`` is a sibling of ``InvalidTokenError``
(both subclass ``JoseError`` directly), NOT a subclass. ``set_clerk_session``
only caught ``InvalidTokenError``, so a stale Clerk JWT (e.g. a user returning
from Stripe checkout) raised out of the background event. The session was
neither set nor cleared, ``auth_checked`` never became True, and every page
waiting on auth hung behind Reflex's "An error occurred" toast.

An expired token now first asks Clerk-JS for a FRESH token (bounded: one
refresh per window) and only clears the session if that also fails, so a
signed-in user is re-synced instead of being bounced to sign-in.

The handler is driven through its underlying function with a stand-in for
``self`` whose ``__setattr__`` is as strict as ``rx.State``: assigning an
undeclared var raises, exactly like ``SetUndefinedStateVarError``.
"""

import asyncio
import time
from typing import Any

import pytest
from authlib.jose import JsonWebKey, jwt
from reflex.event import EventSpec

from custom_components.reflex_clerk_api.clerk_provider import ClerkState

KID = "test-kid"
LEEWAY = 60  # mirrors ``decoded.validate(leeway=60)`` in set_clerk_session

_DECLARED = set(ClerkState.vars) | set(ClerkState.backend_vars)


@pytest.fixture(scope="module")
def rsa_key():
    return JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": KID})


class _FakeClerkState:
    """Stand-in ``self`` for ``set_clerk_session`` with rx.State's setattr rules."""

    def __init__(self, jwks: list[dict[str, Any]], claims_options: dict[str, Any]):
        object.__setattr__(self, "_jwks", jwks)
        object.__setattr__(self, "_claims_options", claims_options)
        object.__setattr__(self, "jwk_resets", 0)
        defaults = ClerkState.get_fields() if hasattr(ClerkState, "get_fields") else {}
        for name in _DECLARED:
            field = defaults.get(name)
            default = getattr(field, "default", None) if field is not None else None
            object.__setattr__(self, name, default)
        object.__setattr__(self, "auth_checked", False)
        object.__setattr__(self, "is_signed_in", False)

    def __setattr__(self, name: str, value: Any) -> None:
        if name not in _DECLARED:
            raise AttributeError(
                f"undeclared state var {name!r} (rx.State would raise)"
            )
        object.__setattr__(self, name, value)

    def __getattr__(self, name: str) -> Any:
        # Class-level config (ClassVars) resolves on the real class, as on rx.State.
        return getattr(ClerkState, name)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def _get_jwk_keys(self) -> list[dict[str, Any]]:
        return self._jwks

    def _request_jwk_reset(self) -> None:
        object.__setattr__(self, "jwk_resets", self.jwk_resets + 1)

    @property
    def _dependent_handlers(self):
        return ClerkState._dependent_handlers


def _fake(rsa_key, claims_options=None, jwk=None) -> _FakeClerkState:
    return _FakeClerkState(
        [jwk or rsa_key.as_dict(is_private=False)],
        claims_options if claims_options is not None else ClerkState._claims_options,
    )


def _token(rsa_key, claims: dict[str, Any], kid: str = KID) -> str:
    return jwt.encode({"alg": "RS256", "kid": kid}, claims, rsa_key).decode()


def _run(fake, token):
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


def _expired_claims() -> dict[str, Any]:
    now = int(time.time())
    return _claims(iat=now - 900, nbf=now - 900, exp=now - LEEWAY - 240)


def _is_token_refresh(result: Any) -> bool:
    if not isinstance(result, EventSpec):
        return False
    args = {name._js_expr: str(value) for name, value in result.args}
    return (
        "getToken" in args.get("javascript_code", "")
        and "skipCache" in args.get("javascript_code", "")
        and "set_clerk_session" in args.get("callback", "")
    )


# --- expired: refresh first, clear only if the refresh fails -----------------


def test_expired_token_requests_fresh_token_instead_of_clearing(rsa_key):
    fake = _fake(rsa_key)
    result = _run(fake, _token(rsa_key, _expired_claims()))
    assert _is_token_refresh(result), result
    assert fake.is_signed_in is False


def test_second_expired_token_in_window_clears_session(rsa_key):
    fake = _fake(rsa_key)
    token = _token(rsa_key, _expired_claims())
    assert _is_token_refresh(_run(fake, token))
    assert _run(fake, token) is ClerkState.clear_clerk_session


def test_refresh_budget_renews_after_window(rsa_key, monkeypatch):
    fake = _fake(rsa_key)
    token = _token(rsa_key, _expired_claims())
    assert _is_token_refresh(_run(fake, token))
    real_time = time.time
    window = ClerkState._expired_refresh_window_seconds
    monkeypatch.setattr(time, "time", lambda: real_time() + window + 1)
    assert _is_token_refresh(_run(fake, token))


def test_valid_token_after_refresh_signs_in_and_resets_budget(rsa_key):
    fake = _fake(rsa_key)
    assert _is_token_refresh(_run(fake, _token(rsa_key, _expired_claims())))
    _run(fake, _token(rsa_key, _claims()))
    assert fake.is_signed_in is True
    assert fake.auth_checked is True
    assert fake._expired_refresh_attempts == 0


@pytest.mark.parametrize("token", [None, "", "   "])
def test_null_or_empty_token_clears_without_raising(rsa_key, token):
    fake = _fake(rsa_key)
    assert _run(fake, token) is ClerkState.clear_clerk_session
    assert fake.jwk_resets == 0


# --- signature / key-set failures: clear + re-fetch JWKs --------------------


def test_bad_signature_clears_and_resets_jwks(rsa_key):
    other = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": KID})
    fake = _fake(rsa_key, jwk=other.as_dict(is_private=False))
    assert _run(fake, _token(rsa_key, _claims())) is ClerkState.clear_clerk_session
    assert fake.jwk_resets == 1
    assert "BadSignatureError" in fake._auth_error


def test_unknown_kid_clears_and_resets_jwks(rsa_key):
    """Key rotation: no JWK matches the token's kid -> authlib ValueError."""
    rotated = JsonWebKey.generate_key(
        "RSA", 2048, is_private=True, options={"kid": "rotated-kid"}
    )
    fake = _fake(rsa_key, jwk=rotated.as_dict(is_private=False))
    assert _run(fake, _token(rsa_key, _claims())) is ClerkState.clear_clerk_session
    assert fake.jwk_resets == 1
    assert "ValueError" in fake._auth_error


def test_malformed_token_clears_and_resets_jwks(rsa_key):
    fake = _fake(rsa_key)
    assert _run(fake, "not-a-jwt") is ClerkState.clear_clerk_session
    assert fake.jwk_resets == 1
    assert "DecodeError" in fake._auth_error


# --- other claim failures: clear --------------------------------------------


def test_not_yet_valid_token_clears_session(rsa_key):
    now = int(time.time())
    fake = _fake(rsa_key)
    token = _token(rsa_key, _claims(nbf=now + LEEWAY + 240))
    assert _run(fake, token) is ClerkState.clear_clerk_session


def test_iat_in_future_clears_session(rsa_key):
    now = int(time.time())
    fake = _fake(rsa_key)
    token = _token(rsa_key, _claims(iat=now + LEEWAY + 240))
    assert _run(fake, token) is ClerkState.clear_clerk_session


def test_missing_essential_claim_clears_session(rsa_key):
    claims = _claims()
    del claims["nbf"]
    assert (
        _run(_fake(rsa_key), _token(rsa_key, claims)) is ClerkState.clear_clerk_session
    )


def test_wrong_issuer_clears_session(rsa_key):
    options = {
        **ClerkState._claims_options,
        "iss": {"essential": True, "value": "https://other.example.com"},
    }
    fake = _fake(rsa_key, claims_options=options)
    assert _run(fake, _token(rsa_key, _claims())) is ClerkState.clear_clerk_session


def test_clear_marks_auth_checked():
    """Every terminal clear path ends with auth_checked=True (no hang)."""

    class _S:
        auth_checked = False

        def reset(self):
            self.auth_checked = False

        _dependent_handlers = ClerkState._dependent_handlers

    s = _S()
    ClerkState.clear_clerk_session.fn(s)
    assert s.auth_checked is True
