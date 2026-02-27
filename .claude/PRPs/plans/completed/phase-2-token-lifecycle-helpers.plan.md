# Feature: Token Lifecycle Helpers

## Summary

Implement the four core token lifecycle functions (`issue_token`, `verify_token`, `revoke_token`, `list_tokens`) and three result dataclasses (`ApiTokenResult`, `TokenVerification`, `TokenSummary`) for the token issuance system. Functions follow the existing `get_user()` async helper pattern in `clerk_provider.py`, using `rx.session()` for database operations and stdlib `secrets`/`hashlib` for cryptography. Result dataclasses go in `token_config.py` alongside existing types.

## User Story

As a Reflex+Clerk developer
I want to issue, verify, revoke, and list API tokens tied to Clerk users
So that I can add programmatic API access to my SaaS app in under 10 lines

## Problem Statement

Phase 1 established the data layer (models + config). Developers still cannot actually issue or verify tokens — the CRUD operations don't exist yet.

## Solution Statement

Four module-level async functions in `clerk_provider.py` following the established helper pattern. `issue_token`, `revoke_token`, and `list_tokens` require `current_state` for user authorization. `verify_token` is stateless (accesses `ClerkState._token_config` ClassVar directly + `rx.session()`) to enable use in FastAPI dependencies in Phase 4.

## Metadata

| Field            | Value                                          |
| ---------------- | ---------------------------------------------- |
| Type             | NEW_CAPABILITY                                 |
| Complexity       | MEDIUM                                         |
| Systems Affected | clerk_provider.py, token_config.py, __init__.py |
| Dependencies     | stdlib only (secrets, hashlib, datetime)        |
| Estimated Tasks  | 5                                              |

---

## UX Design

### Before State
```
Developer has:
  wrap_app(app, ..., token_prefix="myapp_")  ← config works
  ApiToken model exists in DB                ← tables exist

But CANNOT:
  issue_token()   → ❌ function doesn't exist
  verify_token()  → ❌ function doesn't exist
  revoke_token()  → ❌ function doesn't exist
  list_tokens()   → ❌ function doesn't exist
```

### After State
```
Developer can:
  result = await clerk.issue_token(self, name="My Key", expires_in_days=90)
  # → ApiTokenResult(token_string="myapp_a1b2c3_kF7xYz...", id=..., ...)

  verification = clerk.verify_token("myapp_a1b2c3_kF7xYz...")
  # → TokenVerification(user_id="user_abc", token_id=..., name=...)

  await clerk.revoke_token(self, token_id="uuid-here", reason="compromised")
  # → None (soft-deletes token)

  tokens = await clerk.list_tokens(self)
  # → [TokenSummary(id=..., name=..., display_token="myapp_a1b2c3", ...)]
```

### Interaction Changes
| Location | Before | After | User Impact |
|----------|--------|-------|-------------|
| `clerk_provider.py` | No token helpers | 4 async functions | Full token CRUD |
| `token_config.py` | Config + exceptions only | + 3 result dataclasses | Typed return values |
| `__init__.py` | No token helper exports | 7 new exports | Direct import access |

---

## Mandatory Reading

**CRITICAL: Implementation agent MUST read these files before starting any task:**

| Priority | File | Lines | Why Read This |
|----------|------|-------|---------------|
| P0 | `custom_components/reflex_clerk_api/clerk_provider.py` | 601-641 | `_get_state_within_handler()` + `get_user()` pattern to MIRROR exactly |
| P0 | `custom_components/reflex_clerk_api/token_models.py` | 27-89 | ApiToken model fields — must match INSERT/SELECT operations |
| P0 | `custom_components/reflex_clerk_api/token_config.py` | 1-82 | TokenConfig fields + exception classes to use |
| P1 | `custom_components/reflex_clerk_api/clerk_provider.py` | 644-721 | `update_user_phone_number()` — error handling pattern |
| P1 | `custom_components/reflex_clerk_api/__init__.py` | 1-75 | Current exports — extend with new symbols |
| P2 | `tests/test_token_config.py` | 1-93 | Test structure to follow |
| P2 | `tests/test_token_models.py` | 1-133 | Test structure to follow |

---

## Patterns to Mirror

**ASYNC_HELPER_PATTERN:**
```python
# SOURCE: clerk_provider.py:616-641
# COPY THIS PATTERN for issue_token, revoke_token, list_tokens:
async def get_user(current_state: rx.State) -> clerk_backend_api.models.User:
    clerk_state = await _get_state_within_handler(current_state, ClerkState)
    user_id = clerk_state.user_id
    if user_id is None:
        raise MissingUserError("No user_id to get user for")
    # ... do work ...
    return result
```

**DB_SESSION_PATTERN:**
```python
# SOURCE: app/models/admin/user.py:85-96
# COPY THIS PATTERN for all database operations:
with rx.session() as session:
    key_row = UserApiKey(...)
    session.add(key_row)
    session.commit()

# SOURCE: app/models/admin/user.py:100-120
# COPY THIS PATTERN for SELECT + UPDATE:
with rx.session() as session:
    row = session.exec(
        select(ApiToken).where(ApiToken.short_token == short_token)
    ).first()
    if row:
        row.is_active = False
        session.add(row)
        session.commit()
```

**ERROR_HANDLING_PATTERN:**
```python
# SOURCE: clerk_provider.py:636-637
# COPY THIS PATTERN:
if user_id is None:
    raise MissingUserError("No user_id to issue token for")
```

**FROZEN_DATACLASS_PATTERN:**
```python
# SOURCE: token_config.py:50-51
# COPY THIS PATTERN for result types:
@dataclass(frozen=True)
class TokenConfig:
    prefix: str = "token_"
```

**EXPORT_PATTERN:**
```python
# SOURCE: __init__.py:4-11
# COPY THIS PATTERN:
from .clerk_provider import (
    get_user,
    issue_token,
    # ...
)
```

---

## Files to Change

| File | Action | Justification |
| ---- | ------ | ------------- |
| `custom_components/reflex_clerk_api/token_config.py` | UPDATE | Add 3 result dataclasses: ApiTokenResult, TokenVerification, TokenSummary |
| `custom_components/reflex_clerk_api/clerk_provider.py` | UPDATE | Add 4 helper functions: issue_token, verify_token, revoke_token, list_tokens |
| `custom_components/reflex_clerk_api/__init__.py` | UPDATE | Add 7 new exports (4 functions + 3 dataclasses) |
| `tests/test_token_helpers.py` | CREATE | Unit tests for token lifecycle logic |

---

## NOT Building (Scope Limits)

- **Passcode helpers** — Phase 3 (parallel, separate scope)
- **FastAPI dependencies** — Phase 4 (depends on this phase)
- **Token rotation** — Could-have feature, not in MVP
- **Bulk revocation** — Could-have feature, not in MVP
- **Rate limiting** — Consumer responsibility
- **`get_user` integration in verify** — verify_token returns user_id, consumer calls get_user() if needed

---

## Step-by-Step Tasks

### Task 1: UPDATE `token_config.py` — Add result dataclasses

- **ACTION**: Add `ApiTokenResult`, `TokenVerification`, `TokenSummary` frozen dataclasses
- **IMPLEMENT**:
  ```python
  @dataclass(frozen=True)
  class ApiTokenResult:
      """Returned when a new token is issued. token_string is shown ONCE."""
      id: str
      name: str
      prefix: str
      short_token: str
      token_string: str  # full {prefix}{short_token}_{long_token} — only at creation
      is_active: bool
      expires_at: datetime | None
      created_at: datetime

  @dataclass(frozen=True)
  class TokenVerification:
      """Returned when a token is successfully verified."""
      user_id: str
      token_id: str
      name: str

  @dataclass(frozen=True)
  class TokenSummary:
      """Returned by list_tokens(). No secrets exposed."""
      id: str
      name: str
      display_token: str  # "{prefix}{short_token}" — safe to show
      is_active: bool
      expires_at: datetime | None
      last_used_at: datetime | None
      created_at: datetime
  ```
- **MIRROR**: `token_config.py:50-51` — frozen dataclass pattern
- **IMPORTS**: Add `from datetime import datetime` (already imported via `__future__` annotations)
- **GOTCHA**: Use `from __future__ import annotations` (already present) so `datetime | None` works
- **VALIDATE**: `uv run ruff check custom_components/reflex_clerk_api/token_config.py`

### Task 2: UPDATE `clerk_provider.py` — Add `issue_token()` function

- **ACTION**: Add `issue_token()` async helper after `update_user_phone_number()`
- **IMPLEMENT**:
  ```python
  async def issue_token(
      current_state: rx.State,
      name: str,
      expires_in_days: int | None = None,
  ) -> ApiTokenResult:
      """Issue a new API token for the currently logged-in user.

      The returned ApiTokenResult.token_string contains the full token and is only
      available at creation time. It must not be stored by the application.

      Args:
          current_state: The `self` state from the current event handler.
          name: A user-facing label for this token.
          expires_in_days: Optional number of days until the token expires. None = no expiry.

      Returns:
          ApiTokenResult with the full token string (shown once).

      Raises:
          MissingUserError: If no user is logged in.
          TokenError: If the token system is not configured.
      """
      clerk_state = await _get_state_within_handler(current_state, ClerkState)
      user_id = clerk_state.user_id
      if user_id is None:
          raise MissingUserError("No user_id to issue token for")

      config = ClerkState._token_config
      if config is None:
          raise TokenError("Token issuance not configured. Call wrap_app() with token_prefix.")

      short_token = secrets.token_urlsafe(config.short_token_length)
      long_token = secrets.token_urlsafe(config.token_code_length)
      long_token_hash = hashlib.sha256(long_token.encode()).hexdigest()

      now = datetime.now(timezone.utc)
      expires_at = None
      if expires_in_days is not None:
          expires_at = now + timedelta(days=expires_in_days)

      token_row = ApiToken(
          user_id=user_id,
          name=name,
          prefix=config.prefix,
          short_token=short_token,
          long_token_hash=long_token_hash,
          is_active=True,
          expires_at=expires_at,
      )

      with rx.session() as session:
          session.add(token_row)
          session.commit()
          session.refresh(token_row)

      token_string = f"{config.prefix}{short_token}_{long_token}"

      return ApiTokenResult(
          id=token_row.id,
          name=token_row.name,
          prefix=config.prefix,
          short_token=short_token,
          token_string=token_string,
          is_active=True,
          expires_at=expires_at,
          created_at=token_row.created_at,
      )
  ```
- **MIRROR**: `clerk_provider.py:616-641` — `get_user()` pattern
- **IMPORTS**: Add `import hashlib`, `import secrets`, `from datetime import timedelta`, `from sqlmodel import select` at top. Add `from .token_config import ApiTokenResult, TokenConfig, TokenError, ...` and `from .token_models import ApiToken`
- **GOTCHA**: `session.refresh(token_row)` needed to get auto-generated fields (id, created_at) after commit. `rx.session()` is synchronous even in async functions — this is the established pattern.
- **VALIDATE**: `uv run ruff check custom_components/reflex_clerk_api/clerk_provider.py`

### Task 3: UPDATE `clerk_provider.py` — Add `verify_token()`, `revoke_token()`, `list_tokens()`

- **ACTION**: Add remaining 3 helper functions after `issue_token()`
- **IMPLEMENT**:
  ```python
  def verify_token(token_string: str) -> TokenVerification:
      """Verify an API token and return the associated user information.

      This function is synchronous and stateless — it only needs database access
      and the configured token prefix (ClassVar). Suitable for use in FastAPI
      dependencies.

      Args:
          token_string: The full token string (e.g., "myapp_a1b2c3_kF7xYz...").

      Returns:
          TokenVerification with user_id, token_id, and name.

      Raises:
          InvalidTokenError: Token is malformed or not found.
          ExpiredTokenError: Token has expired.
          RevokedTokenError: Token has been revoked.
          TokenError: Token system not configured.
      """
      config = ClerkState._token_config
      if config is None:
          raise TokenError("Token issuance not configured.")

      # Parse: {prefix}{short_token}_{long_token}
      if not token_string.startswith(config.prefix):
          raise InvalidTokenError("Token prefix does not match")

      remainder = token_string[len(config.prefix):]
      parts = remainder.split("_", 1)
      if len(parts) != 2 or not parts[0] or not parts[1]:
          raise InvalidTokenError("Malformed token string")

      short_token, long_token = parts

      with rx.session() as session:
          token_row = session.exec(
              select(ApiToken).where(ApiToken.short_token == short_token)
          ).first()

          if token_row is None:
              raise InvalidTokenError("Token not found")

          if not token_row.is_active:
              raise RevokedTokenError("Token has been revoked")

          if token_row.expires_at is not None:
              now = datetime.now(timezone.utc)
              expires_at = token_row.expires_at
              if expires_at.tzinfo is None:
                  expires_at = expires_at.replace(tzinfo=timezone.utc)
              if now > expires_at:
                  raise ExpiredTokenError("Token has expired")

          expected_hash = hashlib.sha256(long_token.encode()).hexdigest()
          if not secrets.compare_digest(token_row.long_token_hash, expected_hash):
              raise InvalidTokenError("Token verification failed")

          # Update last_used_at
          token_row.last_used_at = datetime.now(timezone.utc)
          session.add(token_row)
          session.commit()

          return TokenVerification(
              user_id=token_row.user_id,
              token_id=token_row.id,
              name=token_row.name,
          )


  async def revoke_token(
      current_state: rx.State,
      token_id: str,
      reason: str | None = None,
  ) -> None:
      """Revoke an API token by its ID (soft-delete).

      Args:
          current_state: The `self` state from the current event handler.
          token_id: The UUID of the token to revoke.
          reason: Optional reason for revocation.

      Raises:
          MissingUserError: If no user is logged in.
          InvalidTokenError: If no matching active token is found for this user.
      """
      clerk_state = await _get_state_within_handler(current_state, ClerkState)
      user_id = clerk_state.user_id
      if user_id is None:
          raise MissingUserError("No user_id to revoke token for")

      with rx.session() as session:
          token_row = session.exec(
              select(ApiToken).where(
                  ApiToken.id == token_id,
                  ApiToken.user_id == user_id,
                  ApiToken.is_active == True,  # noqa: E712
              )
          ).first()

          if token_row is None:
              raise InvalidTokenError("No active token found with this ID for the current user")

          token_row.is_active = False
          token_row.revoked_at = datetime.now(timezone.utc)
          token_row.revocation_reason = reason
          session.add(token_row)
          session.commit()


  async def list_tokens(current_state: rx.State) -> list[TokenSummary]:
      """List all active tokens for the currently logged-in user.

      Args:
          current_state: The `self` state from the current event handler.

      Returns:
          List of TokenSummary objects (no secrets exposed).

      Raises:
          MissingUserError: If no user is logged in.
      """
      clerk_state = await _get_state_within_handler(current_state, ClerkState)
      user_id = clerk_state.user_id
      if user_id is None:
          raise MissingUserError("No user_id to list tokens for")

      with rx.session() as session:
          rows = session.exec(
              select(ApiToken).where(
                  ApiToken.user_id == user_id,
                  ApiToken.is_active == True,  # noqa: E712
              )
          ).all()

          return [
              TokenSummary(
                  id=row.id,
                  name=row.name,
                  display_token=f"{row.prefix}{row.short_token}",
                  is_active=row.is_active,
                  expires_at=row.expires_at,
                  last_used_at=row.last_used_at,
                  created_at=row.created_at,
              )
              for row in rows
          ]
  ```
- **MIRROR**: `clerk_provider.py:616-641` for state access, `app/models/admin/user.py:100-120` for DB patterns
- **IMPORTS**: Same imports from Task 2 (already added). Also import `ExpiredTokenError`, `InvalidTokenError`, `RevokedTokenError`, `TokenVerification`, `TokenSummary` from `.token_config`
- **GOTCHA**: `verify_token()` is synchronous (not async) — it uses `rx.session()` which is sync. This is intentional for FastAPI `Depends()` compatibility. `revoke_token()` checks `user_id == user_id` to ensure users can only revoke their own tokens. Use `# noqa: E712` on `== True` comparisons (SQLAlchemy needs `==` not `is`). Handle naive datetimes from DB by adding `tzinfo=timezone.utc` if missing.
- **VALIDATE**: `uv run ruff check custom_components/reflex_clerk_api/clerk_provider.py`

### Task 4: UPDATE `__init__.py` — Add exports

- **ACTION**: Add 7 new symbols to imports and `__all__`
- **IMPLEMENT**:
  - Add to `from .clerk_provider import (...)`: `get_user`, `issue_token`, `verify_token`, `revoke_token`, `list_tokens`
  - Add to `from .token_config import (...)`: `ApiTokenResult`, `TokenVerification`, `TokenSummary`
  - Add to `__all__`: `"ApiTokenResult"`, `"TokenSummary"`, `"TokenVerification"`, `"get_user"`, `"issue_token"`, `"list_tokens"`, `"revoke_token"`, `"verify_token"`
- **MIRROR**: `__init__.py:4-11` and `__init__.py:22-31` — existing import groups
- **GOTCHA**: `get_user` was not previously exported — add it now since it's part of the public API (already used in docs/examples). Keep `__all__` sorted alphabetically.
- **VALIDATE**: `uv run ruff check custom_components/reflex_clerk_api/__init__.py`

### Task 5: CREATE `tests/test_token_helpers.py` — Unit tests

- **ACTION**: Create comprehensive tests for all 4 helper functions
- **IMPLEMENT**: Tests that can run without a live database. Focus on:
  1. **Token generation logic** (pure functions, no DB):
     - `_parse_token()` helper extraction (if we extract it)
     - Token string format validation
     - Hash computation verification
  2. **Result dataclass tests**:
     - `ApiTokenResult` construction and field access
     - `TokenVerification` construction and field access
     - `TokenSummary` construction and field access
     - Frozen immutability
  3. **verify_token error paths** (can test without DB):
     - Malformed token (no prefix) → InvalidTokenError
     - Malformed token (no separator) → InvalidTokenError
     - Token system not configured → TokenError
  4. **Configuration access**:
     - `ClerkState._token_config` is None by default → verify guard
     - After `set_token_config()` → verify config accessible
  5. **Token string format**:
     - Verify format matches `{prefix}{short_token}_{long_token}`
     - Verify short_token length corresponds to config
     - Verify long_token length corresponds to config
     - Verify SHA-256 hash computation is correct
  6. **Edge cases**:
     - Empty name
     - expires_in_days=0
     - Very long prefix
     - Token with prefix that contains underscores
- **MIRROR**: `tests/test_token_config.py:17-68` — class-based test structure with descriptive names
- **PATTERN**: Pure unit tests (no DB fixtures), same style as Phase 1 tests
- **VALIDATE**: `cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && uv run python -m pytest tests/test_token_helpers.py -v`

---

## Testing Strategy

### Unit Tests to Write

| Test File | Test Cases | Validates |
| --------- | ---------- | --------- |
| `tests/test_token_helpers.py` | Result dataclass construction, frozen, fields | Return types |
| `tests/test_token_helpers.py` | Token string format generation + parsing | Split-token pattern |
| `tests/test_token_helpers.py` | SHA-256 hash computation roundtrip | Crypto correctness |
| `tests/test_token_helpers.py` | verify_token error paths (no prefix, no separator, not configured) | Input validation |
| `tests/test_token_helpers.py` | Config guard (None check) | Safety |

### Edge Cases Checklist

- [ ] Token with prefix containing underscores (e.g., "my_app_")
- [ ] expires_in_days=0 (expires immediately)
- [ ] expires_in_days=None (no expiry)
- [ ] Verify token with wrong long_token (hash mismatch)
- [ ] Verify token with empty string
- [ ] Token string missing separator
- [ ] Token string with extra separators

---

## Validation Commands

### Level 1: STATIC_ANALYSIS

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && uv run ruff check custom_components/reflex_clerk_api/token_config.py custom_components/reflex_clerk_api/clerk_provider.py custom_components/reflex_clerk_api/__init__.py
```

**EXPECT**: Exit 0, no errors

### Level 2: UNIT_TESTS

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && uv run python -m pytest tests/ -v
```

**EXPECT**: All tests pass (26 existing + new tests)

### Level 3: IMPORT_VERIFICATION

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && uv run python -c "from custom_components.reflex_clerk_api import issue_token, verify_token, revoke_token, list_tokens, ApiTokenResult, TokenVerification, TokenSummary, get_user; print('All 8 new exports OK')"
```

**EXPECT**: "All 8 new exports OK"

---

## Acceptance Criteria

- [ ] `issue_token()` generates split-token, stores in DB, returns `ApiTokenResult` with full token
- [ ] `verify_token()` parses token, looks up by short_token, verifies hash, checks expiry/revocation, updates last_used_at
- [ ] `revoke_token()` soft-deletes token (is_active=False, revoked_at, reason), scoped to current user
- [ ] `list_tokens()` returns active tokens for current user as `TokenSummary` list (no secrets)
- [ ] All 4 functions follow `get_user()` pattern (where applicable)
- [ ] `verify_token()` is synchronous (no `current_state`) for FastAPI compatibility
- [ ] Result dataclasses are frozen
- [ ] Level 1-3 validation commands pass with exit 0
- [ ] Unit tests cover token format, hash computation, error paths
- [ ] No regressions in existing 26 tests

---

## Completion Checklist

- [ ] Task 1: Result dataclasses in token_config.py
- [ ] Task 2: issue_token() in clerk_provider.py
- [ ] Task 3: verify_token(), revoke_token(), list_tokens() in clerk_provider.py
- [ ] Task 4: Exports in __init__.py
- [ ] Task 5: Tests in test_token_helpers.py
- [ ] Level 1: Ruff lint passes
- [ ] Level 2: All tests pass
- [ ] Level 3: Import verification passes

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
| ---- | ---------- | ------ | ---------- |
| Token prefix containing `_` breaks parsing | MEDIUM | MEDIUM | Parse by stripping known prefix length, then split on first `_` |
| SQLAlchemy metadata collision (extend_existing) | LOW | LOW | Already handled in Phase 1 with `__table_args__` |
| Naive datetime comparison (DB may return naive) | MEDIUM | HIGH | Explicitly add `tzinfo=timezone.utc` if missing before comparison |
| `rx.session()` context not available in all contexts | LOW | HIGH | Follow established pattern — works in event handlers and module-level functions |

---

## Notes

- `verify_token()` is intentionally synchronous (not async) to be directly usable as a FastAPI dependency in Phase 4
- `get_user` is added to exports even though it existed before — it was in `clerk_provider.py` but not exported via `__init__.py`
- The `# noqa: E712` comment is needed for SQLAlchemy boolean comparisons (`== True`) because `is True` doesn't work with SQLAlchemy column expressions
- Token string format: `{prefix}{short_token}_{long_token}` — the prefix is stripped first, then the remainder is split on the first `_`
- `secrets.compare_digest()` is used for constant-time hash comparison to prevent timing attacks
