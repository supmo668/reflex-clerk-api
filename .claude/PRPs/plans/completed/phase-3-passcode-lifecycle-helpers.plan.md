# Feature: Passcode Lifecycle Helpers

## Summary

Implement `issue_passcode()` and `verify_passcode()` functions plus two result dataclasses (`PasscodeResult`, `PasscodeVerification`) for short-lived numeric passcode authentication. Functions mirror the Phase 2 token lifecycle pattern — `issue_passcode` is async (needs `current_state` for user_id), `verify_passcode` is synchronous/stateless (for FastAPI dependency compatibility). Passcodes are single-use, expire after a configurable TTL (default 10 min), and require both a user identifier (email/phone) and the code for verification.

## User Story

As a Reflex+Clerk developer
I want to issue and verify short-lived numeric passcodes tied to Clerk users
So that I can authenticate users across channels (SMS, email, CLI) without full API tokens

## Problem Statement

Phase 1 created the `Passcode` model and Phase 2 established the helper function patterns. Developers still cannot issue or verify passcodes — the CRUD operations don't exist yet.

## Solution Statement

Two module-level functions in `clerk_provider.py`: `issue_passcode` (async, generates N-digit code, stores SHA-256 hash, invalidates prior passcodes for same user+channel) and `verify_passcode` (synchronous, looks up by user_identifier+channel, verifies hash, marks as used). Both use `rx.session()` for DB operations and stdlib `secrets`/`hashlib` for cryptography.

## Metadata

| Field            | Value                                          |
| ---------------- | ---------------------------------------------- |
| Type             | NEW_CAPABILITY                                 |
| Complexity       | LOW-MEDIUM                                     |
| Systems Affected | clerk_provider.py, token_config.py, __init__.py |
| Dependencies     | stdlib only (secrets, hashlib, datetime)        |
| Estimated Tasks  | 4                                              |

---

## UX Design

### Before State
```
Developer has:
  wrap_app(app, ..., token_prefix="myapp_", passcode_length=6, passcode_ttl_seconds=600)
  Passcode model exists in DB

But CANNOT:
  issue_passcode()   → function doesn't exist
  verify_passcode()  → function doesn't exist
```

### After State
```
Developer can:
  result = await clerk.issue_passcode(self, user_identifier="jane@example.com", channel="email")
  # → PasscodeResult(code="847291", expires_at=..., ...)

  verification = clerk.verify_passcode(code="847291", user_identifier="jane@example.com", channel="email")
  # → PasscodeVerification(user_id="user_abc", ...)

  # Single-use: second verify → InvalidPasscodeError
  # After TTL: verify → ExpiredPasscodeError
```

### Interaction Changes
| Location | Before | After | User Impact |
|----------|--------|-------|-------------|
| `clerk_provider.py` | No passcode helpers | 2 functions | Issue + verify passcodes |
| `token_config.py` | No passcode result types | + 2 dataclasses | Typed return values |
| `__init__.py` | No passcode exports | 4 new exports | Direct import access |

---

## Mandatory Reading

| Priority | File | Lines | Why Read This |
|----------|------|-------|---------------|
| P0 | `custom_components/reflex_clerk_api/clerk_provider.py` | 738-818 | `issue_token()` — EXACT pattern for `issue_passcode()` |
| P0 | `custom_components/reflex_clerk_api/clerk_provider.py` | 821-893 | `verify_token()` — EXACT pattern for `verify_passcode()` |
| P0 | `custom_components/reflex_clerk_api/token_models.py` | 91-131 | `Passcode` model fields |
| P0 | `custom_components/reflex_clerk_api/token_config.py` | 33-48, 65-82 | Passcode exceptions + config params |
| P1 | `custom_components/reflex_clerk_api/token_config.py` | 85-123 | Phase 2 result dataclasses to mirror |
| P2 | `tests/test_token_helpers.py` | all | Test patterns to follow |

---

## Patterns to Mirror

**ISSUE_PATTERN (from issue_token):**
```python
# SOURCE: clerk_provider.py:738-818
async def issue_token(current_state: rx.State, name: str, ...) -> ApiTokenResult:
    clerk_state = await _get_state_within_handler(current_state, ClerkState)
    user_id = clerk_state.user_id
    if user_id is None:
        raise MissingUserError("No user_id to issue token for")
    config = ClerkState._token_config
    if config is None:
        raise TokenError("Token issuance not configured...")
    # generate, hash, store, return result
```

**VERIFY_PATTERN (from verify_token):**
```python
# SOURCE: clerk_provider.py:821-893
def verify_token(token_string: str) -> TokenVerification:  # SYNCHRONOUS
    config = ClerkState._token_config
    if config is None:
        raise TokenError("Token issuance not configured.")
    # parse, lookup, check expiry, compare hash, update, return
```

**DB_INSERT_PATTERN:**
```python
# SOURCE: clerk_provider.py:802-805
with rx.session() as session:
    session.add(row)
    session.commit()
    session.refresh(row)
```

**DB_SELECT_AND_UPDATE_PATTERN:**
```python
# SOURCE: clerk_provider.py:861-887
with rx.session() as session:
    row = session.exec(select(Model).where(...)).first()
    if row is None:
        raise SomeError(...)
    row.field = new_value
    session.add(row)
    session.commit()
```

**FROZEN_DATACLASS_PATTERN:**
```python
# SOURCE: token_config.py:85-100
@dataclass(frozen=True)
class ApiTokenResult:
    id: str
    name: str
    ...
```

---

## Files to Change

| File | Action | Justification |
| ---- | ------ | ------------- |
| `custom_components/reflex_clerk_api/token_config.py` | UPDATE | Add `PasscodeResult` and `PasscodeVerification` dataclasses |
| `custom_components/reflex_clerk_api/clerk_provider.py` | UPDATE | Add `issue_passcode()` and `verify_passcode()` functions, import `Passcode` model |
| `custom_components/reflex_clerk_api/__init__.py` | UPDATE | Add 4 new exports |
| `tests/test_passcode_helpers.py` | CREATE | Unit tests for passcode lifecycle logic |

---

## NOT Building (Scope Limits)

- **Passcode listing** — passcodes are ephemeral/single-use, no list endpoint needed
- **Passcode revocation** — passcodes auto-expire and are single-use; no manual revoke
- **Rate limiting** — consumer responsibility (mentioned in PRD as "Could" priority)
- **Auto-fetching email from ClerkUser** — `user_identifier` is a required parameter; consumer decides what to pass
- **Sending passcodes** (SMS, email) — consumer sends via their channel; we just generate and verify

---

## Step-by-Step Tasks

### Task 1: UPDATE `token_config.py` — Add result dataclasses

- **ACTION**: Add `PasscodeResult` and `PasscodeVerification` frozen dataclasses after existing result types
- **IMPLEMENT**:
  ```python
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
  ```
- **MIRROR**: `token_config.py:85-123` — existing frozen dataclass pattern
- **GOTCHA**: `from __future__ import annotations` already present; `datetime` already imported
- **VALIDATE**: `uv run ruff check custom_components/reflex_clerk_api/token_config.py`

### Task 2: UPDATE `clerk_provider.py` — Add `issue_passcode()` and `verify_passcode()`

- **ACTION**: Add two functions after `list_tokens()` and before `register_on_auth_change_handler()`
- **IMPLEMENT**:

  **`issue_passcode()`:**
  ```python
  async def issue_passcode(
      current_state: rx.State,
      user_identifier: str,
      channel: str = "default",
  ) -> PasscodeResult:
      """Issue a short-lived numeric passcode for the currently logged-in user.

      Any existing unused passcodes for the same user and channel are
      automatically invalidated before the new one is created.

      Args:
          current_state: The ``self`` state from the current event handler.
          user_identifier: Email, phone, or other identifier used for verification.
          channel: Communication channel tag (e.g., ``"email"``, ``"sms"``).

      Returns:
          PasscodeResult with the plaintext code (send to user once).

      Raises:
          MissingUserError: If no user is logged in.
          PasscodeError: If the token system is not configured.
      """
      clerk_state = await _get_state_within_handler(current_state, ClerkState)
      user_id = clerk_state.user_id
      if user_id is None:
          raise MissingUserError("No user_id to issue passcode for")

      config = ClerkState._token_config
      if config is None:
          raise PasscodeError(
              "Passcode issuance not configured. Call wrap_app() with token_prefix."
          )

      # Generate N-digit numeric passcode
      code = "".join(
          str(secrets.randbelow(10)) for _ in range(config.passcode_length)
      )
      code_hash = hashlib.sha256(code.encode()).hexdigest()

      now = datetime.now(timezone.utc)
      expires_at = now + timedelta(seconds=config.passcode_ttl_seconds)

      with rx.session() as session:
          # Invalidate existing unused passcodes for same user+channel
          old_passcodes = session.exec(
              select(Passcode).where(
                  Passcode.user_id == user_id,
                  Passcode.channel == channel,
                  Passcode.is_used == False,  # noqa: E712
              )
          ).all()
          for old in old_passcodes:
              old.is_used = True
              session.add(old)

          # Create new passcode
          passcode_row = Passcode(
              user_id=user_id,
              code_hash=code_hash,
              user_identifier=user_identifier,
              channel=channel,
              expires_at=expires_at,
          )
          session.add(passcode_row)
          session.commit()
          session.refresh(passcode_row)

      return PasscodeResult(
          id=passcode_row.id,
          code=code,
          user_identifier=user_identifier,
          channel=channel,
          expires_at=expires_at,
          created_at=passcode_row.created_at,
      )
  ```

  **`verify_passcode()`:**
  ```python
  def verify_passcode(
      code: str,
      user_identifier: str,
      channel: str = "default",
  ) -> PasscodeVerification:
      """Verify a passcode and mark it as used (single-use).

      This function is synchronous and stateless. Suitable for FastAPI dependencies.

      Args:
          code: The passcode digits provided by the user.
          user_identifier: The email/phone/identifier used when the passcode was issued.
          channel: The channel the passcode was issued for.

      Returns:
          PasscodeVerification with user_id and metadata.

      Raises:
          InvalidPasscodeError: Passcode not found, already used, or hash mismatch.
          ExpiredPasscodeError: Passcode has expired.
          PasscodeError: Passcode system not configured.
      """
      config = ClerkState._token_config
      if config is None:
          raise PasscodeError("Passcode system not configured.")

      code_hash = hashlib.sha256(code.encode()).hexdigest()

      with rx.session() as session:
          passcode_row = session.exec(
              select(Passcode).where(
                  Passcode.user_identifier == user_identifier,
                  Passcode.channel == channel,
                  Passcode.is_used == False,  # noqa: E712
              )
          ).first()

          if passcode_row is None:
              raise InvalidPasscodeError("No valid passcode found")

          # Check expiration
          now = datetime.now(timezone.utc)
          expires_at = passcode_row.expires_at
          if expires_at.tzinfo is None:
              expires_at = expires_at.replace(tzinfo=timezone.utc)
          if now > expires_at:
              raise ExpiredPasscodeError("Passcode has expired")

          # Verify hash (constant-time comparison)
          if not secrets.compare_digest(passcode_row.code_hash, code_hash):
              raise InvalidPasscodeError("Passcode verification failed")

          # Mark as used (single-use)
          passcode_row.is_used = True
          session.add(passcode_row)
          session.commit()

          return PasscodeVerification(
              user_id=passcode_row.user_id,
              passcode_id=passcode_row.id,
              user_identifier=passcode_row.user_identifier,
              channel=passcode_row.channel,
          )
  ```
- **MIRROR**: `clerk_provider.py:738-818` (issue_token), `clerk_provider.py:821-893` (verify_token)
- **IMPORTS**: Add to existing token_config import block: `PasscodeError`, `PasscodeResult`, `PasscodeVerification`, `ExpiredPasscodeError`, `InvalidPasscodeError`. Add `Passcode` to the token_models import (alongside `ApiToken`).
- **GOTCHA**: `secrets`, `hashlib`, `select`, `datetime`/`timedelta`/`timezone` all already imported from Phase 2. `# noqa: E712` needed for `== False` SQLAlchemy comparisons. `verify_passcode` is synchronous (not async) for FastAPI compatibility.
- **VALIDATE**: `uv run ruff check custom_components/reflex_clerk_api/clerk_provider.py`

### Task 3: UPDATE `__init__.py` — Add exports

- **ACTION**: Add 4 new symbols to imports and `__all__`
- **IMPLEMENT**:
  - Add to `from .clerk_provider import (...)`: `issue_passcode`, `verify_passcode`
  - Add to `from .token_config import (...)`: `PasscodeResult`, `PasscodeVerification`
  - Add to `__all__`: `"PasscodeResult"`, `"PasscodeVerification"`, `"issue_passcode"`, `"verify_passcode"` (alphabetically sorted)
- **MIRROR**: `__init__.py:4-16` and `__init__.py:22-40`
- **VALIDATE**: `uv run ruff check custom_components/reflex_clerk_api/__init__.py && uv run python -c "from custom_components.reflex_clerk_api import issue_passcode, verify_passcode, PasscodeResult, PasscodeVerification; print('All 4 new exports OK')"`

### Task 4: CREATE `tests/test_passcode_helpers.py` — Unit tests

- **ACTION**: Create tests mirroring `test_token_helpers.py` structure
- **IMPLEMENT**:
  1. **PasscodeResult dataclass tests**: construction, frozen immutability, field access
  2. **PasscodeVerification dataclass tests**: construction, frozen immutability
  3. **Passcode generation format tests**:
     - 6-digit code format (all digits, correct length)
     - Leading zeros preserved (e.g., "007421")
     - Different codes generate different hashes
     - SHA-256 hash is 64 hex chars
     - `secrets.compare_digest` roundtrip
  4. **Verify error path tests** (no DB needed):
     - Config not set → PasscodeError
     - Exception hierarchy (InvalidPasscodeError ⊂ PasscodeError, etc.)
  5. **Config access tests**:
     - `passcode_length` default is 6
     - `passcode_ttl_seconds` default is 600
     - Generation with custom config
- **MIRROR**: `tests/test_token_helpers.py` — class-based test structure
- **VALIDATE**: `uv run python -m pytest tests/test_passcode_helpers.py -v`

---

## Testing Strategy

### Unit Tests to Write

| Test File | Test Cases | Validates |
| --------- | ---------- | --------- |
| `tests/test_passcode_helpers.py` | PasscodeResult construction, frozen, fields | Return types |
| `tests/test_passcode_helpers.py` | PasscodeVerification construction, frozen | Return types |
| `tests/test_passcode_helpers.py` | 6-digit generation, leading zeros, hash roundtrip | Crypto correctness |
| `tests/test_passcode_helpers.py` | Error paths: config not set, exception hierarchy | Input validation |
| `tests/test_passcode_helpers.py` | Config defaults, custom passcode_length/ttl | Configuration |

### Edge Cases Checklist

- [ ] Passcode with leading zeros (e.g., "001234")
- [ ] Passcode with all same digits (e.g., "000000")
- [ ] Custom passcode_length (4, 8, 10 digits)
- [ ] Empty code string
- [ ] Empty user_identifier
- [ ] Hash comparison with wrong code

---

## Validation Commands

### Level 1: STATIC_ANALYSIS

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && uv run ruff check custom_components/reflex_clerk_api/token_config.py custom_components/reflex_clerk_api/clerk_provider.py custom_components/reflex_clerk_api/__init__.py tests/test_passcode_helpers.py
```

### Level 2: UNIT_TESTS

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && uv run python -m pytest tests/ -v --ignore=tests/test_demo.py
```

### Level 3: IMPORT_VERIFICATION

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && uv run python -c "from custom_components.reflex_clerk_api import issue_passcode, verify_passcode, PasscodeResult, PasscodeVerification; print('All 4 new exports OK')"
```

---

## Acceptance Criteria

- [ ] `issue_passcode()` generates N-digit code, stores SHA-256 hash, invalidates prior passcodes for same user+channel, returns `PasscodeResult`
- [ ] `verify_passcode()` looks up by user_identifier+channel, checks expiry, verifies hash with `compare_digest`, marks as used, returns `PasscodeVerification`
- [ ] `verify_passcode()` is synchronous (no `current_state`) for FastAPI compatibility
- [ ] Result dataclasses are frozen
- [ ] Level 1-3 validation commands pass
- [ ] No regressions in existing 51 tests (26 Phase 1 + 25 Phase 2)

---

## Completion Checklist

- [ ] Task 1: Result dataclasses in token_config.py
- [ ] Task 2: issue_passcode() + verify_passcode() in clerk_provider.py
- [ ] Task 3: Exports in __init__.py
- [ ] Task 4: Tests in test_passcode_helpers.py
- [ ] Level 1: Ruff lint passes
- [ ] Level 2: All tests pass
- [ ] Level 3: Import verification passes

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
| ---- | ---------- | ------ | ---------- |
| Naive datetime comparison | MEDIUM | HIGH | Add `tzinfo=timezone.utc` if missing, same as verify_token() |
| Multiple unused passcodes for same user+channel | LOW | LOW | issue_passcode invalidates old ones; verify uses `.first()` |
| Brute-force (10^6 combinations for 6 digits) | MEDIUM | MEDIUM | Two-piece verification (user_identifier + code), single-use, short TTL |

---

## Notes

- `verify_passcode()` is intentionally synchronous for FastAPI `Depends()` compatibility in Phase 4
- `user_identifier` is a required parameter (not auto-fetched from ClerkUser) because passcode verification is often stateless (API endpoint context)
- The invalidation of old passcodes (mark `is_used=True`) happens in the same DB session as creating the new one for atomicity
- Passcode generation uses `secrets.randbelow(10)` per digit, which preserves leading zeros (e.g., "007421")
- Unlike tokens, passcodes don't need a split-token pattern — they're short enough that the full code is the secret
