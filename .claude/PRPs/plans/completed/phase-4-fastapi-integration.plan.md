# Feature: FastAPI Integration

## Summary

Create FastAPI `Depends()` compatible dependency functions (`validate_api_token`, `validate_passcode`) and a convenience router factory (`create_token_router`) that wrap the existing `verify_token()` and `verify_passcode()` functions. The dependencies extract credentials from HTTP headers/body, catch domain exceptions, and raise `HTTPException(401)`. All code lives in a new `fastapi_helpers.py` module to keep FastAPI imports separate from Reflex component code.

## User Story

As a Reflex+Clerk developer
I want to protect my FastAPI endpoints with `Depends(clerk.validate_api_token)`
So that I can secure API routes with token/passcode authentication without writing boilerplate

## Problem Statement

`verify_token()` and `verify_passcode()` exist and work, but developers must manually write header extraction, exception-to-HTTP mapping, and route setup for every FastAPI endpoint they want to protect.

## Solution Statement

A new `fastapi_helpers.py` module provides:
1. `validate_api_token` — extracts Bearer token from `Authorization` header, validates, returns `TokenVerification` or raises 401
2. `validate_passcode` — takes `PasscodeBody` from request JSON, validates, returns `PasscodeVerification` or raises 401
3. `PasscodeBody` — Pydantic model for passcode verification request body
4. `create_token_router()` — optional factory returning an `APIRouter` with `/tokens/verify` and `/passcodes/verify` endpoints

## Metadata

| Field            | Value                                             |
| ---------------- | ------------------------------------------------- |
| Type             | NEW_CAPABILITY                                    |
| Complexity       | LOW-MEDIUM                                        |
| Systems Affected | fastapi_helpers.py (new), __init__.py              |
| Dependencies     | fastapi (via reflex>=0.8.0), pydantic (via reflex) |
| Estimated Tasks  | 3                                                  |

---

## UX Design

### Before State
```
Developer has:
  verify_token(token_string) → TokenVerification
  verify_passcode(code, user_identifier, channel) → PasscodeVerification

Must manually write for EVERY protected endpoint:
  1. Import HTTPBearer, HTTPException
  2. Extract Authorization header
  3. Parse "Bearer " prefix
  4. Call verify_token()
  5. Catch TokenError/PasscodeError
  6. Raise HTTPException(401)
  → 15-20 lines of boilerplate per endpoint
```

### After State
```
Developer can:
  @router.get("/protected")
  def my_endpoint(auth: TokenVerification = Depends(clerk.validate_api_token)):
      print(auth.user_id)  # Done!

  @router.post("/verify-code")
  def verify(v: PasscodeVerification = Depends(clerk.validate_passcode)):
      print(v.user_id)  # Done!

  # OR use the pre-built router:
  router = clerk.create_token_router(prefix="/auth")
  fastapi_app.include_router(router)
  → 1-2 lines per endpoint
```

### Interaction Changes
| Location | Before | After | User Impact |
|----------|--------|-------|-------------|
| FastAPI routes | Manual header parsing + try/except | `Depends(validate_api_token)` | 1-line token auth |
| Passcode endpoints | Manual body parsing + try/except | `Depends(validate_passcode)` | 1-line passcode auth |
| Router setup | Write routes from scratch | `create_token_router()` | Pre-built verify endpoints |

---

## Mandatory Reading

**CRITICAL: Implementation agent MUST read these files before starting any task:**

| Priority | File | Lines | Why Read This |
|----------|------|-------|---------------|
| P0 | `custom_components/reflex_clerk_api/clerk_provider.py` | 826-898 | `verify_token()` signature, exceptions, return type |
| P0 | `custom_components/reflex_clerk_api/clerk_provider.py` | 1095-1168 | `verify_passcode()` signature, exceptions, return type |
| P0 | `custom_components/reflex_clerk_api/token_config.py` | 9-48 | Exception hierarchy (TokenError, PasscodeError subtypes) |
| P0 | `custom_components/reflex_clerk_api/token_config.py` | 103-149 | TokenVerification, PasscodeVerification dataclasses |
| P1 | `custom_components/reflex_clerk_api/__init__.py` | all | Current exports to extend |
| P2 | `tests/test_token_helpers.py` | 208-280 | Error path test pattern |
| P2 | `tests/test_passcode_helpers.py` | 175-220 | Error path test pattern |

---

## Patterns to Mirror

**EXCEPTION_MAPPING_PATTERN (new for FastAPI):**
```python
# This is the core pattern to implement:
# Catch domain exception → raise HTTPException(401)
try:
    result = verify_token(token_string)
    return result
except TokenError as e:
    raise HTTPException(status_code=401, detail=str(e)) from e
```

**ERROR_PATH_TEST_PATTERN (from test_token_helpers.py:213-280):**
```python
# SOURCE: tests/test_token_helpers.py:222-228
class TestVerifyTokenErrorPaths:
    def test_token_config_not_set_raises_error(self):
        config = None
        if config is None:
            with pytest.raises(TokenError, match="not configured"):
                raise TokenError("Token issuance not configured.")
```

**FROZEN_DATACLASS_PATTERN (from token_config.py:103-110):**
```python
# SOURCE: token_config.py:103-110
@dataclass(frozen=True)
class TokenVerification:
    """Returned when an API token is successfully verified."""
    user_id: str
    token_id: str
    name: str
```

---

## Files to Change

| File | Action | Justification |
| ---- | ------ | ------------- |
| `custom_components/reflex_clerk_api/fastapi_helpers.py` | CREATE | FastAPI dependencies, PasscodeBody model, router factory |
| `custom_components/reflex_clerk_api/__init__.py` | UPDATE | Add 4 new exports |
| `tests/test_fastapi_helpers.py` | CREATE | Unit tests for FastAPI integration |

---

## NOT Building (Scope Limits)

- **Token issuance endpoints** — `issue_token` requires `current_state` (async, Reflex event handler); not suitable for a generic FastAPI endpoint without session context
- **Token revocation endpoints** — Same reason as issuance; requires authenticated Reflex state
- **Passcode issuance endpoints** — Requires Reflex event handler context
- **Rate limiting middleware** — Consumer responsibility per PRD
- **Custom HTTP status codes per exception type** — All auth failures return 401; consumers can override if needed
- **OAuth2 password/client_credentials flows** — Out of scope per PRD
- **Async versions of validate functions** — `verify_token`/`verify_passcode` are sync; wrapping in async adds no value

---

## Step-by-Step Tasks

### Task 1: CREATE `fastapi_helpers.py` — FastAPI dependencies and router factory

- **ACTION**: Create new module with `validate_api_token`, `validate_passcode`, `PasscodeBody`, `create_token_router`
- **IMPLEMENT**:

  ```python
  """FastAPI integration helpers for token and passcode verification.

  Provides ``Depends()``-compatible dependency functions and an optional
  pre-built router for common verification endpoints.

  Usage::

      from reflex_clerk_api import validate_api_token, TokenVerification
      from fastapi import Depends

      @router.get("/protected")
      def my_endpoint(auth: TokenVerification = Depends(validate_api_token)):
          print(auth.user_id)
  """

  from __future__ import annotations

  from fastapi import APIRouter, Depends, HTTPException
  from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
  from pydantic import BaseModel

  from .clerk_provider import verify_passcode, verify_token
  from .token_config import (
      PasscodeError,
      PasscodeVerification,
      TokenError,
      TokenVerification,
  )

  _bearer_scheme = HTTPBearer()


  def validate_api_token(
      credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
  ) -> TokenVerification:
      """FastAPI dependency: validate an API token from the Authorization header.

      Extracts the Bearer token from the ``Authorization`` header and verifies it
      using ``verify_token()``.

      Args:
          credentials: Automatically injected by FastAPI from the Authorization header.

      Returns:
          TokenVerification with ``user_id``, ``token_id``, and ``name``.

      Raises:
          HTTPException: 401 if the token is invalid, expired, revoked, or missing.

      Examples:

      ```python
      @router.get("/protected")
      def my_endpoint(
          auth: TokenVerification = Depends(clerk.validate_api_token),
      ):
          return {"user_id": auth.user_id}
      ```
      """
      try:
          return verify_token(credentials.credentials)
      except TokenError as e:
          raise HTTPException(status_code=401, detail=str(e)) from e


  class PasscodeBody(BaseModel):
      """Request body for passcode verification.

      Used by ``validate_passcode`` to parse the incoming JSON body.
      """

      code: str
      user_identifier: str
      channel: str = "default"


  def validate_passcode(
      body: PasscodeBody,
  ) -> PasscodeVerification:
      """FastAPI dependency: validate a passcode from the request body.

      Parses ``code``, ``user_identifier``, and ``channel`` from the JSON body
      and verifies using ``verify_passcode()``.

      Args:
          body: Automatically parsed by FastAPI from the request JSON body.

      Returns:
          PasscodeVerification with ``user_id``, ``passcode_id``, ``user_identifier``, ``channel``.

      Raises:
          HTTPException: 401 if the passcode is invalid, expired, or not found.

      Examples:

      ```python
      @router.post("/verify-code")
      def verify_code(
          v: PasscodeVerification = Depends(clerk.validate_passcode),
      ):
          return {"user_id": v.user_id}
      ```
      """
      try:
          return verify_passcode(
              code=body.code,
              user_identifier=body.user_identifier,
              channel=body.channel,
          )
      except PasscodeError as e:
          raise HTTPException(status_code=401, detail=str(e)) from e


  def create_token_router(prefix: str = "/auth", tags: list[str] | None = None) -> APIRouter:
      """Create a FastAPI APIRouter with token and passcode verification endpoints.

      This is a convenience factory. Consumers can also use ``validate_api_token``
      and ``validate_passcode`` directly as dependencies on their own routes.

      Args:
          prefix: URL prefix for the router (default ``"/auth"``).
          tags: OpenAPI tags for the router (default ``["auth"]``).

      Returns:
          A FastAPI ``APIRouter`` with ``POST /tokens/verify`` and
          ``POST /passcodes/verify`` endpoints.

      Examples:

      ```python
      from reflex_clerk_api import create_token_router

      router = create_token_router(prefix="/auth")
      fastapi_app.include_router(router)
      # Endpoints: POST /auth/tokens/verify, POST /auth/passcodes/verify
      ```
      """
      if tags is None:
          tags = ["auth"]
      router = APIRouter(prefix=prefix, tags=tags)

      @router.post("/tokens/verify")
      def verify_token_endpoint(
          verification: TokenVerification = Depends(validate_api_token),
      ) -> dict:
          """Verify an API token from the Authorization: Bearer header."""
          return {
              "user_id": verification.user_id,
              "token_id": verification.token_id,
              "name": verification.name,
          }

      @router.post("/passcodes/verify")
      def verify_passcode_endpoint(
          verification: PasscodeVerification = Depends(validate_passcode),
      ) -> dict:
          """Verify a passcode from the request body."""
          return {
              "user_id": verification.user_id,
              "passcode_id": verification.passcode_id,
              "user_identifier": verification.user_identifier,
              "channel": verification.channel,
          }

      return router
  ```

- **IMPORTS**: `fastapi` (via reflex), `pydantic` (via reflex), internal verify functions and types
- **GOTCHA**: `HTTPBearer` auto_error defaults to `True` — will raise 403 if header is missing. This is the desired behavior (FastAPI returns 403 for missing credentials, our wrapper returns 401 for invalid ones). If we want consistent 401 for missing headers too, set `HTTPBearer(auto_error=False)` and handle None credentials manually. **Decision**: Use default `auto_error=True` — the 403/401 distinction is standard and meaningful (403 = no credentials at all, 401 = credentials provided but invalid).
- **VALIDATE**: `uv run ruff check custom_components/reflex_clerk_api/fastapi_helpers.py`

### Task 2: UPDATE `__init__.py` — Add exports

- **ACTION**: Add 4 new symbols to imports and `__all__`
- **IMPLEMENT**:
  - Add new import block: `from .fastapi_helpers import (PasscodeBody, create_token_router, validate_api_token, validate_passcode)`
  - Add to `__all__`: `"PasscodeBody"`, `"create_token_router"`, `"validate_api_token"`, `"validate_passcode"` (alphabetically sorted)
- **MIRROR**: `__init__.py:4-18` and `__init__.py:53-99` for import and `__all__` patterns
- **GOTCHA**: `__all__` must remain sorted (RUF022 rule). Use `ruff check --fix` if needed.
- **VALIDATE**: `uv run ruff check custom_components/reflex_clerk_api/__init__.py && uv run python -c "from custom_components.reflex_clerk_api import validate_api_token, validate_passcode, PasscodeBody, create_token_router; print('All 4 new exports OK')"`

### Task 3: CREATE `tests/test_fastapi_helpers.py` — Unit tests

- **ACTION**: Create tests for FastAPI integration functions
- **IMPLEMENT**:
  1. **PasscodeBody model tests**: construction, defaults, field access
  2. **validate_api_token tests** (mock `verify_token`):
     - Success: mock returns TokenVerification → function returns it
     - TokenError → HTTPException(401)
     - InvalidTokenError → HTTPException(401)
     - ExpiredTokenError → HTTPException(401)
     - RevokedTokenError → HTTPException(401)
  3. **validate_passcode tests** (mock `verify_passcode`):
     - Success: mock returns PasscodeVerification → function returns it
     - PasscodeError → HTTPException(401)
     - InvalidPasscodeError → HTTPException(401)
     - ExpiredPasscodeError → HTTPException(401)
  4. **PasscodeBody validation tests**:
     - Valid body with all fields
     - Valid body with default channel
     - Missing required fields
  5. **create_token_router tests**:
     - Returns APIRouter
     - Default prefix is "/auth"
     - Custom prefix works
     - Has expected routes
  6. **Integration tests with TestClient** (uses FastAPI TestClient, no DB — mocks verify functions):
     - GET /auth/tokens/verify with valid Bearer token (mocked) → 200
     - GET /auth/tokens/verify without header → 403 (HTTPBearer auto_error)
     - POST /auth/passcodes/verify with valid body (mocked) → 200
     - POST /auth/passcodes/verify with invalid body → 422

- **MIRROR**: `tests/test_token_helpers.py` and `tests/test_passcode_helpers.py` for class-based test structure
- **VALIDATE**: `uv run python -m pytest tests/test_fastapi_helpers.py -v`

---

## Testing Strategy

### Unit Tests to Write

| Test File | Test Cases | Validates |
| --------- | ---------- | --------- |
| `tests/test_fastapi_helpers.py` | PasscodeBody construction, defaults, validation | Pydantic model |
| `tests/test_fastapi_helpers.py` | validate_api_token success + 4 error paths | Token dependency |
| `tests/test_fastapi_helpers.py` | validate_passcode success + 3 error paths | Passcode dependency |
| `tests/test_fastapi_helpers.py` | create_token_router structure | Router factory |
| `tests/test_fastapi_helpers.py` | TestClient integration (mocked verify) | End-to-end HTTP |

### Edge Cases Checklist

- [ ] Missing Authorization header → 403 (HTTPBearer default)
- [ ] Empty Bearer token → verify_token raises → 401
- [ ] Invalid JSON body for passcode → 422 (Pydantic validation)
- [ ] Missing required fields in passcode body → 422
- [ ] TokenError base class caught (not just subtypes)
- [ ] PasscodeError base class caught (not just subtypes)
- [ ] HTTPException includes original error message as detail
- [ ] Exception chaining preserved (`from e`)

---

## Validation Commands

### Level 1: STATIC_ANALYSIS

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && uv run ruff check custom_components/reflex_clerk_api/fastapi_helpers.py custom_components/reflex_clerk_api/__init__.py tests/test_fastapi_helpers.py
```

### Level 2: UNIT_TESTS

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && uv run python -m pytest tests/ -v --ignore=tests/test_demo.py
```

### Level 3: IMPORT_VERIFICATION

```bash
cd /home/mo/projects/SyntropyHealth/apps/Syntropy-Journals/libs/reflex-clerk-api && uv run python -c "from custom_components.reflex_clerk_api import validate_api_token, validate_passcode, PasscodeBody, create_token_router; print('All 4 new exports OK')"
```

---

## Acceptance Criteria

- [ ] `validate_api_token` extracts Bearer token and calls `verify_token()`, catching all `TokenError` subtypes → 401
- [ ] `validate_passcode` parses JSON body via `PasscodeBody` and calls `verify_passcode()`, catching all `PasscodeError` subtypes → 401
- [ ] `PasscodeBody` is a Pydantic model with `code`, `user_identifier`, and `channel` (default "default")
- [ ] `create_token_router()` returns an `APIRouter` with POST `/tokens/verify` and POST `/passcodes/verify`
- [ ] All functions are synchronous (matching underlying verify functions)
- [ ] Level 1-3 validation commands pass
- [ ] No regressions in existing 81 tests

---

## Completion Checklist

- [ ] Task 1: fastapi_helpers.py created
- [ ] Task 2: Exports in __init__.py
- [ ] Task 3: Tests in test_fastapi_helpers.py
- [ ] Level 1: Ruff lint passes
- [ ] Level 2: All tests pass
- [ ] Level 3: Import verification passes

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
| ---- | ---------- | ------ | ---------- |
| HTTPBearer 403 vs 401 confusion | LOW | LOW | Document that 403 = missing header, 401 = invalid token; this is standard |
| FastAPI not available (unlikely — comes via reflex) | LOW | HIGH | reflex>=0.8.0 always includes FastAPI; add try/except import if needed |
| rx.session() not available in FastAPI route context | LOW | MEDIUM | Already proven to work — verify_token/verify_passcode use it successfully |
| Pydantic v1 vs v2 mismatch | LOW | LOW | Reflex>=0.8.0 uses Pydantic v2; PasscodeBody uses standard BaseModel |

---

## Notes

- `validate_api_token` and `validate_passcode` are thin wrappers — all business logic remains in `verify_token()` and `verify_passcode()`
- The `create_token_router()` factory returns pre-wired routes; consumers call `fastapi_app.include_router(router)` in their setup
- For the token verify endpoint, the router uses POST (not GET) because the token is in the Authorization header (no body), but POST is conventional for "verify" operations
- Exception chaining (`raise HTTPException(...) from e`) preserves the original traceback for debugging
