# Token Issuance & Passcode System for reflex-clerk-api

## Problem Statement

Developers building SaaS applications with Reflex+Clerk repeatedly implement the same token issuance boilerplate — generating API tokens tied to users, verifying tokens to resolve user identity, and issuing short-lived passcodes for channel authentication. There is no reusable, framework-native solution in the Reflex+Clerk ecosystem, forcing every project to hand-roll token systems from scratch.

## Evidence

- Assumption - needs validation: Every SaaS app with programmatic API access needs user-issued tokens (Stripe, GitHub, OpenAI all provide this)
- Clerk only provides session JWTs — no long-lived, user-issued API token mechanism in the Reflex wrapper
- The reflex-clerk-api package already handles auth state, JWT validation, and user management — token issuance is a natural extension of this surface area
- Cross-service authorization (e.g., authenticating a user across communication channels) is a recurring need with no framework-level answer

## Proposed Solution

Extend `reflex-clerk-api` with two complementary authentication primitives: **API tokens** (long-lived, configurable prefix + random code, stored hashed) and **passcodes** (short-lived 6-digit codes with configurable TTL). Both resolve to a Clerk user on verification. Tokens persist in Reflex's native database via `rx.Session`; passcodes are ephemeral with automatic expiry. The system follows the split-token pattern (industry standard) for API tokens and provides a simple passcode flow for situations where full tokens are burdensome. A metadata schema definition system allows consumers to define typed fields on user metadata.

## Key Hypothesis

We believe adding token issuance and passcode helpers to reflex-clerk-api will eliminate repetitive auth boilerplate for SaaS developers using Reflex+Clerk. We'll know we're right when developers can issue, verify, and revoke tokens tied to Clerk users in under 10 lines of configuration.

## What We're NOT Building

- **OAuth provider capabilities** — no third-party app authorization flows
- **Token scoping/permissions system** — consumers define their own scope semantics
- **UI components** — backend helpers and endpoints only in v1
- **Rate limiting** — consumers implement at their application layer
- **Analytics/tracking service integration** (e.g., PostHog) — out of scope for the package; consumers hook into token lifecycle events themselves
- **Admin dashboard** — no management UI

## Success Metrics

| Metric | Target | How Measured |
|--------|--------|--------------|
| Lines to add token auth to an app | < 10 lines of config | Code review of integration example |
| Token issue → verify round-trip | < 100ms (excluding network) | Benchmark test |
| Passcode issue → verify round-trip | < 50ms | Benchmark test |
| Test coverage on new code | > 90% | pytest-cov |
| Zero new runtime dependencies | 0 added to pyproject.toml | Dependency audit |

## Open Questions

- [ ] Does `clerk-backend-api` 2.0.x include `api_keys` module? If so, should we wrap it as an alternative backend?
- [ ] Should token revocation be soft-delete (`is_active=False`) or hard-delete? (Recommendation: soft-delete for audit trail)
- [ ] Maximum number of active tokens per user — should the framework enforce a limit or leave to consumers?
- [ ] Should passcode verification require user_id + passcode (two-factor style) or passcode-only with user resolution?
- [ ] How should the metadata schema system handle schema migrations when field definitions change?

---

## Users & Context

**Primary User**
- **Who**: Python developer building a SaaS application with Reflex and Clerk authentication
- **Current behavior**: Hand-rolls token generation, hashing, storage, and verification for every project; uses raw Clerk session JWTs where long-lived tokens are needed (insecure, wrong tool for the job)
- **Trigger**: Needs to give end-users programmatic API access, or needs cross-service user identification
- **Success state**: Adds `token_prefix="myapp_"` to `wrap_app()`, calls `issue_token()` / `verify_token()` — done

**Job to Be Done**
When building a SaaS app that needs user-issued authentication tokens or channel passcodes, I want to add token management to my Reflex+Clerk app with minimal configuration, so I can focus on business logic instead of reimplementing auth primitives.

**Non-Users**
- Developers needing full OAuth 2.0 provider capabilities (use Authlib or similar)
- Applications not using Clerk for user management
- Projects requiring token scoping/RBAC (this provides the token primitive, not the authorization layer)

---

## Solution Detail

### Core Capabilities (MoSCoW)

| Priority | Capability | Rationale |
|----------|------------|-----------|
| Must | **API Token Issuance** — generate tokens with configurable prefix + code length, tied to clerk user_id | Core value proposition |
| Must | **API Token Verification** — given a token string, resolve to user_id (or reject if invalid/expired/revoked) | Tokens are useless without verification |
| Must | **API Token Revocation** — soft-delete tokens (set `is_active=False`, record `revoked_at`) | Security fundamental |
| Must | **Passcode Issuance** — generate short-lived N-digit codes (default 6) with configurable TTL (default 10 min) tied to user | Cross-channel auth use case |
| Must | **Passcode Verification** — verify passcode + user identifier (e.g., name/email), resolve to user_id | Passcodes need user context for security |
| Must | **Database Models** — SQLModel tables for tokens and passcodes, using Reflex's native `rx.Session` | Persistent storage with zero external deps |
| Must | **Configuration** — prefix, code length, passcode length, passcode TTL as `wrap_app()` params or ClassVars | Configurable per-application |
| Should | **Token Listing** — list active tokens for a user (name, prefix+short_token, created_at, last_used_at, expires_at) | Users need to manage their tokens |
| Should | **ClerkUser Model Update** — add optional metadata fields (public/private) and `load_user()` extension | Framework should surface metadata |
| Should | **Metadata Schema Definition** — typed schema for user metadata fields, validated on read/write | Prevents metadata drift across services |
| Should | **User-Issued Link Tracking** — generate trackable short links tied to users, record click counts | Shareable profiles, referral links |
| Could | **Token Rotation** — issue new token and revoke old in one atomic operation | Convenience for key rolling |
| Could | **Bulk Revocation** — revoke all tokens for a user | Account compromise response |
| Could | **Passcode Rate Limiting Hooks** — callback on excessive passcode requests per user | Abuse prevention (consumer implements policy) |
| Won't | **OAuth provider flows** — out of scope, first-party only |
| Won't | **Token scoping/RBAC** — consumers define scope semantics |
| Won't | **UI components** — backend-only in v1 |
| Won't | **Analytics service integration** — consumers hook lifecycle events |

### MVP Scope

The minimum to validate the hypothesis:

1. **`ApiToken` SQLModel** — stored in Reflex DB via `rx.Session`
2. **`Passcode` SQLModel** — ephemeral, auto-expires
3. **`issue_token()`** — async helper following `get_user()` pattern
4. **`verify_token()`** — standalone (no state needed), returns user_id or raises
5. **`revoke_token()`** — async helper, soft-delete
6. **`issue_passcode()`** — async helper, generates N-digit code with TTL
7. **`verify_passcode()`** — standalone, checks code + user identifier, returns user_id or raises
8. **Configuration via `wrap_app()`** — `token_prefix`, `token_code_length`, `passcode_length`, `passcode_ttl_seconds`
9. **FastAPI middleware/dependency** — `validate_api_token` for protecting endpoints
10. **Exports in `__init__.py`**

### User Flow

**API Token Flow:**
```
Developer configures:
  clerk.wrap_app(app, ..., token_prefix="myapp_", token_code_length=12)

End-user requests token:
  token_record = await clerk.issue_token(self, name="My Integration", expires_in_days=90)
  # Returns: ApiTokenResult(full_token="myapp_a1b2c3d4_kF7xYz...", id=..., name=..., expires_at=...)
  # full_token shown ONCE to user

External service verifies:
  POST /api/verify  {token: "myapp_a1b2c3d4_kF7xYz..."}
  # OR via FastAPI dependency:
  @app.get("/protected", dependencies=[Depends(clerk.validate_api_token)])

  result = await clerk.verify_token("myapp_a1b2c3d4_kF7xYz...")
  # Returns: TokenVerification(user_id="user_abc123", token_id=..., name=...)
  # Raises: InvalidTokenError, ExpiredTokenError, RevokedTokenError
```

**Passcode Flow:**
```
User requests passcode:
  passcode = await clerk.issue_passcode(self, channel="sms")
  # Returns: PasscodeResult(code="847291", expires_at=..., user_id=...)
  # Code sent to user via consumer's channel (SMS, email, etc.)

Verifying service checks:
  result = await clerk.verify_passcode(code="847291", user_identifier="jane@example.com")
  # Returns: PasscodeVerification(user_id="user_abc123")
  # Raises: InvalidPasscodeError, ExpiredPasscodeError
  # Passcode is single-use — consumed on successful verification
```

---

## Technical Approach

**Feasibility**: HIGH

**Architecture Notes**

- **Split-token pattern** for API tokens: `{prefix}_{short_token}_{long_token}` where `short_token` is stored plaintext (indexed for O(1) lookup) and `long_token` is stored as SHA-256 hash. Full token shown only at creation time.
- **Database**: Reflex's native SQLModel + `rx.Session` (no external DB dependency). Two tables: `api_tokens`, `passcodes`.
- **Passcode generation**: `secrets.randbelow(10**n)` zero-padded to N digits. Stored as SHA-256 hash with user_id + expiry. Single-use (deleted on successful verification).
- **Passcode verification**: Requires user identifier (email, username, or user_id) + passcode. This prevents brute-force since attacker needs both pieces.
- **Configuration**: ClassVars on `ClerkState` set via `wrap_app()` or `set_token_config()` classmethod. Follows existing `_claims_options` pattern.
- **Helper functions**: Follow `get_user()` pattern — `async def`, accept `current_state: rx.State`, use `_get_state_within_handler()`.
- **Verification functions**: Stateless where possible — `verify_token()` and `verify_passcode()` only need DB access, not ClerkState.
- **No new runtime dependencies**: `secrets`, `hashlib`, `datetime` from stdlib. `authlib` already present if needed.
- **Constant-time comparison**: `secrets.compare_digest()` for hash verification (prevents timing attacks).

**Data Models**

```python
# api_tokens table
class ApiToken(rx.Model, table=True):
    __tablename__ = "clerk_api_tokens"

    id: str            # UUID primary key
    user_id: str       # Clerk user_id (indexed)
    name: str          # User-provided label
    prefix: str        # e.g., "myapp_live"
    short_token: str   # Plaintext, unique indexed (for lookup + display)
    long_token_hash: str  # SHA-256 hex digest
    is_active: bool    # Soft-delete flag
    expires_at: datetime | None  # NULL = no expiry
    last_used_at: datetime | None
    revoked_at: datetime | None
    revocation_reason: str | None
    created_at: datetime
    updated_at: datetime

# passcodes table
class Passcode(rx.Model, table=True):
    __tablename__ = "clerk_passcodes"

    id: str            # UUID primary key
    user_id: str       # Clerk user_id (indexed)
    code_hash: str     # SHA-256 of the passcode
    user_identifier: str  # Email/username used for verification
    channel: str       # "sms", "email", "cli", etc. (informational)
    expires_at: datetime  # Always set (TTL-based)
    is_used: bool      # Single-use flag
    created_at: datetime
```

**Technical Risks**

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Clerk SDK api_keys module not in v2.0.x | Medium | Custom split-token implementation is the primary path; Clerk native is optional future enhancement |
| Reflex `rx.Model` / `rx.Session` API changes | Low | Pin to `reflex>=0.8.0`, follow Reflex migration guides |
| Passcode brute-force (10^6 = 1M combinations for 6 digits) | Medium | Require user_identifier + code (two-factor), single-use, short TTL (10 min default), consumers add rate limiting |
| Token table grows unbounded | Low | Soft-delete with `is_active=False`; consumers can implement cleanup jobs. Document recommended maintenance. |
| DB migration conflicts with consumer tables | Low | Use `clerk_` table prefix to namespace |

---

## Implementation Phases

<!--
  STATUS: pending | in-progress | complete
  PARALLEL: phases that can run concurrently (e.g., "with 3" or "-")
  DEPENDS: phases that must complete first (e.g., "1, 2" or "-")
  PRP: link to generated plan file once created
-->

| # | Phase | Description | Status | Parallel | Depends | PRP Plan |
|---|-------|-------------|--------|----------|---------|----------|
| 1 | Database Models & Config | `ApiToken` + `Passcode` SQLModels, config ClassVars, `set_token_config()` | complete | - | - | [phase-1-database-models-config.plan.md](../plans/completed/phase-1-database-models-config.plan.md) |
| 2 | Token Lifecycle Helpers | `issue_token()`, `verify_token()`, `revoke_token()`, `list_tokens()` | complete | - | 1 | [phase-2-token-lifecycle-helpers.plan.md](../plans/completed/phase-2-token-lifecycle-helpers.plan.md) |
| 3 | Passcode Lifecycle Helpers | `issue_passcode()`, `verify_passcode()` | complete | with 2 | 1 | [phase-3-passcode-lifecycle-helpers.plan.md](../plans/completed/phase-3-passcode-lifecycle-helpers.plan.md) |
| 4 | FastAPI Integration | `validate_api_token` dependency, optional endpoint helpers | complete | - | 2, 3 | [phase-4-fastapi-integration.plan.md](../plans/completed/phase-4-fastapi-integration.plan.md) |
| 5 | ClerkUser & Metadata Schema | Metadata fields on ClerkUser, schema definition system | pending | with 4 | 1 | - |
| 6 | Link Tracking | Trackable short links tied to users, click counting | pending | - | 1, 2 | - |
| 7 | Testing & Demo | Unit tests, integration tests, demo app section | pending | - | 2, 3, 4 | - |
| 8 | Documentation | API docs, usage guide, migration notes | pending | - | 7 | - |

### Phase Details

**Phase 1: Database Models & Config**
- **Goal**: Establish the data layer and configuration surface
- **Scope**:
  - `ApiToken(rx.Model)` with all fields from technical approach
  - `Passcode(rx.Model)` with all fields
  - `TokenConfig` dataclass: `prefix`, `code_length`, `short_token_length`, `passcode_length`, `passcode_ttl_seconds`
  - ClassVars on ClerkState: `_token_config: ClassVar[TokenConfig]`
  - `set_token_config()` classmethod
  - `wrap_app()` accepts new config params, passes to `set_token_config()`
  - Custom exceptions: `InvalidTokenError`, `ExpiredTokenError`, `RevokedTokenError`, `InvalidPasscodeError`, `ExpiredPasscodeError`
- **Success signal**: Models create tables via Reflex migration; config flows from `wrap_app()` to ClerkState

**Phase 2: Token Lifecycle Helpers**
- **Goal**: Complete API token CRUD following existing helper patterns
- **Scope**:
  - `issue_token(current_state, name, expires_in_days=None) -> ApiTokenResult`
    - Generates `{prefix}_{short_token}_{long_token}` using `secrets`
    - Stores `short_token` plaintext + `SHA-256(long_token)` in DB
    - Returns `ApiTokenResult` with `full_token` (shown once), `id`, `name`, `expires_at`
  - `verify_token(token_string) -> TokenVerification`
    - Parses prefix, short_token, long_token from string
    - Looks up by `short_token` (indexed)
    - Verifies `SHA-256(long_token)` with `secrets.compare_digest()`
    - Checks `is_active`, `expires_at`
    - Updates `last_used_at`
    - Returns `TokenVerification(user_id, token_id, name)` or raises
  - `revoke_token(current_state, token_id, reason=None) -> None`
    - Sets `is_active=False`, `revoked_at=now()`, `revocation_reason`
  - `list_tokens(current_state) -> list[TokenSummary]`
    - Returns active tokens for current user (name, display_token, created_at, last_used_at, expires_at)
- **Success signal**: Round-trip test: issue → verify → revoke → verify-fails

**Phase 3: Passcode Lifecycle Helpers**
- **Goal**: Short-lived passcode generation and verification
- **Scope**:
  - `issue_passcode(current_state, channel="default") -> PasscodeResult`
    - Generates N-digit code (default 6) via `secrets.randbelow()`
    - Stores `SHA-256(code)` + `user_id` + `user_identifier` (email from ClerkState) + `expires_at`
    - Invalidates any existing unexpired passcodes for same user+channel
    - Returns `PasscodeResult(code, expires_at, user_id)`
  - `verify_passcode(code, user_identifier) -> PasscodeVerification`
    - Looks up by `user_identifier` + active + not expired
    - Verifies `SHA-256(code)` with `secrets.compare_digest()`
    - Marks `is_used=True` on success (single-use)
    - Returns `PasscodeVerification(user_id)` or raises
- **Success signal**: Round-trip test: issue → verify → re-verify-fails (single-use); issue → wait → verify-fails (expired)

**Phase 4: FastAPI Integration**
- **Goal**: Make token verification usable as a FastAPI dependency for protecting endpoints
- **Scope**:
  - `validate_api_token` — FastAPI `Depends()` compatible function
    - Reads `Authorization: Bearer <token>` header
    - Calls `verify_token()` internally
    - Returns `TokenVerification` or raises `HTTPException(401)`
  - `validate_passcode` — FastAPI `Depends()` for passcode-protected endpoints
  - Optional: `create_token_router()` factory that returns a FastAPI `APIRouter` with `/tokens/issue`, `/tokens/verify`, `/tokens/revoke` endpoints
- **Success signal**: FastAPI endpoint protected by `Depends(validate_api_token)` correctly authenticates requests

**Phase 5: ClerkUser & Metadata Schema**
- **Goal**: Surface user metadata and provide schema definition
- **Scope**:
  - Add to `ClerkUser`: `public_metadata: dict = {}`, `private_metadata: dict = {}` populated in `load_user()`
  - `MetadataSchema` class: define typed fields with defaults and validation
    ```python
    class MyUserMeta(clerk.MetadataSchema):
        role: str = "user"
        plan: str = "free"
        referral_code: str | None = None
    ```
  - `get_user_metadata(current_state, schema=MyUserMeta) -> MyUserMeta`
  - `update_user_metadata(current_state, schema_instance) -> None`
  - Validation on read (coerce to schema defaults for missing fields) and write (type checking)
- **Success signal**: Metadata round-trip: write structured metadata → read back as typed schema instance

**Phase 6: Link Tracking**
- **Goal**: User-issued trackable short links
- **Scope**:
  - `TrackedLink(rx.Model)`: `id`, `user_id`, `short_code`, `target_url`, `click_count`, `created_at`, `expires_at`, `is_active`
  - `create_tracked_link(current_state, target_url, expires_in_days=None) -> TrackedLinkResult`
  - `resolve_tracked_link(short_code) -> str` (returns target_url, increments click_count)
  - `list_tracked_links(current_state) -> list[TrackedLinkSummary]`
  - FastAPI route: `GET /l/{short_code}` → redirect to target_url with click tracking
- **Success signal**: Create link → visit short URL → click_count increments → redirect works

**Phase 7: Testing & Demo**
- **Goal**: Comprehensive test coverage and working demo
- **Scope**:
  - Unit tests for token generation, hashing, parsing, verification logic
  - Integration tests using `clerk_client` fixture: issue → verify → revoke lifecycle
  - Passcode tests: generation, single-use, expiry
  - Demo app section: token issuance card, passcode card (following existing `demo_card` pattern)
  - Benchmark tests for round-trip latency
- **Success signal**: > 90% coverage on new code; demo app demonstrates all features

**Phase 8: Documentation**
- **Goal**: Comprehensive docs for the new features
- **Scope**:
  - API reference (auto-generated via mkdocstrings)
  - Usage guide: configuration, token flow, passcode flow, FastAPI integration
  - Migration notes (for existing consumers upgrading)
  - Security notes: hashing approach, recommendations for rate limiting, passcode brute-force protection
- **Success signal**: New developer can add token auth by reading the guide alone

### Parallelism Notes

- **Phases 2 and 3** can run in parallel — token helpers and passcode helpers touch different models and have no code dependency beyond the shared config from Phase 1
- **Phases 4 and 5** can run in parallel — FastAPI integration and metadata schema touch different parts of the codebase (endpoint layer vs model layer)
- **Phase 6** depends on Phase 1 (models) and Phase 2 (follows same helper patterns) but is otherwise independent
- **Phase 7** must wait for Phases 2, 3, and 4 to be complete before integration tests can be written

---

## Decisions Log

| Decision | Choice | Alternatives | Rationale |
|----------|--------|--------------|-----------|
| Token storage | Reflex native DB (`rx.Session`) | Clerk user metadata, external DB, Redis | Metadata has 8KB limit; Reflex DB is zero-config and already available; no new infrastructure |
| Token format | Split-token: `{prefix}_{short}_{long}` | Single opaque token, JWT, Clerk native api_keys | Split-token enables O(1) indexed lookup + hash verification; industry standard (Stripe, GitHub pattern) |
| Hash algorithm | SHA-256 | bcrypt, Argon2id, SHA-512 | Split-token pattern makes brute-force infeasible (256-bit long_token); SHA-256 is fast for validation; no need for slow hash |
| Passcode verification | Requires user_identifier + code | Code-only | Two-piece verification reduces brute-force surface from 10^6 to (10^6 * user_count); standard for channel auth |
| Passcode storage | SHA-256 hash | Plaintext, encrypted | Hashing is sufficient; passcodes are ephemeral and single-use |
| Soft-delete for revocation | `is_active=False` + `revoked_at` | Hard delete | Audit trail; allows consumers to track revocation history |
| Config mechanism | ClassVar + `wrap_app()` params | Environment variables only, separate config file | Follows existing `_claims_options` pattern; composable with existing setup |
| Table namespace | `clerk_` prefix (`clerk_api_tokens`, `clerk_passcodes`) | No prefix, app-specific prefix | Prevents conflicts with consumer tables; clear ownership |
| Passcode default | 6 digits, 10 min TTL | 4 digits, 8 digits, longer/shorter TTL | 6 digits = 1M combinations; with user_identifier requirement and 10 min TTL, sufficient for channel auth |
| No new dependencies | stdlib only (secrets, hashlib) | Add argon2-cffi, add dedicated API key library | Keeps package lightweight; split-token + SHA-256 is cryptographically sound |

---

## Research Summary

**Market Context**
- Every major SaaS platform (Stripe, GitHub, OpenAI, Vercel, PostHog) uses prefixed API tokens with the split-token pattern
- Industry standard: show full token once at creation, store only hash, display prefix + short identifier in dashboards
- Clerk launched native API keys in public beta (Dec 2025) but with limited customization (no custom prefix, eventual paid feature)
- Short passcodes are standard for channel authentication (SMS OTP, CLI auth, cross-service handshake)

**Technical Context**
- `reflex-clerk-api` has all infrastructure needed: ClerkState singleton client, async helper pattern, `rx.Session` DB access
- Zero new dependencies required — `secrets` + `hashlib` from Python stdlib cover all cryptographic needs
- Existing patterns (`get_user()`, `update_user_phone_number()`) provide exact templates for new helpers
- FastAPI integration possible via `api_transformer` pattern for endpoint exposure
- Clerk user metadata is NOT suitable for token storage (8KB limit) — database is the correct approach

---

*Generated: 2026-02-26*
*Status: DRAFT - needs validation*
