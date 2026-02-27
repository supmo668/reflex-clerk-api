# API Token & Passcode Integration

This guide covers the API token issuance system and FastAPI integration helpers provided by `reflex-clerk-api`.

## Overview

The token system lets your users create API tokens (similar to GitHub personal access tokens) that can authenticate requests to your backend API. The passcode system provides one-time verification codes for email/SMS-based authentication flows.

Both systems integrate with Clerk user management — tokens and passcodes are linked to Clerk user IDs.

## Quick Start — One-Line Registration

The fastest way to add auth verification endpoints to a Reflex app:

```python
import reflex as rx
import reflex_clerk_api as clerk

app = rx.App()
clerk.wrap_app(
    app,
    publishable_key=os.environ["CLERK_PUBLISHABLE_KEY"],
    secret_key=os.environ["CLERK_SECRET_KEY"],
    register_api=True,       # adds /auth/tokens/verify and /auth/passcodes/verify
    api_prefix="/auth",      # optional, default is "/auth"
)
```

This registers two POST endpoints on your app's `api_transformer`:

- `POST /auth/tokens/verify` — verify a Bearer token from the `Authorization` header
- `POST /auth/passcodes/verify` — verify a passcode from the JSON body

## Manual Registration

If you need more control, use `register_auth_api` directly:

```python
import reflex as rx
import reflex_clerk_api as clerk

app = rx.App()

# Register auth endpoints on the app's api_transformer
router = clerk.register_auth_api(app, prefix="/api/v1/auth")
```

This works with existing `api_transformer` instances — if your app already has a FastAPI instance set as `api_transformer`, routes are added to it. Otherwise, a new FastAPI instance is created.

```python
from fastapi import FastAPI

# Works with existing FastAPI instances
fastapi_app = FastAPI()
fastapi_app.include_router(my_other_router)
app = rx.App(api_transformer=fastapi_app)
clerk.register_auth_api(app)  # adds to existing FastAPI instance
```

## Protecting Custom Endpoints

Use the `Depends()`-compatible dependency functions to protect your own endpoints:

### Token-Based Protection

```python
from fastapi import APIRouter, Depends
import reflex_clerk_api as clerk

router = APIRouter()

@router.get("/protected")
def my_endpoint(
    auth: clerk.TokenVerification = Depends(clerk.validate_api_token),
):
    """Only accessible with a valid API token."""
    return {
        "message": f"Hello, user {auth.user_id}",
        "token_id": auth.token_id,
        "token_name": auth.name,
    }
```

The client sends the token as a Bearer token:

```bash
curl -X GET https://yourapp.com/protected \
  -H "Authorization: Bearer myapp_abc123def456_longsecretpart"
```

### Passcode-Based Protection

```python
@router.post("/verify-code")
def verify_code(
    verification: clerk.PasscodeVerification = Depends(clerk.validate_passcode),
):
    """Verify a one-time passcode."""
    return {
        "user_id": verification.user_id,
        "channel": verification.channel,
    }
```

The client sends the passcode in the JSON body:

```json
{
    "code": "847291",
    "user_identifier": "jane@example.com",
    "channel": "email"
}
```

## Creating a Standalone Router

If you want to create the router without attaching it to a Reflex app:

```python
from fastapi import FastAPI
import reflex_clerk_api as clerk

router = clerk.create_token_router(prefix="/auth", tags=["auth"])

# Use with any FastAPI app
app = FastAPI()
app.include_router(router)
```

## Token Lifecycle

### Issuing Tokens

Tokens are issued from Reflex event handlers using `clerk.issue_token`:

```python
import reflex as rx
import reflex_clerk_api as clerk

class ApiKeyState(rx.State):
    @rx.event
    async def create_api_key(self):
        clerk_state = await self.get_state(clerk.ClerkState)

        result: clerk.ApiTokenResult = clerk.issue_token(
            user_id=clerk_state.user_id,
            name="My API Key",
            expires_in_days=90,  # optional, None = never expires
        )

        # result.full_token is the ONLY time the full token is available
        # Store/display it to the user now — it cannot be retrieved later
        self.new_token = result.full_token
```

!!! warning

    The `full_token` in the `ApiTokenResult` is the only time the complete token string is available. After creation, only the short token prefix is stored in plaintext. The long token part is stored as a SHA-256 hash.

### Token Format

Tokens follow the format: `{prefix}{short_token}_{long_token}`

- **prefix**: Configurable (default `"myapp_"`), identifies your application
- **short_token**: Hex string used for database lookup (stored in plaintext)
- **long_token**: URL-safe random string, stored as SHA-256 hash

Example: `myapp_abc123def456_xY9kLmNpQrStUvWxAbCdEfGh...`

### Listing Tokens

```python
tokens: list[clerk.TokenSummary] = clerk.list_tokens(user_id=user_id)
for token in tokens:
    print(token.id, token.name, token.created_at, token.expires_at)
```

### Revoking Tokens

```python
clerk.revoke_token(token_id=token_id, user_id=user_id)
```

## Passcode Lifecycle

### Issuing Passcodes

```python
result: clerk.PasscodeResult = clerk.issue_passcode(
    user_id=user_id,
    user_identifier="jane@example.com",
    channel="email",
)
# result.code contains the plaintext passcode — send it to the user
# result.expires_at indicates when the passcode expires
```

### Verifying Passcodes

Passcodes are single-use. After successful verification, the passcode is marked as used and cannot be used again.

```python
verification: clerk.PasscodeVerification = clerk.verify_passcode(
    code="847291",
    user_identifier="jane@example.com",
    channel="email",
)
print(verification.user_id)  # The Clerk user who owns this passcode
```

## Configuration

Configure the token and passcode system via `TokenConfig`:

```python
clerk.wrap_app(
    app,
    publishable_key=...,
    secret_key=...,
    token_prefix="myapp_",      # prefix for issued tokens
    token_code_length=32,       # length of the long token part
    short_token_length=12,      # length of the short token (hex)
    passcode_length=6,          # number of digits in passcodes
    passcode_ttl_seconds=300,   # passcode expiry (5 minutes)
)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `token_prefix` | `"myapp_"` | Prefix prepended to all tokens |
| `token_code_length` | `32` | Length of the secret token part |
| `short_token_length` | `12` | Length of the short token (for lookup) |
| `passcode_length` | `6` | Number of digits in passcodes (4-10) |
| `passcode_ttl_seconds` | `300` | Passcode expiry in seconds (min 30) |

## Error Handling

All verification functions raise specific exceptions that map to HTTP 401:

| Exception | When Raised |
|-----------|-------------|
| `TokenError` | Token system not configured |
| `InvalidTokenError` | Token not found, wrong prefix, or hash mismatch |
| `ExpiredTokenError` | Token has expired |
| `RevokedTokenError` | Token has been revoked |
| `PasscodeError` | Passcode system not configured |
| `InvalidPasscodeError` | Passcode not found or hash mismatch |
| `ExpiredPasscodeError` | Passcode has expired |

The FastAPI helpers automatically convert these to `HTTPException(status_code=401)`.

## Database Requirements

Tokens and passcodes are stored in the database using SQLModel. The models (`ApiToken` and `Passcode`) require a PostgreSQL database configured with Reflex's `rx.session()`.

Make sure your app has database migrations applied for the `api_token` and `passcode` tables.
