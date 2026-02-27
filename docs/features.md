# Features of Reflex Clerk API

This documentation outlines the key components and functionalities available in the package.

See the [Reference](full_docs/clerk_provider.md) for more detailed documentation. This is intended to be more of an overview.

## Reflex Synchronization

`reflex-clerk-api` ensures that the backend states are synchronized with the Clerk authentication happening in the frontend. The main backend states include:

- **ClerkState**: Manages the authentication state of the user. You'll mostly want the `is_signed_in` and `user_id` attributes. Access them from your own event handlers like so:

```python
@rx.event
async def some_handler(self):
    clerk_state = await self.get_state(clerk.ClerkState)
    user_id = clerk_state.user_id
    ...
```

- **ClerkUser**: Provides access to additional user information like `image_url` and `email`.

!!! note

    To enable the `ClerkUser` state, set `clerk_provider(..., register_user_state=True)` when wrapping your page.

    This is not enabled by default since you may want to get the information you need yourself.

    There is also a helper method for getting more user info.

## Helper methods

- **On Load Event Handling**: Use `clerk.on_load(<on_load_events>)` to ensure the `ClerkState` is updated before other `on_load` events. This ensures that `is_signed_in` will be accurate.

- **On Auth Change Handlers**: Register event handlers that are called on authentication changes (login/logout) using `clerk.register_on_auth_change_handler(<handler>)`.

- **Get User Info**: Use `await clerk.get_user(self)` within an event handler to get the full Clerk `User` model.

## Clerk Components

The components implementation largely follows that of the [Clerk react overview](https://clerk.com/docs/references/react/overview).

The components are dscribed here with their `CamelCase` names as they are in the clerk react. To use them in your app, use the `snake_case` versions e.g. `clerk.clerk_provider(...)`.

### ClerkProvider

The `ClerkProvider` component should wrap the contents of your app.
It is required for the clerk frontend components, and is set up in a way that ensures the reflex backend is synchronized.

!!! note

    This is additionally wrapped in a custom `ClerkSessionSynchronizer` component to facilitate the backend synchronization.

### Authentication Components

I.e., **SignIn** and **SignUp** Components to create customizable sign-in and sign-up forms.

### User Components

For displaying the currently signed in user's information via clerk components.

- **UserButton**: A google style avatar button that opens a dropdown with user info.

- **UserProfile**: Displays a user profile with additional information.

### Organization Components

These are only minimally implemented, and not tested. If you would like to use these, I will happily accept pull requests.

### Waitlist Component

This is only minimally implemented, and not tested. If you would like to use this, I will happily accept pull requests.

### Control Components

These determine what content is displayed based on the user's authentication state. Use them to wrap parts of your app that should only be displayed under certain circumstances.

- **ClerkLoaded**: Displays content once Clerk is fully loaded.

- **ClerkLoading**: Displays content while Clerk is loading.

- **Protect**: Protects specific content to ensure only authenticated users can access them.

- **RedirectToSignIn**: Redirects users to the sign-in page if they are not authenticated.

- **RedirectToSignUp**: Redirects users to the sign-up page if they are not authenticated.

- **RedirectToUserProfile**: Redirects users to their profile page.

- **RedirectToOrganizationProfile**: Redirects users to their organization profile page.

- **RedirectToCreateOrganization**: Redirects users to create an organization.

- **SignedIn** and **SignedOut**: Conditional rendering based on user authentication state.

### Unstyled Components

Wrap regular reflex components with these to add the Clerk functionality.

- **SignInButton**, **SignUpButton**, and **SignOutButton**: Button components to trigger sign-in and sign-out actions.

E.g. `clerk.sign_in_button(rx.button("Sign in"))`

- **SignInWithMetamaskButton**: Not yet implemented.

## API Token & Passcode System

Issue and verify API tokens and one-time passcodes linked to Clerk users. Includes FastAPI integration helpers for protecting endpoints.

- **Token Issuance**: Create API tokens with configurable prefix, expiry, and secure split-token storage
- **Passcode Issuance**: Generate one-time verification codes for email/SMS flows
- **FastAPI Helpers**: `Depends()`-compatible functions for token and passcode verification
- **One-Line Registration**: `clerk.register_auth_api(app)` adds verification endpoints to your Reflex app

See the full [API Integration Guide](api_integration.md) for usage details.

## Demos

To see these features in action, visit the [demo](https://reflex-clerk-api-demo.adventuresoftim.com).
