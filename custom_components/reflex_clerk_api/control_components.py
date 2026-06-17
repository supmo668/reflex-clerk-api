import reflex as rx

from reflex_clerk_api.base import ClerkBase

Javascript = str
JSX = str
SignInInitialValues = dict[str, str]
SignUpInitialValues = dict[str, str]


class ClerkLoaded(ClerkBase):
    """Only renders children after authentication has been checked."""

    tag = "ClerkLoaded"


class ClerkLoading(ClerkBase):
    """Only renders childen while Clerk authenticates the user."""

    tag = "ClerkLoading"


class Protect(ClerkBase):
    tag = "Protect"

    condition: Javascript | None = None
    "Optional conditional logic that renders the children if it returns true"
    fallback: JSX | None = None
    "An optional snippet of JSX to show when a user doesn't have the role or permission to access the protected content."
    permission: str | None = None
    "Optional string corresponding to a Role's Permission in the format org:<resource>:<action>"
    role: str | None = None
    "Optional string corresponding to an Organization's Role in the format org:<role>"


class RedirectToSignIn(ClerkBase):
    """Immediately redirects the user to the sign in page when rendered."""

    tag = "RedirectToSignIn"

    sign_in_fallback_redirect_url: str | None = None
    "The fallback URL to redirect to after the user signs in, if there's no redirect_url in the path already. Defaults to /."
    sign_in_force_redirect_url: str | None = None
    "If provided, this URL will always be redirected to after the user signs in."
    initial_values: SignInInitialValues | None = None
    "The values used to prefill the sign-in fields with."


class RedirectToSignUp(ClerkBase):
    """Immediately redirects the user to the sign up page when rendered."""

    tag = "RedirectToSignUp"

    sign_up_fallback_redirect_url: str | None = None
    "The fallback URL to redirect to after the user signs up, if there's no redirect_url in the path already. Defaults to /."
    sign_up_force_redirect_url: str | None = None
    "If provided, this URL will always be redirected to after the user signs up."
    initial_values: SignUpInitialValues | None = None
    "The values used to prefill the sign-up fields with."


class RedirectToUserProfile(ClerkBase):
    """Immediately redirects the user to their profile page when rendered."""

    tag = "RedirectToUserProfile"


class RedirectToOrganizationProfile(ClerkBase):
    tag = "RedirectToOrganizationProfile"


class RedirectToCreateOrganization(ClerkBase):
    tag = "RedirectToCreateOrganization"


class SignedIn(ClerkBase):
    """Only renders children when the user is signed in."""

    tag = "SignedIn"


class SignedOut(ClerkBase):
    """Only renders children when the user is signed out."""

    tag = "SignedOut"


clerk_loaded = ClerkLoaded.create
clerk_loading = ClerkLoading.create
protect = Protect.create
redirect_to_sign_in = RedirectToSignIn.create
redirect_to_sign_up = RedirectToSignUp.create
redirect_to_user_profile = RedirectToUserProfile.create
redirect_to_organization_profile = RedirectToOrganizationProfile.create
redirect_to_create_organization = RedirectToCreateOrganization.create
signed_in = SignedIn.create
signed_out = SignedOut.create


def _neutral_skeleton() -> rx.Component:
    return rx.box(rx.spinner(), width="100%", min_height="2rem")


def auth_gate(
    *children: rx.Component,
    fallback: rx.Component | None = None,
    redirect: bool = True,
) -> rx.Component:
    """SSR-safe, fail-closed auth gate composed over Clerk control components.

    - clerk_loading OR signed_out  → render `fallback` (skeleton).
    - clerk_loaded ∧ signed_in     → render `children` (only path that shows protected content).
    - clerk_loaded ∧ signed_out ∧ redirect → fire exactly one redirect_to_sign_in.
    - Unresolved/default (SSR/hydration) → fallback, never children.
    """
    fb = fallback if fallback is not None else _neutral_skeleton()
    return rx.fragment(
        clerk_loading(fb),
        clerk_loaded(
            signed_in(*children),
            signed_out(
                fb,
                redirect_to_sign_in() if redirect else rx.fragment(),
            ),
        ),
    )
