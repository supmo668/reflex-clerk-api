from reflex_clerk_api.base import ClerkBase


class SignIn(ClerkBase):
    tag = "SignIn"

    path: str | None = None
    "The path the SignIn component is mounted at when using path-based routing. Required when routing='path' (the default when path is set). Omit when routing='hash'."

    routing: str | None = None
    "Clerk routing strategy: 'path' (default when path is set), 'hash', or 'virtual'. Use 'hash' in frameworks without catch-all sub-routes for /sign-in/factor-one etc."

    fallback_redirect_url: str | None = None
    "The fallback URL to redirect to after the user signs in, if there's no redirect_url in the path already. Defaults to /."

    sign_up_fallback_redirect_url: str | None = None
    "The fallback URL to redirect to after the user signs up, if there's no redirect_url in the path already. Defaults to /."

    force_redirect_url: str | None = None
    "If provided, this URL will always be redirected to after the user signs in."

    sign_up_force_redirect_url: str | None = None
    "If provided, this URL will always be redirected to after the user signs up."


class SignUp(ClerkBase):
    tag = "SignUp"

    path: str | None = None
    "The path the SignUp component is mounted at when using path-based routing. Required when routing='path' (the default when path is set). Omit when routing='hash'."

    routing: str | None = None
    "Clerk routing strategy: 'path' (default when path is set), 'hash', or 'virtual'. Use 'hash' in frameworks without catch-all sub-routes for /sign-up/verify etc."

    fallback_redirect_url: str | None = None
    "The fallback URL to redirect to after the user signs up, if there's no redirect_url in the path already. Defaults to /."

    sign_in_fallback_redirect_url: str | None = None
    "The fallback URL to redirect to after the user signs in, if there's no redirect_url in the path already. Defaults to /."

    force_redirect_url: str | None = None
    "If provided, this URL will always be redirected to after the user signs up."

    sign_in_force_redirect_url: str | None = None
    "If provided, this URL will always be redirected to after the user signs in."


sign_in = SignIn.create
sign_up = SignUp.create
