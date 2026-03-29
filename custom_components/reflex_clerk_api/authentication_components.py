from reflex_clerk_api.base import ClerkBase


class SignIn(ClerkBase):
    tag = "SignIn"

    path: str

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

    path: str

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
