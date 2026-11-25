"""The generated ``ClerkSessionSynchronizer`` code re-runs when the user id changes."""

import re

from custom_components.reflex_clerk_api.clerk_provider import (
    ClerkSessionSynchronizer,
    ClerkState,
)


def _code() -> str:
    (code,) = ClerkSessionSynchronizer.create().add_custom_code()
    return code


def test_user_id_is_read_from_use_auth() -> None:
    match = re.search(r"const \{([^}]*)\} = useAuth\(\)", _code())
    assert match is not None
    names = {name.strip() for name in match.group(1).split(",")}
    assert names == {"getToken", "isLoaded", "isSignedIn", "userId"}


def test_the_effect_depends_on_is_signed_in_and_user_id() -> None:
    match = re.search(r"\},\s*\[([^\]]*)\]\)", _code())
    assert match is not None
    deps = [name.strip() for name in match.group(1).split(",")]
    assert deps == ["isSignedIn", "userId"]


def test_the_effect_sends_the_same_two_events() -> None:
    code = _code()
    state = ClerkState.get_full_name()
    assert code.count(f'ReflexEvent("{state}.set_clerk_session", {{token}})') == 1
    assert code.count(f'ReflexEvent("{state}.clear_clerk_session")') == 1
    assert code.count("ReflexEvent(") == 2
