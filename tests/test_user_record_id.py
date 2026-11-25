"""``ClerkUser.user_id`` is the id of the user the record was loaded for.

The handlers are driven through their underlying functions on a real state
tree, with a stand-in for the Clerk backend client.
"""

import asyncio
import sys
from types import SimpleNamespace
from typing import Any

import pytest
import reflex.state as rs

from custom_components.reflex_clerk_api.clerk_provider import (
    ClerkState,
    ClerkUser,
    MissingUserError,
    get_user,
)

# The package re-exports a function named ``clerk_provider``; take the module.
_module = sys.modules[ClerkState.__module__]


def _user(tag: str) -> SimpleNamespace:
    return SimpleNamespace(
        first_name=f"First-{tag}",
        last_name=f"Last-{tag}",
        username=f"name-{tag}",
        email_addresses=[SimpleNamespace(email_address=f"{tag}@example.test")],
        phone_numbers=[],
        has_image=False,
        image_url=f"{tag}.png",
        public_metadata={"tag": tag},
        private_metadata={"tag": tag},
        unsafe_metadata={},
    )


class _Tree:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.root = rs.State(_reflex_internal_init=True)  # type: ignore[call-arg]
        self.clerk: Any = self._sub(ClerkState)
        self.record: Any = self._sub(ClerkUser)
        self.fetched: list[str] = []
        self.during_fetch: Any = None
        self.found = True
        monkeypatch.setattr(
            ClerkState,
            "_client",
            SimpleNamespace(users=SimpleNamespace(get_async=self._get_async)),
        )

    def _sub(self, cls: type) -> Any:
        return self.root.get_substate(tuple(cls.get_full_name().split(".")))

    async def _get_async(self, user_id: str) -> SimpleNamespace | None:
        self.fetched.append(user_id)
        if self.during_fetch is not None:
            self.during_fetch()
        return _user(user_id) if self.found else None

    def sign_in(self, user_id: str | None) -> None:
        self.clerk.is_signed_in = user_id is not None
        self.clerk.user_id = user_id

    def load(self) -> None:
        asyncio.run(ClerkUser.load_user.fn(self.record))


@pytest.fixture
def tree(monkeypatch: pytest.MonkeyPatch) -> _Tree:
    return _Tree(monkeypatch)


def test_user_id_defaults_to_empty(tree: _Tree) -> None:
    assert tree.record.user_id == ""


def test_load_user_stores_the_user_id_the_record_was_loaded_for(tree: _Tree) -> None:
    tree.sign_in("user_1")
    tree.load()
    assert tree.fetched == ["user_1"]
    assert tree.record.user_id == "user_1"
    assert tree.record.email_address == "user_1@example.test"
    assert tree.record.public_metadata == {"tag": "user_1"}


def test_load_user_ignores_a_result_for_a_different_user(tree: _Tree) -> None:
    tree.sign_in("user_1")
    tree.during_fetch = lambda: tree.sign_in("user_2")
    tree.load()
    assert tree.fetched == ["user_1"]
    assert tree.record.user_id == ""
    assert tree.record.email_address == ""
    assert tree.record.first_name == ""
    assert tree.record.public_metadata == {}
    assert tree.record.private_metadata == {}


def test_load_user_replaces_a_record_when_the_user_changed_while_loading(
    tree: _Tree,
) -> None:
    tree.sign_in("user_1")
    tree.load()
    tree.sign_in("user_2")
    tree.during_fetch = lambda: tree.sign_in("user_3")
    tree.load()
    assert tree.record.user_id == ""
    assert tree.record.email_address == ""


def test_load_user_ignores_a_result_when_signed_out_while_loading(tree: _Tree) -> None:
    tree.sign_in("user_1")
    tree.during_fetch = lambda: tree.sign_in(None)
    tree.load()
    assert tree.record.user_id == ""
    assert tree.record.email_address == ""


@pytest.mark.parametrize("user_id", [None, ""])
def test_load_user_without_a_user_id_clears_the_record(
    tree: _Tree, user_id: str | None
) -> None:
    tree.sign_in("user_1")
    tree.load()
    tree.sign_in(user_id)
    tree.load()
    assert tree.fetched == ["user_1"]
    assert tree.record.user_id == ""
    assert tree.record.email_address == ""


def test_a_missing_user_clears_the_user_id(tree: _Tree) -> None:
    tree.sign_in("user_1")
    tree.load()
    tree.found = False
    tree.load()
    assert tree.record.user_id == ""
    assert tree.record.email_address == ""


def test_loading_again_for_the_same_user_keeps_the_user_id(tree: _Tree) -> None:
    tree.sign_in("user_1")
    tree.load()
    tree.load()
    assert tree.fetched == ["user_1", "user_1"]
    assert tree.record.user_id == "user_1"


def test_get_user_fetches_the_signed_in_user(tree: _Tree) -> None:
    tree.sign_in("user_1")
    user = asyncio.run(get_user(tree.record))
    assert tree.fetched == ["user_1"]
    assert user.email_addresses[0].email_address == "user_1@example.test"


def test_get_user_without_a_user_id_raises(tree: _Tree) -> None:
    with pytest.raises(MissingUserError):
        asyncio.run(get_user(tree.record))
    assert tree.fetched == []


def _update(tree: _Tree, monkeypatch: pytest.MonkeyPatch) -> None:
    async def updated(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(
            public_metadata={"new": True}, private_metadata={}, unsafe_metadata={}
        )

    monkeypatch.setattr(_module, "update_user_metadata", updated)
    asyncio.run(
        ClerkUser.update_metadata.fn(tree.record, public_metadata={"new": True})
    )


def test_update_metadata_updates_a_record_loaded_for_the_signed_in_user(
    tree: _Tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree.sign_in("user_1")
    tree.load()
    _update(tree, monkeypatch)
    assert tree.record.public_metadata == {"new": True}


def test_update_metadata_leaves_a_record_loaded_for_another_user_unchanged(
    tree: _Tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree.sign_in("user_1")
    tree.load()
    tree.sign_in("user_2")
    _update(tree, monkeypatch)
    assert tree.record.user_id == "user_1"
    assert tree.record.public_metadata == {"tag": "user_1"}
