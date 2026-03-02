"""Tests for ClerkUser metadata fields and update_user_metadata helper."""

import ast
import inspect
from pathlib import Path

from custom_components.reflex_clerk_api import ClerkUser, update_user_metadata


class TestClerkUserMetadataFields:
    """ClerkUser must expose metadata dict fields."""

    def test_has_public_metadata(self):
        assert "public_metadata" in ClerkUser.__annotations__

    def test_has_private_metadata(self):
        assert "private_metadata" in ClerkUser.__annotations__

    def test_has_unsafe_metadata(self):
        assert "unsafe_metadata" in ClerkUser.__annotations__

    def test_public_metadata_default_is_empty_dict(self):
        field = ClerkUser.__fields__["public_metadata"]
        # Reflex wraps mutable defaults with default_factory
        assert field.default_factory() == {}

    def test_private_metadata_default_is_empty_dict(self):
        field = ClerkUser.__fields__["private_metadata"]
        assert field.default_factory() == {}

    def test_unsafe_metadata_default_is_empty_dict(self):
        field = ClerkUser.__fields__["unsafe_metadata"]
        assert field.default_factory() == {}


class TestClerkUserUpdateMetadataMethod:
    """ClerkUser must have an update_metadata event handler."""

    def test_update_metadata_method_exists(self):
        assert hasattr(ClerkUser, "update_metadata")

    def test_update_metadata_is_event_handler(self):
        import reflex as rx

        handler = getattr(ClerkUser, "update_metadata")
        assert isinstance(handler, rx.EventHandler)


class TestUpdateUserMetadataHelper:
    """Standalone update_user_metadata helper must exist and be async."""

    def test_function_exists(self):
        assert callable(update_user_metadata)

    def test_function_is_async(self):
        assert inspect.iscoroutinefunction(update_user_metadata)

    def test_accepts_metadata_params(self):
        sig = inspect.signature(update_user_metadata)
        params = set(sig.parameters.keys())
        assert "current_state" in params
        assert "public_metadata" in params
        assert "private_metadata" in params
        assert "unsafe_metadata" in params


class TestLoadUserLoadsMetadata:
    """load_user must populate metadata fields (AST check)."""

    def test_load_user_sets_public_metadata(self):
        source = Path(
            "custom_components/reflex_clerk_api/clerk_provider.py"
        ).read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "load_user"
            ):
                body_src = ast.dump(ast.Module(body=node.body, type_ignores=[]))
                assert "public_metadata" in body_src
                assert "private_metadata" in body_src
                assert "unsafe_metadata" in body_src
                return
        raise AssertionError("load_user method not found")
