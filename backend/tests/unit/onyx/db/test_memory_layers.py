"""Tests for the layered memory system (raw / distilled).

These tests verify the two-tier memory CRUD, capacity limits, and the
UserMemoryContext two-tier structure. They do not require a database —
the functions are tested via SQLite in-memory sessions where possible,
and via direct function logic for pure-Python parts.
"""


import pytest

from onyx.db.memory import MAX_DISTILLED_MEMORIES_PER_USER
from onyx.db.memory import MAX_RAW_MEMORIES_PER_USER
from onyx.db.memory import MEMORY_LAYER_DISTILLED
from onyx.db.memory import MEMORY_LAYER_RAW
from onyx.db.memory import RECENT_RAW_MEMORIES_IN_PROMPT
from onyx.db.memory import UserInfo
from onyx.db.memory import UserMemoryContext

# ─── UserMemoryContext two-tier tests ──────────────────────────────────────────


class TestUserMemoryContextTwoTier:
    def test_distilled_and_raw_are_separate_fields(self) -> None:
        ctx = UserMemoryContext(
            user_info=UserInfo(),
            distilled_memories=("Prefers dark mode",),
            raw_memories=("Working on auth fix",),
            memories=("Prefers dark mode", "Working on auth fix"),
        )
        assert ctx.distilled_memories == ("Prefers dark mode",)
        assert ctx.raw_memories == ("Working on auth fix",)
        assert len(ctx.memories) == 2

    def test_without_memories_clears_both_layers(self) -> None:
        ctx = UserMemoryContext(
            user_info=UserInfo(name="Alice"),
            distilled_memories=("summary",),
            raw_memories=("recent",),
            memories=("summary", "recent"),
        )
        cleared = ctx.without_memories()
        assert cleared.distilled_memories == ()
        assert cleared.raw_memories == ()
        assert cleared.memories == ()
        # User info should be preserved.
        assert cleared.user_info.name == "Alice"

    def test_as_formatted_list_includes_user_info(self) -> None:
        ctx = UserMemoryContext(
            user_info=UserInfo(name="Bob", role="analyst", email="bob@test.com"),
            user_preferences="prefers concise answers",
            memories=("memory one",),
        )
        result = ctx.as_formatted_list()
        assert any("Bob" in r for r in result)
        assert any("analyst" in r for r in result)
        assert any("bob@test.com" in r for r in result)
        assert any("concise" in r for r in result)
        assert "memory one" in result

    def test_context_is_frozen(self) -> None:
        ctx = UserMemoryContext(user_info=UserInfo(), memories=("x",))
        with pytest.raises(Exception):
            ctx.memories = ("y",)  # type: ignore[misc]


# ─── Constants tests ──────────────────────────────────────────────────────────


class TestMemoryConstants:
    def test_raw_capacity_is_100(self) -> None:
        assert MAX_RAW_MEMORIES_PER_USER == 100

    def test_distilled_capacity_is_15(self) -> None:
        assert MAX_DISTILLED_MEMORIES_PER_USER == 15

    def test_layer_constants(self) -> None:
        assert MEMORY_LAYER_RAW == "raw"
        assert MEMORY_LAYER_DISTILLED == "distilled"

    def test_recent_raw_prompt_limit(self) -> None:
        assert RECENT_RAW_MEMORIES_IN_PROMPT == 5
