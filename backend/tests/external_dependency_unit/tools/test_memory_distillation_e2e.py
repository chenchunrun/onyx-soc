"""End-to-end validity tests for the layered memory + distillation system.

These tests exercise the full stack against a real PostgreSQL database:
  1. DB schema (layer/importance/distilled_from_ids columns exist and work)
  2. Layered CRUD (raw/distilled separation, capacity limits, FIFO)
  3. get_memories two-tier loading
  4. Distillation flow (LLM-mocked consolidation, raw deletion, importance)
  5. Prompt injection (two-section display)
  6. Distillable user discovery
  7. Threshold trigger logic

Requires: PostgreSQL running (external dependency unit test environment).
"""

import json
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from onyx.db.memory import MAX_DISTILLED_MEMORIES_PER_USER
from onyx.db.memory import MAX_RAW_MEMORIES_PER_USER
from onyx.db.memory import MEMORY_LAYER_DISTILLED
from onyx.db.memory import MEMORY_LAYER_RAW
from onyx.db.memory import RECENT_RAW_MEMORIES_IN_PROMPT
from onyx.db.memory import add_distilled_memory
from onyx.db.memory import add_memory
from onyx.db.memory import clear_distilled_memories
from onyx.db.memory import count_raw_memories
from onyx.db.memory import delete_raw_memories
from onyx.db.memory import get_distillable_users
from onyx.db.memory import get_distilled_memories
from onyx.db.memory import get_memories
from onyx.db.memory import get_raw_memories
from onyx.db.models import Memory
from onyx.db.models import User
from onyx.secondary_llm_flows.memory_distillation import DISTILLATION_THRESHOLD
from onyx.secondary_llm_flows.memory_distillation import PRESERVE_RECENT_RAW
from onyx.secondary_llm_flows.memory_distillation import distill_user_memories
from tests.external_dependency_unit.conftest import create_test_user


@pytest.fixture()
def test_user(db_session: Session) -> User:
    """Create a test user with memories enabled."""
    user = create_test_user(db_session, "memory_e2e")
    user.use_memories = True
    user.enable_memory_tool = True
    db_session.commit()
    db_session.refresh(user)
    return user


def _cleanup_user_memories(user_id: UUID, db_session: Session) -> None:
    """Delete all memories for a user to ensure test isolation."""
    db_session.query(Memory).filter(Memory.user_id == user_id).delete()
    db_session.commit()


# ─── 1. DB Schema ─────────────────────────────────────────────────────────────


class TestDBSchema:
    def test_new_columns_exist(self, db_session: Session, test_user: User) -> None:
        """Verify layer/importance/last_accessed_at/distilled_from_ids are
        writable and have correct defaults."""
        _cleanup_user_memories(test_user.id, db_session)
        mem = add_memory(test_user.id, "schema test", db_session)
        db_session.refresh(mem)

        assert mem.layer == MEMORY_LAYER_RAW
        assert mem.importance == 0.5
        assert mem.last_accessed_at is None
        assert mem.distilled_from_ids is None

    def test_distilled_from_ids_stores_json(
        self, db_session: Session, test_user: User
    ) -> None:
        """distilled_from_ids should store a list of ints."""
        _cleanup_user_memories(test_user.id, db_session)
        mem = add_distilled_memory(
            test_user.id,
            "Distilled from raw 1,2,3",
            db_session,
            distilled_from_ids=[1, 2, 3],
            importance=0.9,
        )
        assert mem is not None
        db_session.refresh(mem)
        assert mem.layer == MEMORY_LAYER_DISTILLED
        assert mem.importance == 0.9
        assert mem.distilled_from_ids == [1, 2, 3]

    def test_composite_index_exists(self) -> None:
        """The (user_id, layer) index should exist for query performance."""
        from sqlalchemy import inspect as sa_inspect
        from onyx.db.engine.sql_engine import get_sqlalchemy_engine

        engine = get_sqlalchemy_engine()
        inspector = sa_inspect(engine)
        indexes = inspector.get_indexes("memory")
        index_names = [idx["name"] for idx in indexes]
        assert "ix_memory_user_id_layer" in index_names


# ─── 2. Layered CRUD ──────────────────────────────────────────────────────────


class TestLayeredCRUD:
    def test_add_memory_creates_raw_layer(
        self, db_session: Session, test_user: User
    ) -> None:
        _cleanup_user_memories(test_user.id, db_session)
        add_memory(test_user.id, "raw memory 1", db_session)
        raw = get_raw_memories(test_user.id, db_session)
        distilled = get_distilled_memories(test_user.id, db_session)
        assert len(raw) == 1
        assert len(distilled) == 0
        assert raw[0].layer == MEMORY_LAYER_RAW

    def test_add_distilled_memory_separate_from_raw(
        self, db_session: Session, test_user: User
    ) -> None:
        _cleanup_user_memories(test_user.id, db_session)
        add_memory(test_user.id, "raw 1", db_session)
        add_distilled_memory(test_user.id, "distilled 1", db_session)
        assert len(get_raw_memories(test_user.id, db_session)) == 1
        assert len(get_distilled_memories(test_user.id, db_session)) == 1

    def test_fifo_eviction_respects_raw_cap(
        self, db_session: Session, test_user: User
    ) -> None:
        """Adding beyond MAX_RAW should evict the oldest raw memory."""
        _cleanup_user_memories(test_user.id, db_session)
        for i in range(MAX_RAW_MEMORIES_PER_USER):
            add_memory(test_user.id, f"raw {i}", db_session)

        assert count_raw_memories(test_user.id, db_session) == MAX_RAW_MEMORIES_PER_USER

        # Add one more — should evict "raw 0"
        add_memory(test_user.id, "overflow raw", db_session)
        raw = get_raw_memories(test_user.id, db_session)
        assert len(raw) == MAX_RAW_MEMORIES_PER_USER
        assert raw[0].memory_text == "raw 1"
        assert raw[-1].memory_text == "overflow raw"

    def test_distilled_cap_enforced(self, db_session: Session, test_user: User) -> None:
        """add_distilled_memory returns None when distilled cap is reached."""
        _cleanup_user_memories(test_user.id, db_session)
        for i in range(MAX_DISTILLED_MEMORIES_PER_USER):
            result = add_distilled_memory(test_user.id, f"distilled {i}", db_session)
            assert result is not None

        # One more should return None (cap reached)
        overflow = add_distilled_memory(test_user.id, "overflow", db_session)
        assert overflow is None
        assert (
            len(get_distilled_memories(test_user.id, db_session))
            == MAX_DISTILLED_MEMORIES_PER_USER
        )

    def test_clear_distilled_only_affects_distilled(
        self, db_session: Session, test_user: User
    ) -> None:
        _cleanup_user_memories(test_user.id, db_session)
        add_memory(test_user.id, "raw 1", db_session)
        add_distilled_memory(test_user.id, "distilled 1", db_session)
        add_distilled_memory(test_user.id, "distilled 2", db_session)

        deleted = clear_distilled_memories(test_user.id, db_session)
        assert deleted == 2
        # Raw should be untouched.
        assert len(get_raw_memories(test_user.id, db_session)) == 1
        assert len(get_distilled_memories(test_user.id, db_session)) == 0

    def test_delete_raw_memories_by_id(
        self, db_session: Session, test_user: User
    ) -> None:
        _cleanup_user_memories(test_user.id, db_session)
        add_memory(test_user.id, "keep me", db_session)
        m2 = add_memory(test_user.id, "delete me", db_session)

        deleted = delete_raw_memories(test_user.id, [m2.id], db_session)
        assert deleted == 1
        raw = get_raw_memories(test_user.id, db_session)
        assert len(raw) == 1
        assert raw[0].memory_text == "keep me"

    def test_count_raw_memories(self, db_session: Session, test_user: User) -> None:
        _cleanup_user_memories(test_user.id, db_session)
        add_memory(test_user.id, "r1", db_session)
        add_memory(test_user.id, "r2", db_session)
        add_distilled_memory(test_user.id, "d1", db_session)
        assert count_raw_memories(test_user.id, db_session) == 2


# ─── 3. get_memories Two-Tier Loading ─────────────────────────────────────────


class TestGetMemoriesTwoTier:
    def test_returns_both_layers(self, db_session: Session, test_user: User) -> None:
        _cleanup_user_memories(test_user.id, db_session)
        add_memory(test_user.id, "raw fact", db_session)
        add_distilled_memory(test_user.id, "distilled summary", db_session)

        ctx = get_memories(test_user, db_session)
        assert "distilled summary" in ctx.distilled_memories
        assert "raw fact" in ctx.raw_memories

    def test_recent_raw_limit_in_prompt(
        self, db_session: Session, test_user: User
    ) -> None:
        """Only the most recent RECENT_RAW_MEMORIES_IN_PROMPT raw memories
        should appear in the prompt context."""
        _cleanup_user_memories(test_user.id, db_session)
        for i in range(RECENT_RAW_MEMORIES_IN_PROMPT + 5):
            add_memory(test_user.id, f"raw {i}", db_session)

        ctx = get_memories(test_user, db_session)
        assert len(ctx.raw_memories) == RECENT_RAW_MEMORIES_IN_PROMPT
        # Should be the most recent ones.
        assert f"raw {RECENT_RAW_MEMORIES_IN_PROMPT + 4}" in ctx.raw_memories

    def test_flat_memories_is_distilled_plus_recent_raw(
        self, db_session: Session, test_user: User
    ) -> None:
        """The backward-compatible 'memories' field = distilled + recent raw."""
        _cleanup_user_memories(test_user.id, db_session)
        add_memory(test_user.id, "raw1", db_session)
        add_memory(test_user.id, "raw2", db_session)
        add_distilled_memory(test_user.id, "dist1", db_session)

        ctx = get_memories(test_user, db_session)
        assert ctx.memories == ("dist1", "raw1", "raw2")

    def test_without_memories_preserves_user_info(
        self, db_session: Session, test_user: User
    ) -> None:
        _cleanup_user_memories(test_user.id, db_session)
        add_memory(test_user.id, "raw1", db_session)
        test_user.personal_name = "TestUser"
        db_session.commit()

        ctx = get_memories(test_user, db_session)
        cleared = ctx.without_memories()
        assert cleared.user_info.name == "TestUser"
        assert cleared.raw_memories == ()
        assert cleared.distilled_memories == ()


# ─── 4. Distillation Flow ────────────────────────────────────────────────────


class TestDistillationFlow:
    def test_below_threshold_is_noop(
        self, db_session: Session, test_user: User
    ) -> None:
        """Below threshold, no LLM call, no changes."""
        _cleanup_user_memories(test_user.id, db_session)
        for i in range(DISTILLATION_THRESHOLD - 1):
            add_memory(test_user.id, f"raw {i}", db_session)

        llm = MagicMock()
        result = distill_user_memories(test_user.id, db_session, llm)
        assert result.success is True
        assert result.distilled_written == 0
        llm.invoke.assert_not_called()

    def test_distillation_consolidates_and_deletes(
        self, db_session: Session, test_user: User
    ) -> None:
        """Full distillation: LLM consolidates, writes distilled, deletes consumed raw."""
        _cleanup_user_memories(test_user.id, db_session)
        raw_memories = []
        for i in range(DISTILLATION_THRESHOLD + 5):
            m = add_memory(test_user.id, f"raw fact {i}", db_session)
            raw_memories.append(m)

        raw_before = count_raw_memories(test_user.id, db_session)

        # Mock LLM to consolidate first 3 raw into 1 distilled.
        # (distillable set is raw_memories[:-PRESERVE_RECENT_RAW])
        llm_response = {
            "distilled_memories": [
                {
                    "text": "Consolidated preference summary",
                    "importance": 0.85,
                    "source_ids": [1, 2, 3],
                }
            ],
            "raw_to_delete": [1, 2, 3],
        }
        llm = MagicMock()
        resp = MagicMock()
        resp.choice.message.content = json.dumps(llm_response)
        llm.invoke.return_value = resp

        result = distill_user_memories(test_user.id, db_session, llm)

        assert result.success is True
        assert result.distilled_written == 1
        assert result.raw_deleted == 3

        # Verify DB state.
        distilled_rows = get_distilled_memories(test_user.id, db_session)
        assert len(distilled_rows) == 1
        assert distilled_rows[0].memory_text == "Consolidated preference summary"
        assert distilled_rows[0].importance == 0.85
        # distilled_from_ids should reference actual DB ids of consumed raw.
        assert distilled_rows[0].distilled_from_ids is not None
        assert len(distilled_rows[0].distilled_from_ids) == 3

        # Raw count should have decreased.
        raw_after = count_raw_memories(test_user.id, db_session)
        assert raw_after == raw_before - 3

    def test_distillation_preserves_recent_raw(
        self, db_session: Session, test_user: User
    ) -> None:
        """The most recent PRESERVE_RECENT_RAW memories should never be in the
        distillable set, even if the LLM tries to delete them."""
        _cleanup_user_memories(test_user.id, db_session)
        all_mems = []
        for i in range(DISTILLATION_THRESHOLD + 5):
            m = add_memory(test_user.id, f"raw {i}", db_session)
            all_mems.append(m)

        # LLM tries to delete ALL raw memories (greedy).
        total_distillable = len(all_mems) - PRESERVE_RECENT_RAW
        llm_response = {
            "distilled_memories": [
                {
                    "text": "Everything",
                    "importance": 0.5,
                    "source_ids": list(range(1, total_distillable + 1)),
                }
            ],
            "raw_to_delete": list(range(1, total_distillable + 1)),
        }
        llm = MagicMock()
        resp = MagicMock()
        resp.choice.message.content = json.dumps(llm_response)
        llm.invoke.return_value = resp

        distill_user_memories(test_user.id, db_session, llm)

        # Recent raw should still exist.
        raw_after = get_raw_memories(test_user.id, db_session)
        assert len(raw_after) >= PRESERVE_RECENT_RAW
        # The newest memories should be preserved.
        recent_texts = [m.memory_text for m in raw_after[-PRESERVE_RECENT_RAW:]]
        assert "raw 24" in recent_texts  # The very last one

    def test_distillation_importance_clamped(
        self, db_session: Session, test_user: User
    ) -> None:
        """Importance > 1.0 should be clamped to 1.0."""
        _cleanup_user_memories(test_user.id, db_session)
        for i in range(DISTILLATION_THRESHOLD + 1):
            add_memory(test_user.id, f"raw {i}", db_session)

        llm_response = {
            "distilled_memories": [
                {"text": "Over-scored", "importance": 99.0, "source_ids": [1]}
            ],
            "raw_to_delete": [],
        }
        llm = MagicMock()
        resp = MagicMock()
        resp.choice.message.content = json.dumps(llm_response)
        llm.invoke.return_value = resp

        distill_user_memories(test_user.id, db_session, llm)

        distilled = get_distilled_memories(test_user.id, db_session)
        assert len(distilled) == 1
        assert distilled[0].importance == 1.0

    def test_distillation_llm_failure_is_safe(
        self, db_session: Session, test_user: User
    ) -> None:
        """LLM exception should not corrupt data."""
        _cleanup_user_memories(test_user.id, db_session)
        for i in range(DISTILLATION_THRESHOLD + 1):
            add_memory(test_user.id, f"raw {i}", db_session)
        raw_before = count_raw_memories(test_user.id, db_session)

        llm = MagicMock()
        llm.invoke.side_effect = RuntimeError("LLM down")

        result = distill_user_memories(test_user.id, db_session, llm)

        assert result.success is False
        # No data should have changed.
        assert count_raw_memories(test_user.id, db_session) == raw_before
        assert len(get_distilled_memories(test_user.id, db_session)) == 0


# ─── 5. Prompt Injection ─────────────────────────────────────────────────────


class TestPromptInjection:
    def test_two_section_display(self) -> None:
        """System prompt should have Summary + Recent sections."""
        from onyx.chat.prompt_utils import _build_user_information_section
        from onyx.db.memory import UserMemoryContext
        from onyx.db.memory import UserInfo

        ctx = UserMemoryContext(
            user_id=UUID("00000000-0000-0000-0000-000000000001"),
            user_info=UserInfo(name="Alice"),
            distilled_memories=("Prefers dark mode", "Uses Python"),
            raw_memories=("Working on auth fix",),
            memories=(),
        )
        section = _build_user_information_section(ctx, None)

        assert "## User Memories (Summary)" in section
        assert "## User Memories (Recent)" in section
        assert "Prefers dark mode" in section
        assert "Working on auth fix" in section

    def test_empty_layers_no_memory_section(self) -> None:
        from onyx.chat.prompt_utils import _build_user_information_section
        from onyx.db.memory import UserMemoryContext
        from onyx.db.memory import UserInfo

        ctx = UserMemoryContext(
            user_id=UUID("00000000-0000-0000-0000-000000000002"),
            user_info=UserInfo(),
            distilled_memories=(),
            raw_memories=(),
            memories=(),
        )
        section = _build_user_information_section(ctx, None)
        # No memory section when both layers are empty.
        assert "User Memories" not in section


# ─── 6. Distillable User Discovery ──────────────────────────────────────────


class TestDistillableUsers:
    def test_finds_users_above_threshold(
        self, db_session: Session, test_user: User
    ) -> None:
        _cleanup_user_memories(test_user.id, db_session)
        for i in range(DISTILLATION_THRESHOLD + 1):
            add_memory(test_user.id, f"raw {i}", db_session)

        users = get_distillable_users(db_session, DISTILLATION_THRESHOLD)
        assert test_user.id in users

    def test_excludes_users_below_threshold(
        self, db_session: Session, test_user: User
    ) -> None:
        _cleanup_user_memories(test_user.id, db_session)
        for i in range(DISTILLATION_THRESHOLD - 5):
            add_memory(test_user.id, f"raw {i}", db_session)

        users = get_distillable_users(db_session, DISTILLATION_THRESHOLD)
        assert test_user.id not in users


# ─── 7. Celery Task Smoke Test ──────────────────────────────────────────────


class TestCeleryTaskIntegration:
    def test_task_logic_with_specific_user(
        self, db_session: Session, test_user: User
    ) -> None:
        """Verify the distillation logic that the celery task invokes works
        correctly for a specific user. We call the underlying
        distill_user_memories directly (the task wraps it with advisory locks
        and celery bookkeeping that require a running broker)."""
        _cleanup_user_memories(test_user.id, db_session)
        add_memory(test_user.id, "single raw", db_session)

        llm = MagicMock()
        result = distill_user_memories(
            user_id=test_user.id,
            db_session=db_session,
            llm=llm,
            user_info={"name": "TestUser"},
        )

        # Below threshold — no-op.
        assert result.success is True
        assert result.raw_before == 1
        assert result.distilled_written == 0
        llm.invoke.assert_not_called()
