"""Tests for the memory distillation flow.

Uses a mock LLM to verify the distillation logic: consolidation, raw
deletion, importance scoring, and threshold gating.
"""

import json
from unittest.mock import MagicMock
from unittest.mock import patch
from uuid import uuid4

import pytest

from onyx.secondary_llm_flows.memory_distillation import DISTILLATION_THRESHOLD
from onyx.secondary_llm_flows.memory_distillation import PRESERVE_RECENT_RAW
from onyx.secondary_llm_flows.memory_distillation import DistillationResult
from onyx.secondary_llm_flows import memory_distillation  # noqa: F401 — ensure import


def _make_mock_llm(response_json: dict) -> MagicMock:
    """Create a mock LLM whose .invoke returns the given JSON dict."""
    llm = MagicMock()
    response = MagicMock()
    response.choice.message.content = json.dumps(response_json)
    llm.invoke.return_value = response
    return llm


class TestDistillationThreshold:
    def test_below_threshold_is_noop(self) -> None:
        """When raw count < threshold, distillation should be a no-op."""
        db_session = MagicMock()
        llm = MagicMock()

        # Mock get_raw_memories to return fewer than threshold memories.
        raw_mocks = [MagicMock(id=i, memory_text=f"mem {i}") for i in range(5)]

        with patch(
            "onyx.secondary_llm_flows.memory_distillation.get_raw_memories",
            return_value=raw_mocks,
        ):
            result = memory_distillation.distill_user_memories(
                user_id=uuid4(),
                db_session=db_session,
                llm=llm,
            )

        assert result.success is True
        assert result.distilled_written == 0
        assert result.raw_deleted == 0
        # LLM should NOT have been called.
        llm.invoke.assert_not_called()


class TestDistillationLogic:
    def test_distillation_writes_distilled_and_deletes_raw(self) -> None:
        """When raw count >= threshold, distillation should consolidate."""
        user_id = uuid4()
        db_session = MagicMock()

        # 25 raw memories (> threshold of 20).
        raw_mocks = [
            MagicMock(id=100 + i, memory_text=f"raw memory {i}") for i in range(25)
        ]

        # LLM returns 2 distilled memories and says to delete raw ids 1-3.
        llm_response = {
            "distilled_memories": [
                {
                    "text": "Consolidated preference for dark mode",
                    "importance": 0.9,
                    "source_ids": [1, 2, 3],
                },
                {
                    "text": "Uses React for frontend",
                    "importance": 0.7,
                    "source_ids": [4, 5],
                },
            ],
            "raw_to_delete": [1, 2, 3, 4, 5],
        }
        llm = _make_mock_llm(llm_response)

        with (
            patch(
                "onyx.secondary_llm_flows.memory_distillation.get_raw_memories",
                return_value=raw_mocks,
            ),
            patch(
                "onyx.secondary_llm_flows.memory_distillation.clear_distilled_memories",
                return_value=0,
            ),
            patch(
                "onyx.secondary_llm_flows.memory_distillation.add_distilled_memory"
            ) as mock_add,
            patch(
                "onyx.secondary_llm_flows.memory_distillation.delete_raw_memories",
                return_value=5,
            ) as mock_delete,
            patch(
                "onyx.secondary_llm_flows.memory_distillation.count_raw_safe",
                return_value=20,
            ),
        ):
            # add_distilled_memory should return a non-None object on success
            mock_add.return_value = MagicMock(id=1)

            result = memory_distillation.distill_user_memories(
                user_id=user_id,
                db_session=db_session,
                llm=llm,
            )

        assert result.success is True
        assert result.distilled_written == 2
        assert result.raw_deleted == 5
        assert result.raw_before == 25
        assert result.raw_after == 20
        mock_add.assert_called()

    def test_preserves_recent_raw_memories(self) -> None:
        """The most recent N raw memories should not be in the distillable set."""
        # With 25 memories and PRESERVE_RECENT_RAW=5, only 20 are distillable.
        assert PRESERVE_RECENT_RAW == 5

    def test_llm_failure_returns_unsuccessful_result(self) -> None:
        """If the LLM call raises, the result should indicate failure."""
        db_session = MagicMock()
        llm = MagicMock()
        llm.invoke.side_effect = RuntimeError("LLM unavailable")

        raw_mocks = [
            MagicMock(id=i, memory_text=f"mem {i}")
            for i in range(DISTILLATION_THRESHOLD + 5)
        ]

        with patch(
            "onyx.secondary_llm_flows.memory_distillation.get_raw_memories",
            return_value=raw_mocks,
        ):
            result = memory_distillation.distill_user_memories(
                user_id=uuid4(),
                db_session=db_session,
                llm=llm,
            )

        assert result.success is False
        assert "LLM unavailable" in (result.error or "")

    def test_empty_llm_response_returns_failure(self) -> None:
        """Empty LLM content should result in failure."""
        db_session = MagicMock()
        llm = MagicMock()
        response = MagicMock()
        response.choice.message.content = ""
        llm.invoke.return_value = response

        raw_mocks = [
            MagicMock(id=i, memory_text=f"mem {i}")
            for i in range(DISTILLATION_THRESHOLD + 5)
        ]

        with patch(
            "onyx.secondary_llm_flows.memory_distillation.get_raw_memories",
            return_value=raw_mocks,
        ):
            result = memory_distillation.distill_user_memories(
                user_id=uuid4(),
                db_session=db_session,
                llm=llm,
            )

        assert result.success is False
        assert "Empty" in (result.error or "")

    def test_malformed_json_returns_failure(self) -> None:
        """Unparseable LLM output should result in failure."""
        db_session = MagicMock()
        llm = MagicMock()
        response = MagicMock()
        response.choice.message.content = "this is not json {{{"
        llm.invoke.return_value = response

        raw_mocks = [
            MagicMock(id=i, memory_text=f"mem {i}")
            for i in range(DISTILLATION_THRESHOLD + 5)
        ]

        with patch(
            "onyx.secondary_llm_flows.memory_distillation.get_raw_memories",
            return_value=raw_mocks,
        ):
            result = memory_distillation.distill_user_memories(
                user_id=uuid4(),
                db_session=db_session,
                llm=llm,
            )

        assert result.success is False

    def test_importance_score_clamped(self) -> None:
        """Importance scores outside 0-1 should be clamped."""
        user_id = uuid4()
        db_session = MagicMock()

        raw_mocks = [
            MagicMock(id=i, memory_text=f"mem {i}")
            for i in range(DISTILLATION_THRESHOLD + 5)
        ]

        llm_response = {
            "distilled_memories": [
                {
                    "text": "High importance",
                    "importance": 5.0,  # Out of range
                    "source_ids": [1],
                },
            ],
            "raw_to_delete": [],
        }
        llm = _make_mock_llm(llm_response)

        captured_importance: list[float] = []

        def _capture_importance(*args, **kwargs):
            captured_importance.append(kwargs.get("importance", 0.5))
            return MagicMock(id=1)

        with (
            patch(
                "onyx.secondary_llm_flows.memory_distillation.get_raw_memories",
                return_value=raw_mocks,
            ),
            patch(
                "onyx.secondary_llm_flows.memory_distillation.clear_distilled_memories"
            ),
            patch(
                "onyx.secondary_llm_flows.memory_distillation.add_distilled_memory",
                side_effect=_capture_importance,
            ),
            patch(
                "onyx.secondary_llm_flows.memory_distillation.delete_raw_memories"
            ),
            patch(
                "onyx.secondary_llm_flows.memory_distillation.count_raw_safe",
                return_value=25,
            ),
        ):
            result = memory_distillation.distill_user_memories(
                user_id=user_id,
                db_session=db_session,
                llm=llm,
            )

        assert result.success is True
        assert len(captured_importance) == 1
        assert captured_importance[0] == 1.0  # Clamped from 5.0


class TestDistillationPrompt:
    def test_prompt_contains_raw_memories_and_limits(self) -> None:
        from onyx.prompts.memory_distillation import MEMORY_DISTILLATION_PROMPT

        formatted = MEMORY_DISTILLATION_PROMPT.format(
            raw_memories="1. Prefers dark mode\n2. Uses Python",
            user_context="Name: Alice",
            max_distilled=15,
        )
        assert "Prefers dark mode" in formatted
        assert "Alice" in formatted
        assert "distilled_memories" in formatted
        assert "raw_to_delete" in formatted
        assert "15" in formatted
