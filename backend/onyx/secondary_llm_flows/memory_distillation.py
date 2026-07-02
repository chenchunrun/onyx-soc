"""Periodic memory distillation flow.

Consolidates a user's accumulated raw memories into a smaller set of
high-value distilled memories, then removes the raw memories that have
been captured. This is invoked by the celery beat task (scheduled) and
by the threshold-triggered async task (when raw count >= threshold).
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.orm import Session

from onyx.db.memory import MEMORY_LAYER_RAW
from onyx.db.memory import clear_distilled_memories
from onyx.db.memory import add_distilled_memory
from onyx.db.memory import delete_raw_memories
from onyx.db.memory import get_raw_memories
from onyx.db.memory import MAX_DISTILLED_MEMORIES_PER_USER
from onyx.llm.interfaces import LLM
from onyx.llm.models import ReasoningEffort
from onyx.llm.models import UserMessage
from onyx.prompts.memory_distillation import MEMORY_DISTILLATION_PROMPT
from onyx.tracing.llm_utils import llm_generation_span
from onyx.tracing.llm_utils import record_llm_response
from onyx.utils.logger import setup_logger
from onyx.utils.text_processing import parse_llm_json_response

logger = setup_logger()

# Raw memories at or above this count trigger distillation.
DISTILLATION_THRESHOLD = 20

# Number of most-recent raw memories to always preserve (never distill away).
PRESERVE_RECENT_RAW = 5


@dataclass
class DistillationResult:
    """Outcome of a single user's distillation run."""

    user_id: UUID
    raw_before: int
    raw_after: int
    distilled_written: int
    raw_deleted: int
    success: bool
    error: str | None = None


def _format_raw_memories(raw_memories: list) -> str:
    """Format raw memories as a 1-indexed numbered list for the LLM."""
    lines: list[str] = []
    for i, mem in enumerate(raw_memories, 1):
        text = mem.memory_text if hasattr(mem, "memory_text") else str(mem)
        lines.append(f"{i}. {text}")
    return "\n".join(lines)


def _format_user_context(user_info: dict | None) -> str:
    """Format basic user info for the prompt."""
    if not user_info:
        return "No user context available."
    parts: list[str] = []
    if user_info.get("name"):
        parts.append(f"Name: {user_info['name']}")
    if user_info.get("role"):
        parts.append(f"Role: {user_info['role']}")
    return ", ".join(parts) if parts else "No user context available."


def distill_user_memories(
    user_id: UUID,
    db_session: Session,
    llm: LLM,
    user_info: dict | None = None,
) -> DistillationResult:
    """Distill a user's raw memories into consolidated distilled memories.

    1. Load all raw memories.
    2. Split into "distillable" (older) and "preserve" (recent N).
    3. Ask LLM to consolidate the distillable set.
    4. Clear old distilled memories, write new ones, delete consumed raw.
    """
    raw_all = get_raw_memories(user_id, db_session)
    raw_before = len(raw_all)

    if raw_before < DISTILLATION_THRESHOLD:
        return DistillationResult(
            user_id=user_id,
            raw_before=raw_before,
            raw_after=raw_before,
            distilled_written=0,
            raw_deleted=0,
            success=True,
        )

    # Never distill away the most recent memories — they keep recent context.
    preserve_count = min(PRESERVE_RECENT_RAW, raw_before)
    distillable = raw_all[:-preserve_count] if preserve_count > 0 else raw_all

    if not distillable:
        return DistillationResult(
            user_id=user_id,
            raw_before=raw_before,
            raw_after=raw_before,
            distilled_written=0,
            raw_deleted=0,
            success=True,
        )

    prompt = MEMORY_DISTILLATION_PROMPT.format(
        raw_memories=_format_raw_memories(distillable),
        user_context=_format_user_context(user_info),
        max_distilled=MAX_DISTILLED_MEMORIES_PER_USER,
    )

    # Call the LLM to produce consolidated memories.
    try:
        prompt_msg = UserMessage(content=prompt)
        with llm_generation_span(
            llm=llm, flow="memory_distillation", input_messages=[prompt_msg]
        ) as span_generation:
            response = llm.invoke(
                prompt=prompt_msg, reasoning_effort=ReasoningEffort.OFF
            )
            record_llm_response(span_generation, response)
            content = response.choice.message.content
    except Exception as e:
        logger.warning(f"[memory_distillation] LLM call failed for user {user_id}: {e}")
        return DistillationResult(
            user_id=user_id,
            raw_before=raw_before,
            raw_after=raw_before,
            distilled_written=0,
            raw_deleted=0,
            success=False,
            error=str(e),
        )

    if not content:
        logger.warning(f"[memory_distillation] Empty LLM response for user {user_id}")
        return DistillationResult(
            user_id=user_id,
            raw_before=raw_before,
            raw_after=raw_before,
            distilled_written=0,
            raw_deleted=0,
            success=False,
            error="Empty LLM response",
        )

    parsed = parse_llm_json_response(content)
    if not parsed or not isinstance(parsed, dict):
        logger.warning(
            f"[memory_distillation] Failed to parse JSON for user {user_id}: {content[:200]}"
        )
        return DistillationResult(
            user_id=user_id,
            raw_before=raw_before,
            raw_after=raw_before,
            distilled_written=0,
            raw_deleted=0,
            success=False,
            error="JSON parse failure",
        )

    distilled_entries = parsed.get("distilled_memories", [])
    raw_to_delete_indices = parsed.get("raw_to_delete", [])

    if not isinstance(distilled_entries, list):
        distilled_entries = []
    if not isinstance(raw_to_delete_indices, list):
        raw_to_delete_indices = []

    # Clear previous distilled memories before writing the fresh set.
    clear_distilled_memories(user_id, db_session)

    # Write new distilled memories.
    distilled_written = 0
    for entry in distilled_entries:
        if not isinstance(entry, dict):
            continue
        text = entry.get("text", "").strip()
        if not text:
            continue
        importance = entry.get("importance", 0.5)
        try:
            importance = float(importance)
            importance = max(0.0, min(1.0, importance))
        except (ValueError, TypeError):
            importance = 0.5
        # Resolve source_ids (1-indexed in LLM output) to actual DB ids.
        source_ids: list[int] = []
        for sid in entry.get("source_ids", []):
            try:
                idx = int(sid) - 1  # Convert to 0-indexed
                if 0 <= idx < len(distillable):
                    source_ids.append(distillable[idx].id)
            except (ValueError, TypeError):
                continue

        result = add_distilled_memory(
            user_id=user_id,
            memory_text=text,
            db_session=db_session,
            distilled_from_ids=source_ids or None,
            importance=importance,
        )
        if result is not None:
            distilled_written += 1

    # Delete raw memories that the LLM identified as fully captured.
    raw_ids_to_delete: list[int] = []
    for idx_1based in raw_to_delete_indices:
        try:
            idx = int(idx_1based) - 1
            if 0 <= idx < len(distillable):
                raw_ids_to_delete.append(distillable[idx].id)
        except (ValueError, TypeError):
            continue

    raw_deleted = delete_raw_memories(user_id, raw_ids_to_delete, db_session)

    raw_after = count_raw_safe(user_id, db_session)

    logger.info(
        f"[memory_distillation] user={user_id} raw {raw_before}→{raw_after}, "
        f"distilled={distilled_written}, deleted={raw_deleted}"
    )

    return DistillationResult(
        user_id=user_id,
        raw_before=raw_before,
        raw_after=raw_after,
        distilled_written=distilled_written,
        raw_deleted=raw_deleted,
        success=True,
    )


def count_raw_safe(user_id: UUID, db_session: Session) -> int:
    """Count raw memories, tolerating any error."""
    try:
        from onyx.db.memory import count_raw_memories

        return count_raw_memories(user_id, db_session)
    except Exception:
        return -1
