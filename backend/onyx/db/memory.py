from datetime import datetime
from datetime import timezone
from uuid import UUID

from pydantic import BaseModel
from pydantic import ConfigDict
from sqlalchemy import delete
from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy.orm import Session

from onyx.db.models import Memory
from onyx.db.models import User

# ─── Layered memory constants ─────────────────────────────────────────────────

MEMORY_LAYER_RAW = "raw"
MEMORY_LAYER_DISTILLED = "distilled"

# Capacity per layer.
MAX_RAW_MEMORIES_PER_USER = 100
MAX_DISTILLED_MEMORIES_PER_USER = 15

# Backward-compatible alias (used by server/manage/models.py validation and
# external dependency tests). Now points to the raw-layer limit.
MAX_MEMORIES_PER_USER = MAX_RAW_MEMORIES_PER_USER

# When injecting raw memories into the prompt, only show the most recent N.
RECENT_RAW_MEMORIES_IN_PROMPT = 5


class UserInfo(BaseModel):
    name: str | None = None
    role: str | None = None
    email: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "role": self.role,
            "email": self.email,
        }


class UserMemoryContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: UUID | None = None
    user_info: UserInfo
    user_preferences: str | None = None
    # Two-tier memories: distilled (consolidated) + raw (recent, original).
    distilled_memories: tuple[str, ...] = ()
    raw_memories: tuple[str, ...] = ()
    # Backward-compatible flat view (distilled first, then raw).
    memories: tuple[str, ...] = ()

    def without_memories(self) -> "UserMemoryContext":
        """Return a copy with memories cleared but user info/preferences intact."""
        return UserMemoryContext(
            user_id=self.user_id,
            user_info=self.user_info,
            user_preferences=self.user_preferences,
            distilled_memories=(),
            raw_memories=(),
            memories=(),
        )

    def as_formatted_list(self) -> list[str]:
        """Returns combined list of user info, preferences, and memories.

        Memories are rendered in two groups (distilled summary first, then
        recent raw) so the LLM can distinguish stable traits from fresh facts.
        """
        result: list[str] = []
        if self.user_info.name:
            result.append(f"User's name: {self.user_info.name}")
        if self.user_info.role:
            result.append(f"User's role: {self.user_info.role}")
        if self.user_info.email:
            result.append(f"User's email: {self.user_info.email}")
        if self.user_preferences:
            result.append(f"User preferences: {self.user_preferences}")
        # Backward-compatible flat fallback.
        result.extend(self.memories)
        return result


# ─── Query helpers ────────────────────────────────────────────────────────────


def get_memories(user: User, db_session: Session) -> UserMemoryContext:
    """Load the user's memory context, split into distilled and raw layers."""
    user_info = UserInfo(
        name=user.personal_name,
        role=user.personal_role,
        email=user.email,
    )

    user_preferences = None
    if user.user_preferences:
        user_preferences = user.user_preferences

    all_rows = db_session.scalars(
        select(Memory).where(Memory.user_id == user.id).order_by(Memory.id.asc())
    ).all()

    distilled_texts: list[str] = []
    raw_texts: list[str] = []
    for row in all_rows:
        if not row.memory_text:
            continue
        if row.layer == MEMORY_LAYER_DISTILLED:
            distilled_texts.append(row.memory_text)
        else:
            raw_texts.append(row.memory_text)

    # For the prompt, only the most recent raw memories are shown.
    recent_raw = tuple(raw_texts[-RECENT_RAW_MEMORIES_IN_PROMPT:])
    # Flat backward-compatible view: distilled + recent raw.
    flat = tuple(distilled_texts + list(recent_raw))

    return UserMemoryContext(
        user_id=user.id,
        user_info=user_info,
        user_preferences=user_preferences,
        distilled_memories=tuple(distilled_texts),
        raw_memories=recent_raw,
        memories=flat,
    )


def get_raw_memories(
    user_id: UUID, db_session: Session, limit: int | None = None
) -> list[Memory]:
    """Return all raw-layer memories for a user, oldest first."""
    stmt = (
        select(Memory)
        .where(Memory.user_id == user_id, Memory.layer == MEMORY_LAYER_RAW)
        .order_by(Memory.id.asc())
    )
    if limit is not None:
        stmt = stmt.limit(limit)
    return list(db_session.scalars(stmt).all())


def get_distilled_memories(user_id: UUID, db_session: Session) -> list[Memory]:
    """Return all distilled-layer memories for a user, oldest first."""
    return list(
        db_session.scalars(
            select(Memory)
            .where(Memory.user_id == user_id, Memory.layer == MEMORY_LAYER_DISTILLED)
            .order_by(Memory.id.asc())
        ).all()
    )


def count_raw_memories(user_id: UUID, db_session: Session) -> int:
    """Count raw-layer memories for a user."""
    return (
        db_session.scalar(
            select(func.count(Memory.id)).where(
                Memory.user_id == user_id, Memory.layer == MEMORY_LAYER_RAW
            )
        )
        or 0
    )


def get_distillable_users(db_session: Session, threshold: int) -> list[UUID]:
    """Return user IDs that have at least ``threshold`` raw memories."""
    rows = db_session.execute(
        select(Memory.user_id)
        .where(Memory.layer == MEMORY_LAYER_RAW)
        .group_by(Memory.user_id)
        .having(func.count(Memory.id) >= threshold)
    ).all()
    return [row[0] for row in rows]


# ─── Write helpers ────────────────────────────────────────────────────────────


def add_memory(
    user_id: UUID,
    memory_text: str,
    db_session: Session,
) -> Memory:
    """Insert a new raw Memory row for the given user.

    If the user already has MAX_RAW_MEMORIES_PER_USER raw memories, the oldest
    one (lowest id) is deleted before inserting the new one (FIFO eviction).
    """
    existing = db_session.scalars(
        select(Memory)
        .where(Memory.user_id == user_id, Memory.layer == MEMORY_LAYER_RAW)
        .order_by(Memory.id.asc())
    ).all()

    if len(existing) >= MAX_RAW_MEMORIES_PER_USER:
        db_session.delete(existing[0])

    memory = Memory(
        user_id=user_id,
        memory_text=memory_text,
        layer=MEMORY_LAYER_RAW,
    )
    db_session.add(memory)
    db_session.commit()
    return memory


def update_memory_at_index(
    user_id: UUID,
    index: int,
    new_text: str,
    db_session: Session,
) -> Memory | None:
    """Update the raw memory at the given 0-based index (ordered by id ASC).

    Returns the updated Memory row, or None if the index is out of range.
    """
    memory_rows = db_session.scalars(
        select(Memory)
        .where(Memory.user_id == user_id, Memory.layer == MEMORY_LAYER_RAW)
        .order_by(Memory.id.asc())
    ).all()

    if index < 0 or index >= len(memory_rows):
        return None

    memory = memory_rows[index]
    memory.memory_text = new_text
    db_session.commit()
    return memory


def add_distilled_memory(
    user_id: UUID,
    memory_text: str,
    db_session: Session,
    distilled_from_ids: list[int] | None = None,
    importance: float = 0.5,
) -> Memory | None:
    """Insert a distilled memory. Returns None if the distilled cap is reached
    and eviction is not desired (caller should manage eviction explicitly)."""
    existing_count = (
        db_session.scalar(
            select(func.count(Memory.id)).where(
                Memory.user_id == user_id, Memory.layer == MEMORY_LAYER_DISTILLED
            )
        )
        or 0
    )

    if existing_count >= MAX_DISTILLED_MEMORIES_PER_USER:
        return None

    memory = Memory(
        user_id=user_id,
        memory_text=memory_text,
        layer=MEMORY_LAYER_DISTILLED,
        importance=importance,
        distilled_from_ids=distilled_from_ids,
    )
    db_session.add(memory)
    db_session.commit()
    return memory


def clear_distilled_memories(user_id: UUID, db_session: Session) -> int:
    """Delete all distilled memories for a user. Returns the number deleted."""
    result = db_session.execute(
        delete(Memory).where(
            Memory.user_id == user_id, Memory.layer == MEMORY_LAYER_DISTILLED
        )
    )
    db_session.commit()
    return result.rowcount


def delete_raw_memories(
    user_id: UUID, memory_ids: list[int], db_session: Session
) -> int:
    """Delete specific raw memories by id. Returns the number deleted."""
    if not memory_ids:
        return 0
    result = db_session.execute(
        delete(Memory).where(
            Memory.user_id == user_id,
            Memory.layer == MEMORY_LAYER_RAW,
            Memory.id.in_(memory_ids),
        )
    )
    db_session.commit()
    return result.rowcount


def touch_memory_access(user_id: UUID, db_session: Session) -> None:
    """Update last_accessed_at for all of a user's memories (called when
    memories are injected into a prompt)."""
    now = datetime.now(timezone.utc)
    db_session.execute(
        Memory.__table__.update()
        .where(Memory.user_id == user_id)
        .values(last_accessed_at=now)
    )
    db_session.commit()
