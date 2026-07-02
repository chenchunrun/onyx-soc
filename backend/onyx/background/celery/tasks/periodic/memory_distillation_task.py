"""Periodic memory distillation task.

Consolidates users' raw memories into distilled memories on a schedule
and on-demand (threshold-triggered via .delay()).
"""

from typing import Any

from celery import shared_task
from celery.contrib.abortable import AbortableTask  # type: ignore
from celery.exceptions import TaskRevokedError
from sqlalchemy import text

from onyx.background.celery.apps.app_base import task_logger
from onyx.configs.app_configs import JOB_TIMEOUT
from onyx.configs.constants import OnyxCeleryTask
from onyx.configs.constants import PostgresAdvisoryLocks
from onyx.db.engine.sql_engine import get_session_with_current_tenant
from onyx.db.memory import get_distillable_users
from onyx.secondary_llm_flows.memory_distillation import DISTILLATION_THRESHOLD
from onyx.secondary_llm_flows.memory_distillation import distill_user_memories


@shared_task(
    name=OnyxCeleryTask.MEMORY_DISTILLATION_TASK,
    soft_time_limit=JOB_TIMEOUT,
    bind=True,
    base=AbortableTask,
)
def memory_distillation_task(
    self: Any,  # type: ignore[override]
    tenant_id: str,
    user_id: str | None = None,
) -> dict[str, Any]:
    """Distill raw memories into distilled memories.

    If ``user_id`` is provided, distill only that user.
    Otherwise, scan for all users with raw count >= threshold.
    """
    task_logger.info(
        f"memory_distillation_task started: tenant={tenant_id} user={user_id}"
    )

    results: list[dict] = []

    with get_session_with_current_tenant() as db_session:
        # Prevent concurrent distillation across workers.
        lock_acquired = db_session.execute(
            text("SELECT pg_try_advisory_lock(:id)"),
            {"id": PostgresAdvisoryLocks.MEMORY_DISTILLATION_LOCK_ID.value},
        ).scalar()

        if not lock_acquired:
            task_logger.info(
                "memory_distillation_task: another instance is running, skipping"
            )
            return {"skipped": True, "reason": "lock_busy"}

        try:
            from onyx.llm.factory import get_default_llm

            llm = get_default_llm()
        except Exception as e:
            task_logger.error(f"memory_distillation_task: cannot get LLM: {e}")
            db_session.execute(
                text("SELECT pg_advisory_unlock(:id)"),
                {"id": PostgresAdvisoryLocks.MEMORY_DISTILLATION_LOCK_ID.value},
            )
            return {"error": str(e)}

        # Determine which users to process.
        if user_id:
            from uuid import UUID

            target_user_ids: list[UUID] = [UUID(user_id)]
        else:
            target_user_ids = get_distillable_users(
                db_session, DISTILLATION_THRESHOLD
            )

        task_logger.info(
            f"memory_distillation_task: processing {len(target_user_ids)} user(s)"
        )

        for uid in target_user_ids:
            if self.is_aborted():
                raise TaskRevokedError(
                    "memory_distillation_task was aborted."
                )

            # Get basic user info for the prompt.
            user_info: dict | None = None
            try:
                from onyx.db.users import get_user_by_id

                user = get_user_by_id(db_session, uid)
                if user:
                    user_info = {
                        "name": getattr(user, "personal_name", None),
                        "role": getattr(user, "personal_role", None),
                    }
            except Exception:
                pass  # User info is optional context for the prompt.

            result = distill_user_memories(
                user_id=uid,
                db_session=db_session,
                llm=llm,
                user_info=user_info,
            )

            results.append(
                {
                    "user_id": str(uid),
                    "raw_before": result.raw_before,
                    "raw_after": result.raw_after,
                    "distilled_written": result.distilled_written,
                    "raw_deleted": result.raw_deleted,
                    "success": result.success,
                    "error": result.error,
                }
            )

        # Release the advisory lock.
        db_session.execute(
            text("SELECT pg_advisory_unlock(:id)"),
            {"id": PostgresAdvisoryLocks.MEMORY_DISTILLATION_LOCK_ID.value},
        )

    summary = {
        "processed": len(results),
        "succeeded": sum(1 for r in results if r["success"]),
        "failed": sum(1 for r in results if not r["success"]),
        "results": results,
    }
    task_logger.info(f"memory_distillation_task complete: {summary}")
    return summary
