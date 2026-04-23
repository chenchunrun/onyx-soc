from unittest.mock import MagicMock
from unittest.mock import call
from unittest.mock import patch

from onyx.background.celery.tasks.connector_deletion.tasks import (
    revoke_tasks_blocking_deletion,
    monitor_connector_deletion_taskset,
)
from onyx.configs.constants import OnyxRedisConstants
from onyx.db.enums import IndexingStatus


CONNECTOR_DELETION_TASKS_MODULE = (
    "onyx.background.celery.tasks.connector_deletion.tasks"
)


class _SimpleRedisPayload:
    def __init__(self, task_id: str | None) -> None:
        self.celery_task_id = task_id


def test_revoke_tasks_blocking_deletion_requests_cancellation_and_revoke() -> None:
    redis_connector = MagicMock()
    redis_connector.cc_pair_id = 123
    redis_connector.permissions.payload = _SimpleRedisPayload("permissions-task")
    redis_connector.prune.payload = _SimpleRedisPayload("prune-task")
    redis_connector.external_group_sync.payload = _SimpleRedisPayload("ext-group-task")

    app = MagicMock()
    app.control.revoke = MagicMock()

    with (
        patch(
            f"{CONNECTOR_DELETION_TASKS_MODULE}.get_all_search_settings",
            return_value=[MagicMock(id=1), MagicMock(id=2)],
        ),
        patch(
            f"{CONNECTOR_DELETION_TASKS_MODULE}.get_recent_attempts_for_cc_pair",
            side_effect=[
                [
                    _build_indexing_attempt(
                        10, IndexingStatus.IN_PROGRESS, "docfetching-task"
                    )
                ],
                [],
            ],
        ),
        patch(
            f"{CONNECTOR_DELETION_TASKS_MODULE}.IndexingCoordination.request_cancellation"
        ) as mock_request_cancellation,
    ):
        db_session = MagicMock()
        revoke_tasks_blocking_deletion(redis_connector, db_session, app)

    mock_request_cancellation.assert_called_once_with(db_session, 10)
    app.control.revoke.assert_has_calls(
        [
            call("docfetching-task"),
            call("permissions-task"),
            call("prune-task"),
            call("ext-group-task"),
        ],
        any_order=False,
    )


def test_revoke_tasks_blocking_deletion_skips_non_running_indexing_attempt() -> None:
    redis_connector = MagicMock()
    redis_connector.cc_pair_id = 123
    redis_connector.permissions.payload = _SimpleRedisPayload(None)
    redis_connector.prune.payload = _SimpleRedisPayload(None)
    redis_connector.external_group_sync.payload = _SimpleRedisPayload(None)

    app = MagicMock()
    app.control.revoke = MagicMock()

    with (
        patch(
            f"{CONNECTOR_DELETION_TASKS_MODULE}.get_all_search_settings",
            return_value=[MagicMock(id=1)],
        ),
        patch(
            f"{CONNECTOR_DELETION_TASKS_MODULE}.get_recent_attempts_for_cc_pair",
            return_value=[
                _build_indexing_attempt(
                    10, IndexingStatus.NOT_STARTED, "docfetching-task"
                )
            ],
        ),
        patch(
            f"{CONNECTOR_DELETION_TASKS_MODULE}.IndexingCoordination.request_cancellation"
        ) as mock_request_cancellation,
    ):
        revoke_tasks_blocking_deletion(redis_connector, MagicMock(), app)

    mock_request_cancellation.assert_not_called()
    app.control.revoke.assert_not_called()


def test_monitor_connector_deletion_taskset_removes_invalid_active_fence_key() -> None:
    redis = MagicMock()
    monitor_connector_deletion_taskset("tenant", b"invalid-key", redis)

    redis.srem.assert_called_once_with(OnyxRedisConstants.ACTIVE_FENCES, b"invalid-key")


def test_monitor_connector_deletion_taskset_clears_fence_when_cc_pair_missing() -> None:
    redis = MagicMock()
    redis_connector = MagicMock()
    redis_connector.delete.payload = _build_delete_payload(
        execution_id="exec-1", num_tasks=0
    )
    redis_connector.delete.get_remaining.return_value = 0
    redis_connector.delete.reset = MagicMock()

    db_session = MagicMock()

    with (
        patch(f"{CONNECTOR_DELETION_TASKS_MODULE}.RedisConnector") as mock_connector,
        patch(
            f"{CONNECTOR_DELETION_TASKS_MODULE}.get_connector_credential_pair_from_id",
            return_value=None,
        ),
        patch(
            f"{CONNECTOR_DELETION_TASKS_MODULE}.get_session_with_current_tenant"
        ) as mock_session,
    ):
        mock_connector.get_id_from_fence_key.return_value = "123"
        mock_connector.return_value = redis_connector
        mock_session.return_value.__enter__.return_value = db_session
        monitor_connector_deletion_taskset(
            "tenant", b"connectordeletion_fence_123", redis
        )

    redis_connector.delete.reset.assert_called_once()


def _build_indexing_attempt(
    attempt_id: int, status: IndexingStatus, celery_task_id: str
) -> MagicMock:
    attempt = MagicMock()
    attempt.id = attempt_id
    attempt.status = status
    attempt.celery_task_id = celery_task_id
    return attempt


def _build_delete_payload(
    *, execution_id: str, num_tasks: int | None
) -> MagicMock:
    payload = MagicMock()
    payload.execution_id = execution_id
    payload.num_tasks = num_tasks
    return payload
