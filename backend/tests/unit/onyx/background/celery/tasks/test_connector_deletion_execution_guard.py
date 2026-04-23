from unittest.mock import MagicMock

from onyx.background.celery.tasks.connector_deletion.tasks import (
    _is_current_deletion_execution,
)
from onyx.redis.redis_connector_delete import RedisConnectorDeletePayload


def _payload(execution_id: str | None) -> RedisConnectorDeletePayload:
    return RedisConnectorDeletePayload(
        num_tasks=1,
        submitted="2026-01-01T00:00:00+00:00",
        execution_id=execution_id,
    )


def test_is_current_deletion_execution_false_when_payload_missing() -> None:
    redis_connector = MagicMock()
    redis_connector.delete.payload = None

    assert (
        _is_current_deletion_execution(
            redis_connector=redis_connector,
            execution_id="exec-1",
            cc_pair_id=1,
            stage="test",
        )
        is False
    )


def test_is_current_deletion_execution_true_for_matching_execution_id() -> None:
    redis_connector = MagicMock()
    redis_connector.delete.payload = _payload("exec-1")

    assert (
        _is_current_deletion_execution(
            redis_connector=redis_connector,
            execution_id="exec-1",
            cc_pair_id=1,
            stage="test",
        )
        is True
    )


def test_is_current_deletion_execution_false_for_mismatched_execution_id() -> None:
    redis_connector = MagicMock()
    redis_connector.delete.payload = _payload("exec-2")

    assert (
        _is_current_deletion_execution(
            redis_connector=redis_connector,
            execution_id="exec-1",
            cc_pair_id=1,
            stage="test",
        )
        is False
    )


def test_is_current_deletion_execution_true_for_legacy_payload() -> None:
    redis_connector = MagicMock()
    redis_connector.delete.payload = _payload(None)

    assert (
        _is_current_deletion_execution(
            redis_connector=redis_connector,
            execution_id="exec-1",
            cc_pair_id=1,
            stage="test",
        )
        is True
    )
