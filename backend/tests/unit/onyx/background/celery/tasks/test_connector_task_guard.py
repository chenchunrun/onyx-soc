from unittest.mock import MagicMock

from onyx.background.celery.tasks.shared.connector_task_guard import guard_cc_pair_for_task
from onyx.db.enums import ConnectorCredentialPairStatus


def _build_cc_pair(status: ConnectorCredentialPairStatus) -> MagicMock:
    cc_pair = MagicMock()
    cc_pair.id = 123
    cc_pair.status = status
    return cc_pair


def test_guard_cc_pair_for_task_rejects_missing_pair() -> None:
    assert (
        guard_cc_pair_for_task(
            cc_pair=None,
            task_name="unit_test_task",
        )
        is False
    )


def test_guard_cc_pair_for_task_rejects_deleting_pair() -> None:
    assert (
        guard_cc_pair_for_task(
            cc_pair=_build_cc_pair(ConnectorCredentialPairStatus.DELETING),
            task_name="unit_test_task",
        )
        is False
    )


def test_guard_cc_pair_for_task_rejects_disallowed_status() -> None:
    assert (
        guard_cc_pair_for_task(
            cc_pair=_build_cc_pair(ConnectorCredentialPairStatus.PAUSED),
            task_name="unit_test_task",
            allowed_statuses=(ConnectorCredentialPairStatus.ACTIVE,),
        )
        is False
    )


def test_guard_cc_pair_for_task_accepts_allowed_status() -> None:
    assert (
        guard_cc_pair_for_task(
            cc_pair=_build_cc_pair(ConnectorCredentialPairStatus.ACTIVE),
            task_name="unit_test_task",
            allowed_statuses=(ConnectorCredentialPairStatus.ACTIVE,),
        )
        is True
    )
