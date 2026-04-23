from collections.abc import Iterable

from onyx.background.celery.apps.app_base import task_logger
from onyx.db.enums import ConnectorCredentialPairStatus
from onyx.db.models import ConnectorCredentialPair


def guard_cc_pair_for_task(
    *,
    cc_pair: ConnectorCredentialPair | None,
    task_name: str,
    allowed_statuses: Iterable[ConnectorCredentialPairStatus] | None = None,
) -> bool:
    """Returns True when a connector credential pair is eligible for task execution.

    The guard intentionally centralizes common checks for async task entrypoints:
    missing cc_pair rows, delete-in-progress, and optional status allowlists.
    """
    if cc_pair is None:
        task_logger.info("%s - skipping: connector credential pair missing", task_name)
        return False

    if cc_pair.status == ConnectorCredentialPairStatus.DELETING:
        task_logger.info("%s - skipping: cc_pair=%s deleting", task_name, cc_pair.id)
        return False

    if allowed_statuses is not None:
        allowed = tuple(allowed_statuses)
        if cc_pair.status not in allowed:
            task_logger.info(
                "%s - skipping: cc_pair=%s status=%s allowed=%s",
                task_name,
                cc_pair.id,
                cc_pair.status.value,
                [status.value for status in allowed],
            )
            return False

    return True
