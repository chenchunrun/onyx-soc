from datetime import datetime
from datetime import timedelta
from datetime import timezone
from unittest.mock import MagicMock

from onyx.db.enums import ConnectorCredentialPairStatus
from onyx.db.models import IndexingStatus
from onyx.server.documents.connector import _compute_operational_reasons
from onyx.server.documents.connector import _get_connector_indexing_status_lite


def _build_cc_pair(
    *,
    status: ConnectorCredentialPairStatus = ConnectorCredentialPairStatus.ACTIVE,
    repeated_error: bool = False,
    deletion_failure_message: str | None = None,
) -> MagicMock:
    cc_pair = MagicMock()
    cc_pair.id = 1
    cc_pair.name = "cc-pair"
    cc_pair.status = status
    cc_pair.access_type = "public"
    cc_pair.connector_id = 10
    cc_pair.credential_id = 20
    cc_pair.connector = MagicMock()
    cc_pair.connector.source = "file"
    cc_pair.credential = MagicMock()
    cc_pair.in_repeated_error_state = repeated_error
    cc_pair.deletion_failure_message = deletion_failure_message
    return cc_pair


def _build_attempt(status: IndexingStatus, updated_at: datetime) -> MagicMock:
    attempt = MagicMock()
    attempt.status = status
    attempt.time_updated = updated_at
    attempt.total_docs_indexed = 42
    return attempt


def test_operational_state_active_when_healthy() -> None:
    cc_pair = _build_cc_pair()
    latest_attempt = _build_attempt(IndexingStatus.SUCCESS, datetime.now(timezone.utc))

    status = _get_connector_indexing_status_lite(
        cc_pair=cc_pair,
        latest_index_attempt=latest_attempt,
        latest_finished_index_attempt=latest_attempt,
        last_successful_index_time=datetime.now(timezone.utc),
        is_editable=True,
        document_cnt=100,
    )

    assert status is not None
    assert status.operational_active is True
    assert status.operational_deleting is False
    assert status.operational_error is False
    assert status.operational_stuck is False


def test_operational_state_deleting() -> None:
    cc_pair = _build_cc_pair(status=ConnectorCredentialPairStatus.DELETING)

    status = _get_connector_indexing_status_lite(
        cc_pair=cc_pair,
        latest_index_attempt=None,
        latest_finished_index_attempt=None,
        last_successful_index_time=None,
        is_editable=True,
        document_cnt=0,
    )

    assert status is not None
    assert status.operational_deleting is True


def test_operational_state_error_when_latest_finished_failed() -> None:
    cc_pair = _build_cc_pair()
    failed_attempt = _build_attempt(IndexingStatus.FAILED, datetime.now(timezone.utc))

    status = _get_connector_indexing_status_lite(
        cc_pair=cc_pair,
        latest_index_attempt=failed_attempt,
        latest_finished_index_attempt=failed_attempt,
        last_successful_index_time=None,
        is_editable=True,
        document_cnt=0,
    )

    assert status is not None
    assert status.operational_error is True
    assert status.operational_active is False


def test_operational_state_stuck_for_old_in_progress_attempt() -> None:
    cc_pair = _build_cc_pair()
    stale_attempt = _build_attempt(
        IndexingStatus.IN_PROGRESS,
        datetime.now(timezone.utc) - timedelta(hours=8),
    )

    status = _get_connector_indexing_status_lite(
        cc_pair=cc_pair,
        latest_index_attempt=stale_attempt,
        latest_finished_index_attempt=None,
        last_successful_index_time=None,
        is_editable=True,
        document_cnt=0,
    )

    assert status is not None
    assert status.operational_stuck is True
    assert status.operational_active is False


def test_compute_operational_reasons_includes_error_sources() -> None:
    cc_pair = _build_cc_pair(repeated_error=True, deletion_failure_message="failed")
    failed_attempt = _build_attempt(IndexingStatus.FAILED, datetime.now(timezone.utc))

    reasons = _compute_operational_reasons(
        cc_pair=cc_pair,
        latest_finished_index_attempt=failed_attempt,
        operational_deleting=False,
        operational_error=True,
        operational_stuck=False,
    )

    assert "deletion_failure" in reasons
    assert "repeated_indexing_errors" in reasons
    assert "latest_index_attempt_failed" in reasons


def test_compute_operational_reasons_includes_deleting_and_stuck() -> None:
    cc_pair = _build_cc_pair(status=ConnectorCredentialPairStatus.DELETING)
    reasons = _compute_operational_reasons(
        cc_pair=cc_pair,
        latest_finished_index_attempt=None,
        operational_deleting=True,
        operational_error=False,
        operational_stuck=True,
    )

    assert reasons == ["deleting", "indexing_stuck"]
