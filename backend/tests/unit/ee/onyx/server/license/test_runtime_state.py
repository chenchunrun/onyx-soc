from datetime import datetime
from datetime import timedelta
from datetime import timezone

from ee.onyx.server.license.models import LicenseMetadata
from ee.onyx.server.license.models import LicenseOperationalState
from ee.onyx.server.license.models import LicenseSource
from ee.onyx.server.license.models import PlanType
from ee.onyx.server.license.runtime_state import derive_license_operational_state
from onyx.server.settings.models import ApplicationStatus


def _metadata(status: ApplicationStatus) -> LicenseMetadata:
    now = datetime.now(timezone.utc)
    return LicenseMetadata(
        tenant_id="public",
        organization_name="Test Org",
        seats=10,
        used_seats=3,
        plan_type=PlanType.MONTHLY,
        issued_at=now - timedelta(days=30),
        expires_at=now + timedelta(days=30),
        status=status,
        source=LicenseSource.AUTO_FETCH,
    )


def test_derive_state_valid() -> None:
    state, reason = derive_license_operational_state(
        metadata=_metadata(ApplicationStatus.ACTIVE),
        has_license_record=True,
    )
    assert state == LicenseOperationalState.VALID
    assert "valid" in reason.lower()


def test_derive_state_grace_period() -> None:
    state, _ = derive_license_operational_state(
        metadata=_metadata(ApplicationStatus.GRACE_PERIOD),
        has_license_record=True,
    )
    assert state == LicenseOperationalState.GRACE_PERIOD


def test_derive_state_expired_from_gated_status() -> None:
    state, _ = derive_license_operational_state(
        metadata=_metadata(ApplicationStatus.GATED_ACCESS),
        has_license_record=True,
    )
    assert state == LicenseOperationalState.EXPIRED


def test_derive_state_verification_failed_when_record_exists_without_metadata() -> None:
    state, _ = derive_license_operational_state(
        metadata=None,
        has_license_record=True,
    )
    assert state == LicenseOperationalState.VERIFICATION_FAILED


def test_derive_state_disconnected_cached_when_circuit_open() -> None:
    state, _ = derive_license_operational_state(
        metadata=_metadata(ApplicationStatus.ACTIVE),
        has_license_record=True,
        billing_circuit_open=True,
    )
    assert state == LicenseOperationalState.DISCONNECTED_CACHED
