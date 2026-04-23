from ee.onyx.server.license.models import LicenseMetadata
from ee.onyx.server.license.models import LicenseOperationalState
from onyx.server.settings.models import ApplicationStatus


def derive_license_operational_state(
    *,
    metadata: LicenseMetadata | None,
    has_license_record: bool,
    billing_circuit_open: bool = False,
) -> tuple[LicenseOperationalState, str]:
    if metadata is None:
        if has_license_record:
            return (
                LicenseOperationalState.VERIFICATION_FAILED,
                "A local license exists but verification or cache refresh failed.",
            )
        return (
            LicenseOperationalState.EXPIRED,
            "No active license is currently available.",
        )

    if billing_circuit_open:
        return (
            LicenseOperationalState.DISCONNECTED_CACHED,
            "Billing connection is temporarily unavailable; using cached license state.",
        )

    if metadata.status == ApplicationStatus.GRACE_PERIOD:
        return (
            LicenseOperationalState.GRACE_PERIOD,
            "License is expired but still within grace period.",
        )

    if metadata.status == ApplicationStatus.GATED_ACCESS:
        return (
            LicenseOperationalState.EXPIRED,
            "License has expired and access is gated.",
        )

    return (
        LicenseOperationalState.VALID,
        "License is currently valid.",
    )
