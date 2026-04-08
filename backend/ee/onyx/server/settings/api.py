"""EE Settings API - provides license-aware settings override."""

from onyx.server.settings.models import Settings


def check_ee_features_enabled() -> bool:
    """EE features are always enabled for self-hosted deployments.

    License enforcement is controlled by LICENSE_ENFORCEMENT_ENABLED env var.
    When enforcement is disabled (default), EE features are always available.
    """
    return True


def apply_license_status_to_settings(settings: Settings) -> Settings:
    """EE features are always enabled for self-hosted deployments.

    License enforcement is controlled by LICENSE_ENFORCEMENT_ENABLED env var.
    When enforcement is disabled (default), EE features are always available
    and no license is required.
    """
    settings.ee_features_enabled = True
    return settings
