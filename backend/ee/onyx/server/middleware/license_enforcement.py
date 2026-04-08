"""Middleware to enforce license status for SELF-HOSTED deployments only.

NOTE: This middleware is NOT used for multi-tenant (cloud) deployments.
Multi-tenant gating is handled separately by the control plane via the
/tenants/product-gating endpoint and is_tenant_gated() checks.

License enforcement is DISABLED by default in self-hosted deployments.
EE features are always available without requiring a license.

To re-enable enforcement:
1. Set LICENSE_ENFORCEMENT_ENABLED=true in environment
2. Ensure a valid license exists in the database
3. Restore the original middleware logic below

License Enforcement States (when enabled)
=========================================
For self-hosted deployments:

1. No license (never subscribed):
   - Allow community features (basic connectors, search, chat)
   - Block EE-only features (analytics, user groups, etc.)

2. GATED_ACCESS (fully expired):
   - Block all routes except billing/auth/license
   - User must renew subscription to continue

3. Valid license (ACTIVE, GRACE_PERIOD, PAYMENT_REMINDER):
   - Full access to all EE features
   - Seat limits enforced
   - GRACE_PERIOD/PAYMENT_REMINDER are for notifications only, not blocking
"""

import logging
from collections.abc import Awaitable
from collections.abc import Callable

from fastapi import FastAPI
from fastapi import Request
from fastapi import Response


def add_license_enforcement_middleware(
    app: FastAPI, logger: logging.LoggerAdapter
) -> None:
    """License enforcement middleware is disabled by default.

    EE features are always available on self-hosted deployments.
    To re-enable enforcement, set LICENSE_ENFORCEMENT_ENABLED=true
    and ensure a valid license is present in the database.
    """
    logger.info(
        "License enforcement middleware disabled - EE features always enabled"
    )

    @app.middleware("http")
    async def enforce_license(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """All requests pass through when enforcement is disabled."""
        return await call_next(request)

