from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from onyx.error_handling.error_codes import OnyxErrorCode
from onyx.error_handling.exceptions import OnyxError


class TestClaimLicense:
    @pytest.mark.asyncio
    @patch("ee.onyx.server.license.api.MULTI_TENANT", False)
    @patch("ee.onyx.server.license.api.SELF_HOSTED_ONLINE_BILLING_ENABLED", False)
    async def test_rejects_when_self_hosted_online_billing_disabled(self) -> None:
        from ee.onyx.server.license.api import claim_license

        with pytest.raises(OnyxError) as exc_info:
            await claim_license(
                session_id="checkout-session",
                _=MagicMock(),
                db_session=MagicMock(),
            )

        assert exc_info.value.error_code is OnyxErrorCode.VALIDATION_ERROR
        assert "Online billing is disabled" in exc_info.value.detail
