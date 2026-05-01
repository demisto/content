import json

import demistomock as demisto  # noqa: F401
from VerifySupportTicketPermission import verify_support_ticket_permission


def _mock_api(mocker, user_csp_permission: bool, tenant_entitlement_check: bool):
    """Helper to mock demisto._apiCall with the given permission values."""
    reply = {
        "reply": {
            "user_csp_permission": user_csp_permission,
            "tenant_entitlement_check": tenant_entitlement_check,
        }
    }
    mocker.patch.object(
        demisto,
        "_apiCall",
        return_value={"data": json.dumps(reply)},
    )


def test_verify_permission_granted(mocker):
    """GIVEN:
        Both user_csp_permission and tenant_entitlement_check are True.
    WHEN:
        verify_support_ticket_permission is called.
    THEN:
        has_permission is True and no Error key is set.
    """
    _mock_api(mocker, user_csp_permission=True, tenant_entitlement_check=True)

    result = verify_support_ticket_permission()

    assert result.outputs_prefix == "Core.SupportTicketPermission"
    assert result.outputs["has_permission"] is True
    assert result.outputs["user_csp_permission"] is True
    assert result.outputs["tenant_entitlement_check"] is True
    assert "Error" not in result.outputs


def test_verify_permission_denied_no_csp(mocker):
    """GIVEN:
        user_csp_permission is False.
    WHEN:
        verify_support_ticket_permission is called.
    THEN:
        has_permission is False and Error mentions CSP permissions.
    """
    _mock_api(mocker, user_csp_permission=False, tenant_entitlement_check=True)

    result = verify_support_ticket_permission()

    assert result.outputs["has_permission"] is False
    assert "CSP permissions" in result.outputs["Error"]


def test_verify_permission_denied_expired_tenant(mocker):
    """GIVEN:
        tenant_entitlement_check is False.
    WHEN:
        verify_support_ticket_permission is called.
    THEN:
        has_permission is False and Error mentions expired support.
    """
    _mock_api(mocker, user_csp_permission=True, tenant_entitlement_check=False)

    result = verify_support_ticket_permission()

    assert result.outputs["has_permission"] is False
    assert "expired" in result.outputs["Error"]


def test_verify_permission_both_denied(mocker):
    """GIVEN:
        Both user_csp_permission and tenant_entitlement_check are False.
    WHEN:
        verify_support_ticket_permission is called.
    THEN:
        has_permission is False and Error mentions both issues.
    """
    _mock_api(mocker, user_csp_permission=False, tenant_entitlement_check=False)

    result = verify_support_ticket_permission()

    assert result.outputs["has_permission"] is False
    assert "expired" in result.outputs["Error"]
    assert "CSP permissions" in result.outputs["Error"]
