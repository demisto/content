from WAB import main, Client
import demistomock as demisto
from CommonServerPython import BaseClient
from typing import Any


class Settable:
    pass


def test_wab_get_device(mocker):
    mocker.patch.object(demisto, "args", return_value={"device_id": "012345"})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "1.1.1.1",
            "verify_certificate": False,
            "api_version": "v3.12",
            "auth_key": "key",
            "auth_user": "user",
        },
    )
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="wab-get-device")

    mock_result = mocker.patch("WAB.return_results")

    def mock_http_request(*args, **kwargs):
        assert args[0] == "get"
        assert args[1] == "devices/012345"
        assert kwargs["headers"].get("X-Auth-Key") == "key"
        assert kwargs["headers"].get("X-Auth-User") == "user"

        mock: Any = Settable()

        mock.status_code = 200
        mock.headers = {}
        mock.json = lambda: {"device_name": "my device", "host": "1.2.3.4"}

        return mock

    mocker.patch.object(BaseClient, "_http_request", side_effect=mock_http_request)

    main()

    assert mock_result.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = mock_result.call_args[0]

    assert len(results) == 1

    result = results[0]

    assert result.outputs_prefix == "WAB.device_get"
    assert result.outputs_key_field == "id"

    assert result.outputs["device_name"] == "my device"
    assert result.outputs["host"] == "1.2.3.4"


def test_commands(mocker):
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "1.1.1.1",
            "verify_certificate": False,
            "api_version": "v3.12",
            "auth_key": "key",
            "auth_user": "user",
        },
    )

    mocker.patch.object(Client, "_http_request", return_value={})

    for name in command_names:
        mocker.patch.object(demisto, "results")
        mocker.patch.object(demisto, "command", return_value=name)

        mock_result = mocker.patch("WAB.return_results")

        main()

        assert mock_result.call_count == 1


command_names = {
    "wab-add-account-in-global-domain",
    "wab-add-account-to-local-domain-of-application",
    "wab-add-account-to-local-domain-on-device",
    "wab-add-authorization",
    "wab-add-device",
    "wab-add-notification",
    "wab-add-user",
    "wab-cancel-accepted-approval",
    "wab-cancel-approval-request",
    "wab-cancel-scan-job",
    "wab-check-if-approval-is-required-for-target",
    "wab-create-session-request",
    "wab-delete-account",
    "wab-delete-account-from-global-domain",
    "wab-delete-account-from-local-domain-of-application",
    "wab-delete-account-from-local-domain-of-device",
    "wab-delete-application",
    "wab-delete-authorization",
    "wab-delete-device",
    "wab-delete-notification",
    "wab-delete-pending-or-live-session-request",
    "wab-delete-resource-from-global-domain-account",
    "wab-delete-service-from-device",
    "wab-edit-account-in-global-domain",
    "wab-edit-account-on-local-domain-of-application",
    "wab-edit-account-on-local-domain-of-device",
    "wab-edit-application",
    "wab-edit-authorization",
    "wab-edit-device",
    "wab-edit-notification",
    "wab-edit-service-of-device",
    "wab-edit-session",
    "wab-extend-duration-time-to-get-passwords-for-target",
    "wab-generate-trace-for-session",
    "wab-get-account-of-global-domain",
    "wab-get-account-reference",
    "wab-get-account-references",
    "wab-get-accounts-of-global-domain",
    "wab-get-all-accounts",
    "wab-get-all-accounts-on-device-local-domain",
    "wab-get-application",
    "wab-get-application-account",
    "wab-get-application-accounts",
    "wab-get-applications",
    "wab-get-approval-request-pending-for-user",
    "wab-get-approvals",
    "wab-get-approvals-for-all-approvers",
    "wab-get-approvals-for-approver",
    "wab-get-auth-domain",
    "wab-get-auth-domains",
    "wab-get-authentication",
    "wab-get-authentications",
    "wab-get-authorization",
    "wab-get-authorizations",
    "wab-get-certificate-on-device",
    "wab-get-certificates-on-device",
    "wab-get-checkout-policies",
    "wab-get-checkout-policy",
    "wab-get-device",
    "wab-get-devices",
    "wab-get-global-domain",
    "wab-get-global-domains",
    "wab-get-information-about-wallix-bastion-license",
    "wab-get-latest-snapshot-of-running-session",
    "wab-get-ldap-user-of-domain",
    "wab-get-ldap-users-of-domain",
    "wab-get-metadata-of-one-or-multiple-sessions",
    "wab-get-notification",
    "wab-get-notifications",
    "wab-get-object-to-onboard",
    "wab-get-one-account",
    "wab-get-one-account-on-device-local-domain",
    "wab-get-profile",
    "wab-get-profiles",
    "wab-get-scan",
    "wab-get-scanjob",
    "wab-get-scanjobs",
    "wab-get-scans",
    "wab-get-service-of-device",
    "wab-get-services-of-device",
    "wab-get-session-sharing-requests",
    "wab-get-sessionrights",
    "wab-get-sessionrights-user-name",
    "wab-get-sessions",
    "wab-get-status-of-trace-generation",
    "wab-get-target-by-type",
    "wab-get-target-group",
    "wab-get-target-groups",
    "wab-get-user",
    "wab-get-user-group",
    "wab-get-user-groups",
    "wab-get-users",
    "wab-get-wallix-bastion-usage-statistics",
    "wab-make-new-approval-request-to-access-target",
    "wab-release-passwords-for-target",
    "wab-reply-to-approval-request",
    "wab-revoke-certificate-of-device",
    "wab-start-scan-job-manually",
}
