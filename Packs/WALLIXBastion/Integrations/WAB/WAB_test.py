from WAB import main, Client
import demistomock as demisto
from CommonServerPython import *
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
        assert args[1] == "/devices/012345"
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
    """test that all commands names match an existing method."""
    mocker.patch.object(demisto, "args", return_value={
        "session_account_type": "account"  # required for add_session_target_to_target_group
    })
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

    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_result = mocker.patch.object(demisto, "results")
    main()
    assert mock_result.call_count == 1

    for name in command_names:
        mocker.patch.object(demisto, "results")
        mocker.patch.object(demisto, "command", return_value=name)

        mock_result = mocker.patch("WAB.return_results")

        main()

        assert mock_result.call_count == 1

    for deprecated in deprecated_names:
        mocker.patch.object(demisto, "command", return_value=deprecated)

        mock_result = mocker.patch("WAB.return_results")
        main()

        assert mock_result.call_count == 1


deprecated_names = {
    "wab-get-metadata-of-one-or-multiple-sessions"
}

command_names = {
    "wab-add-session-target-to-target-group",
    "wab-add-password-target-to-target-group",
    "wab-add-restriction-to-target-group",
    "wab-get-account-references",
    "wab-get-account-reference",
    "wab-get-all-accounts",
    "wab-get-one-account",
    "wab-delete-account",
    "wab-get-application-accounts",
    "wab-add-account-to-local-domain-of-application",
    "wab-get-application-account",
    "wab-edit-account-on-local-domain-of-application",
    "wab-delete-account-from-local-domain-of-application",
    "wab-get-applications",
    "wab-get-application",
    "wab-edit-application",
    "wab-delete-application",
    "wab-get-approvals",
    "wab-get-approvals-for-all-approvers",
    "wab-reply-to-approval-request",
    "wab-get-approvals-for-approver",
    "wab-cancel-accepted-approval",
    "wab-get-approval-request-pending-for-user",
    "wab-make-new-approval-request-to-access-target",
    "wab-cancel-approval-request",
    "wab-notify-approvers-linked-to-approval-request",
    "wab-check-if-approval-is-required-for-target",
    "wab-get-auth-domains",
    "wab-get-auth-domain",
    "wab-get-authentications",
    "wab-get-authentication",
    "wab-get-authorizations",
    "wab-add-authorization",
    "wab-get-authorization",
    "wab-edit-authorization",
    "wab-delete-authorization",
    "wab-get-checkout-policies",
    "wab-get-checkout-policy",
    "wab-getx509-configuration-infos",
    "wab-uploadx509-configuration",
    "wab-updatex509-configuration",
    "wab-resetx509-configuration",
    "wab-get-current-serial-configuration-number-of-bastion",
    "wab-get-all-accounts-on-device-local-domain",
    "wab-add-account-to-local-domain-on-device",
    "wab-get-one-account-on-device-local-domain",
    "wab-edit-account-on-local-domain-of-device",
    "wab-delete-account-from-local-domain-of-device",
    "wab-get-certificates-on-device",
    "wab-get-certificate-on-device",
    "wab-revoke-certificate-of-device",
    "wab-get-services-of-device",
    "wab-get-service-of-device",
    "wab-edit-service-of-device",
    "wab-delete-service-from-device",
    "wab-get-devices",
    "wab-add-device",
    "wab-get-device",
    "wab-edit-device",
    "wab-delete-device",
    "wab-get-accounts-of-global-domain",
    "wab-add-account-in-global-domain",
    "wab-get-account-of-global-domain",
    "wab-edit-account-in-global-domain",
    "wab-delete-account-from-global-domain",
    "wab-delete-resource-from-global-domain-account",
    "wab-get-global-domains",
    "wab-get-global-domain",
    "wab-get-ldap-users-of-domain",
    "wab-get-ldap-user-of-domain",
    "wab-get-information-about-wallix-bastion-license",
    "wab-post-logsiem",
    "wab-get-notifications",
    "wab-add-notification",
    "wab-get-notification",
    "wab-edit-notification",
    "wab-delete-notification",
    "wab-get-object-to-onboard",
    "wab-get-profiles",
    "wab-get-profile",
    "wab-get-scanjobs",
    "wab-start-scan-job-manually",
    "wab-get-scanjob",
    "wab-cancel-scan-job",
    "wab-get-scans",
    "wab-get-scan",
    "wab-get-sessionrights",
    "wab-get-sessionrights-user-name",
    "wab-get-sessions",
    "wab-edit-session",
    "wab-get-session-metadata",
    "wab-get-session-sharing-requests",
    "wab-create-session-request",
    "wab-delete-pending-or-live-session-request",
    "wab-get-latest-snapshot-of-running-session",
    "wab-get-status-of-trace-generation",
    "wab-generate-trace-for-session",
    "wab-get-wallix-bastion-usage-statistics",
    "wab-get-target-groups",
    "wab-add-target-group",
    "wab-get-target-group",
    "wab-edit-target-group",
    "wab-delete-target-group",
    "wab-delete-target-from-group",
    "wab-get-user-groups",
    "wab-get-user-group",
    "wab-get-users",
    "wab-add-user",
    "wab-get-user",
    "wab-extend-duration-time-to-get-passwords-for-target",
    "wab-release-passwords-for-target",
    "wab-get-target-by-type",
    "wab-get-password-for-target",
    "wab-add-service-in-device"
}
