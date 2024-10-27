from WAB import main, Client
import demistomock as demisto
from CommonServerPython import *
from typing import Any


class Settable:
    pass


class Counter:
    def __init__(self) -> None:
        self.count = 0


def test_timeout(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "timeout": "0"
        },
    )
    try:
        main()
    except ValueError:
        pass
    else:
        raise AssertionError("zero timeout should not be allowed")


def test_test_module(mocker):
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})
    results_mock = mocker.patch.object(demisto, "results")

    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "1.1.1.1",
            "verify_certificate": False,
            "api_version": "v3.12",
            "auth_key": "key",
            "auth_user": "user"
        }
    )

    def mock_http_request(*args, **kwargs):
        assert args[0] == "get"
        assert args[1] == ""
        assert kwargs["headers"].get("X-Auth-Key") == "key"
        assert kwargs["headers"].get("X-Auth-User") == "user"

        mock: Any = Settable()

        mock.status_code = 204
        mock.headers = {}

        return mock

    mocker.patch.object(BaseClient, "_http_request", side_effect=mock_http_request)

    main()

    results_mock.assert_called_once_with("ok")


def test_login(mocker):
    mocker.patch.object(demisto, "command", return_value="wab-get-current-serial-configuration-number-of-bastion")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "results")

    params = {
        "url": "1.1.1.1",
        "verify_certificate": False,
        "api_version": "v3.12",
        "auth_key": "key",
        "auth_user": "user"
    }

    mocker.patch.object(
        demisto,
        "params",
        return_value=params
    )

    integration_context = {}

    def set_context(new_context, *args):
        integration_context.clear()
        integration_context.update(new_context)

    mocker.patch.object(demisto, "getIntegrationContextVersioned", return_value=integration_context)
    mocker.patch.object(demisto, "setIntegrationContextVersioned", side_effect=set_context)
    mocker.patch.object(demisto, "getIntegrationContext", return_value=integration_context)
    mocker.patch.object(demisto, "setIntegrationContext", side_effect=set_context)

    c = Counter()

    def mock_http_request(*args, **kwargs):
        c.count += 1
        mock: Any = Settable()
        mock.headers = {}

        if c.count == 1:
            # API key auth
            assert kwargs["headers"].get("X-Auth-Key") == "key"
            assert kwargs["headers"].get("X-Auth-User") == "user"

            mock.status_code = 200
            mock.headers["Set-Cookie"] = "session=foobar"
            mock.json = lambda: {"configuration_number": "3615"}

        elif c.count == 2:
            # session token auth
            assert integration_context.get("session_token") == "session=foobar"
            assert integration_context.get("last_request_at") > 0

            assert kwargs["headers"].get("Cookies") == "session=foobar"
            assert kwargs["headers"].get("X-Auth-User") is None
            assert kwargs["headers"].get("X-Auth-Key") is None

            mock.status_code = 401

            kwargs["error_handler"](mock)

        elif c.count == 3:
            # password auth
            assert not integration_context
            assert kwargs.get("auth") == ("user", "key")
            assert kwargs["headers"].get("X-Auth-User") is None
            assert kwargs["headers"].get("X-Auth-Key") is None

            mock.status_code = 200
            mock.headers["Set-Cookie"] = "session=foobaz"
            mock.json = lambda: {"configuration_number": "3615"}

        else:
            raise ValueError("counter: " + str(c.count))

        return mock

    mocker.patch.object(BaseClient, "_http_request", side_effect=mock_http_request)

    main()
    assert c.count == 1

    params["is_password"] = True

    main()

    assert c.count == 3
    assert integration_context.get("session_token") == "session=foobaz"


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
            "timeout": "50"
        },
    )
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "command", return_value="wab-get-device")

    mock_result = mocker.patch("WAB.return_results")

    def mock_http_request(self: BaseClient, *args, **kwargs):
        assert args[0] == "get"
        assert args[1] == "/devices/012345"
        assert kwargs["headers"].get("X-Auth-Key") == "key"
        assert kwargs["headers"].get("X-Auth-User") == "user"
        assert self.timeout == 50

        mock: Any = Settable()

        mock.status_code = 200
        mock.headers = {}
        mock.json = lambda: {"device_name": "my device", "host": "1.2.3.4"}

        return mock

    mocker.patch.object(BaseClient, "_http_request", autospec=True, side_effect=mock_http_request)

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
            "timeout": "50"
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


command_names = [
    "wab-add-account-in-global-domain",
    "wab-add-account-to-local-domain-of-application",
    "wab-add-account-to-local-domain-on-device",
    "wab-add-authorization",
    "wab-add-connection-policy",
    "wab-add-device",
    "wab-add-mapping-in-domain",
    "wab-add-mapping-in-group",
    "wab-add-notification",
    "wab-add-password-change-policy",
    "wab-add-password-target-to-target-group",
    "wab-add-restriction-to-target-group",
    "wab-add-restriction-to-usergroup",
    "wab-add-service-in-device",
    "wab-add-session-target-to-target-group",
    "wab-add-target-group",
    "wab-add-timeframe",
    "wab-add-timeframe-period",
    "wab-add-user",
    "wab-cancel-accepted-approval",
    "wab-cancel-approval-request",
    "wab-cancel-scan-job",
    "wab-change-password-or-ssh-key-of-account",
    "wab-check-if-approval-is-required-for-target",
    "wab-create-session-request",
    "wab-delete-account",
    "wab-delete-account-from-global-domain",
    "wab-delete-account-from-local-domain-of-application",
    "wab-delete-account-from-local-domain-of-device",
    "wab-delete-application",
    "wab-delete-authorization",
    "wab-delete-connection-policy",
    "wab-delete-device",
    "wab-delete-mapping-of-domain",
    "wab-delete-mapping-of-user-group",
    "wab-delete-notification",
    "wab-delete-password-change-policy",
    "wab-delete-pending-or-live-session-request",
    "wab-delete-resource-from-global-domain-account",
    "wab-delete-restriction-from-targetgroup",
    "wab-delete-restriction-from-usergroup",
    "wab-delete-scan",
    "wab-delete-service-from-device",
    "wab-delete-target-from-group",
    "wab-delete-target-group",
    "wab-delete-timeframe",
    "wab-edit-account-in-global-domain",
    "wab-edit-account-on-local-domain-of-application",
    "wab-edit-account-on-local-domain-of-device",
    "wab-edit-application",
    "wab-edit-authorization",
    "wab-edit-connection-policy",
    "wab-edit-device",
    "wab-edit-mapping-of-domain",
    "wab-edit-mapping-of-user-group",
    "wab-edit-mappings-of-domain",
    "wab-edit-notification",
    "wab-edit-password-change-policy",
    "wab-edit-restriction-from-targetgroup",
    "wab-edit-restriction-from-usergroup",
    "wab-edit-scan",
    "wab-edit-service-of-device",
    "wab-edit-session",
    "wab-edit-target-group",
    "wab-edit-timeframe",
    "wab-edit-user",
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
    "wab-get-cluster",
    "wab-get-clusters",
    "wab-get-connection-policies",
    "wab-get-connection-policy",
    "wab-get-current-serial-configuration-number-of-bastion",
    "wab-get-device",
    "wab-get-devices",
    "wab-get-external-authentication-group-mappings",
    "wab-get-global-domain",
    "wab-get-global-domains",
    "wab-get-information-about-wallix-bastion-license",
    "wab-get-latest-snapshot-of-running-session",
    "wab-get-ldap-user-of-domain",
    "wab-get-ldap-users-of-domain",
    "wab-get-local-domain-data-for-application",
    "wab-get-local-domain-of-device",
    "wab-get-local-domains-data-for-application",
    "wab-get-local-domains-of-device",
    "wab-get-mapping-of-domain",
    "wab-get-mapping-of-user-group",
    "wab-get-mappings-of-domain",
    "wab-get-mappings-of-user-group",
    "wab-get-notification",
    "wab-get-notifications",
    "wab-get-object-to-onboard",
    "wab-get-one-account",
    "wab-get-one-account-on-device-local-domain",
    "wab-get-password-change-policies",
    "wab-get-password-change-policy",
    "wab-get-password-for-target",
    "wab-get-passwordrights",
    "wab-get-passwordrights-user-name",
    "wab-get-profile",
    "wab-get-profiles",
    "wab-get-scan",
    "wab-get-scanjob",
    "wab-get-scanjobs",
    "wab-get-scans",
    "wab-get-service-of-device",
    "wab-get-services-of-device",
    "wab-get-session-metadata",
    "wab-get-session-sharing-requests",
    "wab-get-sessionrights",
    "wab-get-sessionrights-user-name",
    "wab-get-sessions",
    "wab-get-status-of-trace-generation",
    "wab-get-target-by-type",
    "wab-get-target-group",
    "wab-get-target-group-restriction",
    "wab-get-target-group-restrictions",
    "wab-get-target-groups",
    "wab-get-timeframe",
    "wab-get-timeframes",
    "wab-get-user",
    "wab-get-user-group",
    "wab-get-user-group-restriction",
    "wab-get-user-group-restrictions",
    "wab-get-user-groups",
    "wab-get-users",
    "wab-get-version",
    "wab-get-wallix-bastion-usage-statistics",
    "wab-getx509-configuration-infos",
    "wab-make-new-approval-request-to-access-target",
    "wab-notify-approvers-linked-to-approval-assignment",
    "wab-notify-approvers-linked-to-approval-request",
    "wab-post-logsiem",
    "wab-release-passwords-for-target",
    "wab-reply-to-approval-request",
    "wab-resetx509-configuration",
    "wab-revoke-certificate-of-device",
    "wab-start-scan-job-manually",
    "wab-updatex509-configuration",
    "wab-uploadx509-configuration"
]
