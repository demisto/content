import pytest
from MicrosoftApiModule import AZURE_WORLDWIDE_CLOUD


users_list_mock = [
    {
        "id": "08779ba7-f3ed-4344-b9d7-98b9911ea8a8",
        "displayName": "Test User",
        "jobTitle": "Magician",
        "mobilePhone": None,
        "mail": None,
    },
    {
        "id": "670edadc-0197-45b0-90e6-ee061e25ab73",
        "displayName": "Test1",
        "jobTitle": "TESTER",
        "mobilePhone": "050505050",
        "mail": None,
        "@removed": {"reason": "changed"},
    },
]

expected_outputs = [
    {
        "ID": "08779ba7-f3ed-4344-b9d7-98b9911ea8a8",
        "DisplayName": "Test User",
        "JobTitle": "Magician",
        "MobilePhone": None,
        "Mail": None,
    },
    {
        "ID": "670edadc-0197-45b0-90e6-ee061e25ab73",
        "DisplayName": "Test1",
        "JobTitle": "TESTER",
        "MobilePhone": "050505050",
        "Mail": None,
        "Status": "deleted",
    },
]


def test_camel_case_to_readable():
    from MicrosoftGraphUser import camel_case_to_readable

    assert camel_case_to_readable("id") == "ID"
    assert camel_case_to_readable("createdDateTime") == "Created Date Time"


def test_parse_outputs():
    from MicrosoftGraphUser import parse_outputs

    _, parsed_outputs = parse_outputs(users_list_mock)
    assert parsed_outputs == expected_outputs


def test_get_user_command_404_response(mocker):
    """
    Given:
        - The get_user_command
    When:
        - The returned response is a 404 - not found error.
    Then:
        - Validate that the error is handled and that the human readable indicates an error.
    """
    from MicrosoftGraphUser import MsGraphClient, get_user_command
    from MicrosoftApiModule import MicrosoftClient, BaseClient
    from requests.models import Response

    client = MsGraphClient(
        "tenant_id",
        "auth_id",
        "enc_key",
        "app_name",
        "base_url",
        "verify",
        "proxy",
        "self_deployed",
        "redirect_uri",
        "auth_code",
        True,
        azure_cloud=AZURE_WORLDWIDE_CLOUD,
    )
    error_404 = Response()
    error_404._content = (
        b'{"error": {"code": "Request_ResourceNotFound", "message": "Resource ' b'"NotExistingUser does not exist."}}'
    )
    error_404.status_code = 404
    mocker.patch.object(BaseClient, "_http_request", return_value=error_404)
    mocker.patch.object(MicrosoftClient, "get_access_token")
    hr, _, _ = get_user_command(client, {"user": "NotExistingUser"})  # client.get_user('user', 'properties')
    assert "User NotExistingUser was not found" in hr


def test_get_user_command_url_saved_chars(mocker):
    """
    Given:
        - The get_user_command
    When:
        - The returned response is a 404 - not found error.
    Then:
        - Validate that the error is handled and that the human readable indicates an error.
    """
    from MicrosoftGraphUser import MsGraphClient, get_user_command
    from MicrosoftApiModule import MicrosoftClient, BaseClient

    user_name = "dbot^"
    client = MsGraphClient(
        "tenant_id",
        "auth_id",
        "enc_key",
        "app_name",
        "http://base_url",
        "verify",
        "proxy",
        "self_deployed",
        "redirect_uri",
        "auth_code",
        False,
        azure_cloud=AZURE_WORLDWIDE_CLOUD,
    )
    http_mock = mocker.patch.object(BaseClient, "_http_request")
    mocker.patch.object(MicrosoftClient, "get_access_token")
    hr, _, _ = get_user_command(client, {"user": user_name})
    assert http_mock.call_args[1]["url_suffix"] == "users/dbot%5E"


def test_get_unsupported_chars_in_user():
    """
    Given:
        - User with unsupported characters
    When:
        - Calling get_unsupported_chars_in_user
    Then:
        - Validate special characters were extracted
    """
    from MicrosoftGraphUser import get_unsupported_chars_in_user

    invalid_chars = "%&*+/=?`{|}"
    invalid_user = f"demi{invalid_chars}sto"

    assert len(get_unsupported_chars_in_user(invalid_user).difference(set(invalid_chars))) == 0


def test_suppress_errors(mocker):
    from MicrosoftGraphUser import (
        unblock_user_command,
        disable_user_account_command,
        update_user_command,
        change_password_user_command,
        delete_user_command,
        get_direct_reports_command,
        get_manager_command,
        assign_manager_command,
        revoke_user_session_command,
        MsGraphClient,
    )
    from MicrosoftApiModule import NotFoundError

    TEST_SUPPRESS_ERRORS = [
        {
            "fun": unblock_user_command,
            "mock_fun": "unblock_user",
            "mock_value": NotFoundError("123456789"),
            "args": {"user": "123456789"},
            "expected_result": "#### User -> 123456789 does not exist",
        },
        {
            "fun": disable_user_account_command,
            "mock_fun": "disable_user_account_session",
            "mock_value": NotFoundError("123456789"),
            "args": {"user": "123456789"},
            "expected_result": "#### User -> 123456789 does not exist",
        },
        {
            "fun": update_user_command,
            "mock_fun": "update_user",
            "mock_value": NotFoundError("123456789"),
            "args": {"user": "123456789", "updated_fields": "test1=test2"},
            "expected_result": "#### User -> 123456789 does not exist",
        },
        {
            "fun": change_password_user_command,
            "mock_fun": "password_change_user",
            "mock_value": NotFoundError("123456789"),
            "args": {"user": "123456789"},
            "expected_result": "#### User -> 123456789 does not exist",
        },
        {
            "fun": delete_user_command,
            "mock_fun": "delete_user",
            "mock_value": NotFoundError("123456789"),
            "args": {"user": "123456789"},
            "expected_result": "#### User -> 123456789 does not exist",
        },
        {
            "fun": get_direct_reports_command,
            "mock_fun": "get_direct_reports",
            "mock_value": NotFoundError("123456789"),
            "args": {"user": "123456789"},
            "expected_result": "#### User -> 123456789 does not exist",
        },
        {
            "fun": get_manager_command,
            "mock_fun": "get_manager",
            "mock_value": NotFoundError("123456789"),
            "args": {"user": "123456789"},
            "expected_result": "#### User -> 123456789 does not exist",
        },
        {
            "fun": assign_manager_command,
            "mock_fun": "assign_manager",
            "mock_value": NotFoundError("123456789"),
            "args": {"user": "123456789"},
            "expected_result": "#### User -> 123456789 does not exist",
        },
        {
            "fun": assign_manager_command,
            "mock_fun": "assign_manager",
            "mock_value": NotFoundError("123456789"),
            "args": {"manager": "123456789"},
            "expected_result": "#### Manager -> 123456789 does not exist",
        },
        {
            "fun": revoke_user_session_command,
            "mock_fun": "revoke_user_session",
            "mock_value": NotFoundError("123456789"),
            "args": {"user": "123456789"},
            "expected_result": "#### User -> 123456789 does not exist",
        },
    ]

    client = MsGraphClient(
        base_url="https://graph.microsoft.com/v1.0",
        tenant_id="tenant-id",
        auth_id="auth_and_token_url",
        enc_key="enc_key",
        app_name="ms-graph-groups",
        verify="use_ssl",
        proxy="proxies",
        self_deployed="self_deployed",
        handle_error=True,
        auth_code="",
        redirect_uri="",
        azure_cloud=AZURE_WORLDWIDE_CLOUD,
    )
    for test in TEST_SUPPRESS_ERRORS:
        mocker.patch.object(client, test["mock_fun"], side_effect=test["mock_value"])
        results, _, _ = test["fun"](client, test["args"])
        assert results == test["expected_result"]


USERS_LIST_MOCK = [
    {
        "ID": "08779ba7-f3ed-4344-b9d7-98b9911ea8a8",
        "DisplayName": "Test User",
        "UserPrincipalName": None,
        "JobTitle": "Magician",
        "MobilePhone": None,
        "Mail": None,
    },
    {
        "ID": "670edadc-0197-45b0-90e6-ee061e25ab73",
        "DisplayName": "Test1",
        "UserPrincipalName": "PrincipalTest",
        "JobTitle": "TESTER",
        "MobilePhone": "050505050",
        "Mail": "test@test.com",
    },
]
USERS_JSON_MOCK = {
    "ID": "6705dadc-0197-45b4-9fe6-ee061e25abf7",
    "DisplayName": "Test2",
    "UserPrincipalName": "PrincipalTest2",
    "JobTitle": "TESTER2",
    "MobilePhone": "02020202",
    "Mail": "test2@test2.com",
}


@pytest.mark.parametrize("users_mock", [(USERS_LIST_MOCK), (USERS_JSON_MOCK)])
def test_create_account_outputs(users_mock):
    from MicrosoftGraphUser import create_account_outputs

    results = create_account_outputs(users_mock)

    if not isinstance(users_mock, list):
        users_mock = [users_mock]

    for i in range(len(results)):
        assert results[i]["DisplayName"] == users_mock[i]["DisplayName"]
        assert results[i]["Email"]["Address"] == users_mock[i]["Mail"]
        assert results[i]["Username"] == users_mock[i]["UserPrincipalName"]


@pytest.mark.parametrize(
    "user, updated_fields, updated_fields_delimiter, expected_request_params",
    [
        # A case with a single field to update.
        (
            "1875cf67-ebf9-4a29-b5e2-54e36591296e",
            "displayName=test_name1",
            None,
            {
                "json_data": {"displayName": "test_name1"},
                "method": "PATCH",
                "resp_type": "text",
                "url_suffix": "users/1875cf67-ebf9-4a29-b5e2-54e36591296e",
            },
        ),
        # A case with multiple fields to update.
        (
            "1875cf67-ebf9-4a29-b5e2-54e36591296e",
            "displayName=test_name2,jobTitle=test_title,phoneNumber=123456789",
            None,
            {
                "json_data": {"displayName": "test_name2", "jobTitle": "test_title", "phoneNumber": "123456789"},
                "method": "PATCH",
                "resp_type": "text",
                "url_suffix": "users/1875cf67-ebf9-4a29-b5e2-54e36591296e",
            },
        ),
        # A case with multiple fields to update and a custom delimiter.
        (
            "1875cf67-ebf9-4a29-b5e2-54e36591296e",
            "displayName=test_name3;jobTitle=test_title;phoneNumber=123456789",
            ";",
            {
                "json_data": {"displayName": "test_name3", "jobTitle": "test_title", "phoneNumber": "123456789"},
                "method": "PATCH",
                "resp_type": "text",
                "url_suffix": "users/1875cf67-ebf9-4a29-b5e2-54e36591296e",
            },
        ),
    ],
)
def test_update_user_command(
    mocker, user: str, updated_fields: str, updated_fields_delimiter: str, expected_request_params: dict
):
    """
    Given:
        - User to update with fields to update.
    When:
        - Calling update_user.
    Then:
        - Ensure the user is updated.
    """
    from MicrosoftGraphUser import MsGraphClient, update_user_command

    client = MsGraphClient(
        base_url="https://graph.microsoft.com/v1.0",
        tenant_id="tenant-id",
        auth_id="auth_and_token_url",
        enc_key="enc_key",
        app_name="ms-graph-groups",
        verify="use_ssl",
        proxy="proxies",
        self_deployed="self_deployed",
        handle_error=True,
        auth_code="",
        redirect_uri="",
        azure_cloud=AZURE_WORLDWIDE_CLOUD,
    )
    request = mocker.patch.object(client.ms_client, "http_request", return_value={})
    mocker.patch.object(client, "get_user", return_value={})

    args = {"user": user, "updated_fields": updated_fields}

    if updated_fields_delimiter is not None:
        args["updated_fields_delimiter"] = updated_fields_delimiter

    update_user_command(client=client, args=args)

    request.assert_called_with(**expected_request_params)


@pytest.mark.parametrize(argnames="client_id", argvalues=["test_client_id", None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
    Given:
        - Managed Identities client id for authentication.
    When:
        - Calling test_module.
    Then:
        - Ensure the output are as expected.
    """
    from MicrosoftGraphUser import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import demistomock as demisto
    import re

    mock_token = {"access_token": "test_token", "expires_in": "86400"}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f"^{Resources.graph}.*"), json={})

    params = {"managed_identities_client_id": {"password": client_id}, "use_managed_identities": "True", "host": Resources.graph}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "results", return_value=params)
    mocker.patch("MicrosoftApiModule.get_integration_context", return_value={})

    main()

    assert "ok" in demisto.results.call_args[0][0]["Contents"]
    qs = get_mock.last_request.qs
    assert qs["resource"] == [Resources.graph]
    assert client_id and qs["client_id"] == [client_id] or "client_id" not in qs


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function msgraph-user-generate-login-url
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from MicrosoftGraphUser import main, Scopes
    import MicrosoftGraphUser

    redirect_uri = "redirect_uri"
    tenant_id = "tenant_id"
    client_id = "client_id"
    mocked_params = {
        "redirect_uri": redirect_uri,
        "auth_type": "Authorization Code",
        "self_deployed": "True",
        "creds_tenant_id": {"password": tenant_id},
        "creds_auth_id": {"password": client_id},
        "creds_enc_key": {"password": "client_secret"},
    }
    mocker.patch.object(demisto, "params", return_value=mocked_params)
    mocker.patch.object(demisto, "command", return_value="msgraph-user-generate-login-url")
    mocker.patch.object(MicrosoftGraphUser, "return_results")

    # call
    main()

    # assert
    expected_url = (
        f"[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?"
        f"response_type=code&scope=offline_access%20{Scopes.graph}"
        f"&client_id={client_id}&redirect_uri={redirect_uri})"
    )
    res = MicrosoftGraphUser.return_results.call_args[0][0].readable_output
    assert expected_url in res


@pytest.mark.parametrize(
    "grant_type, self_deployed, expected_result, should_raise",
    [
        ("authorization_code", False, "ok", False),
        ("authorization_code", True, "ok", True),
        ("client_credentials", False, "ok", False),
        ("client_credentials", True, "```✅ Success!```", False),
    ],
)
def test_test_function(mocker, grant_type, self_deployed, expected_result, should_raise):
    """
    Given:
        - Authentication method and self_deployed information.
    When:
        - Calling test_module.
    Then:
        - Ensure the output are as expected.
    """
    import demistomock as demisto
    from MicrosoftGraphUser import test_function, MsGraphClient

    client = MsGraphClient(
        base_url="https://graph.microsoft.com/v1.0",
        tenant_id="tenant-id",
        auth_id="auth_and_token_url",
        enc_key="enc_key",
        app_name="user",
        verify="use_ssl",
        proxy="proxies",
        self_deployed=self_deployed,
        handle_error=True,
        auth_code="",
        redirect_uri="",
        azure_cloud=AZURE_WORLDWIDE_CLOUD,
    )

    client.ms_client.grant_type = grant_type
    mocker.patch.object(demisto, "params", return_value={"self_deployed": self_deployed})
    mocker.patch.object(client.ms_client, "http_request")

    if should_raise:
        with pytest.raises(Exception) as exc:
            test_function(client, {})
            assert "Please enable the integration" in str(exc)
    else:
        result = test_function(client, {})
        assert result[0] == expected_result
