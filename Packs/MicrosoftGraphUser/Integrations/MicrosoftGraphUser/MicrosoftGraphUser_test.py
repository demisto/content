import pytest
from MicrosoftApiModule import AZURE_WORLDWIDE_CLOUD
import os
import time

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
    from MicrosoftApiModule import BaseClient, MicrosoftClient
    from MicrosoftGraphUser import MsGraphClient, get_user_command
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
        b'{"error": {"code": "Request_ResourceNotFound", "message": "Resource "NotExistingUser does not exist."}}'
    )
    error_404.status_code = 404
    mocker.patch.object(BaseClient, "_http_request", return_value=error_404)
    mocker.patch.object(MicrosoftClient, "get_access_token")
    output = get_user_command(client, {"user": "NotExistingUser"})  # client.get_user('user', 'properties')
    assert "User NotExistingUser was not found" in output.readable_output


def test_get_user_command_url_saved_chars(mocker):
    """
    Given:
        - The get_user_command
    When:
        - The returned response is a 404 - not found error.
    Then:
        - Validate that the error is handled and that the human readable indicates an error.
    """
    from MicrosoftApiModule import BaseClient, MicrosoftClient
    from MicrosoftGraphUser import MsGraphClient, get_user_command

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
    _ = get_user_command(client, {"user": user_name})
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
    result = get_unsupported_chars_in_user(invalid_user)
    assert len(result.difference(set(invalid_chars))) == 0, "All invalid characters should be extracted."

    # Test case with None as user
    result = get_unsupported_chars_in_user(None)
    assert result == set(), "Expected an empty set when user is None."

    # Test case with an empty string as user
    result = get_unsupported_chars_in_user("")
    assert result == set(), "Expected an empty set when user is an empty string."


def test_suppress_errors(mocker):
    from MicrosoftApiModule import NotFoundError
    from MicrosoftGraphUser import (
        MsGraphClient,
        assign_manager_command,
        change_password_user_saas_command,
        delete_user_command,
        disable_user_account_command,
        get_direct_reports_command,
        get_manager_command,
        revoke_user_session_command,
        unblock_user_command,
        update_user_command,
        list_tap_policy_command,
        delete_tap_policy_command,
        create_tap_policy_command,
    )

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
            "fun": change_password_user_saas_command,
            "mock_fun": "password_change_user_saas",
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
        {
            "fun": list_tap_policy_command,
            "mock_fun": "list_tap_policy",
            "mock_value": NotFoundError("The specified user could not be found."),
            "args": {"user_id": "123456789"},
            "expected_result": "#### User -> 123456789 does not exist",
        },
        {
            "fun": delete_tap_policy_command,
            "mock_fun": "delete_tap_policy",
            "mock_value": NotFoundError("The specified user could not be found."),
            "args": {"user_id": "123456789", "policy_id": "987654321"},
            "expected_result": "#### User -> 123456789 does not exist",
        },
        {
            "fun": create_tap_policy_command,
            "mock_fun": "create_tap_policy",
            "mock_value": NotFoundError("The specified user could not be found."),
            "args": {"user_id": "123456789", "zip_password": "12345"},
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
        results = test["fun"](client, test["args"])
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
    import re

    import demistomock as demisto
    from MicrosoftGraphUser import MANAGED_IDENTITIES_TOKEN_URL, Resources, main

    mock_token = {"access_token": "test_token", "expires_in": "86400"}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f"^{Resources.graph}.*"), json={})

    params = {"managed_identities_client_id": {"password": client_id}, "use_managed_identities": "True", "host": Resources.graph}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "results", return_value=params)
    mocker.patch("MicrosoftApiModule.get_integration_context", return_value={})

    main()

    assert "ok" in demisto.results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs["resource"] == [Resources.graph]
    assert (client_id and qs["client_id"] == [client_id]) or "client_id" not in qs


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
    import MicrosoftGraphUser
    from MicrosoftGraphUser import Scopes, main

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
    from MicrosoftGraphUser import MsGraphClient, test_function

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
        assert result == expected_result


def test_create_zip_with_password():
    """
    Tests the creation of a password-protected ZIP file containing a Temporary Access Pass (TAP) password.
    Validates that the correct TAP password is stored in the ZIP file, and cleans up any files created during the test.

    Given:
        - A generated TAP password, a password for protected-zip file, file names.
    When:
        - Running the generate_password_protected_zip function.
    Then:
        1. Generates a password protected zip file, that will include the password of the new TAP.
        2. Verifies that the returned 'File' field matches the expected ZIP file name - TAPPolicyInfo.zip.
        3. Confirms that the 'ContentsFormat' field in the result is 'text'.
        3. Opens the zip file using the given password by the user.
        4. Validates the password inside 'TAPPolicyPass.txt' matches the generated TAP password.
        5. Clean all the encrypted files created during the process.
    """
    from pyzipper import AESZipFile, ZIP_DEFLATED, WZ_AES
    from MicrosoftGraphUser import generate_password_protected_zip

    def clean_up_files(created_time):
        cwd = os.getcwd()
        for filename in os.listdir(cwd):
            file_path = os.path.join(cwd, filename)
            if os.path.isfile(file_path):
                file_creation_time = os.path.getctime(file_path)
                if file_creation_time > created_time:
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        pytest.fail(f"Error removing {file_path}: {e}")

    generated_tap_password = "test_password_123"
    zip_password = "kldsjflk453lksdf"
    zip_file_name = os.path.join(os.getcwd(), "TAPPolicyInfo.zip")
    txt_file_name = "TAPPolicyPass.txt"
    start_time = time.time()

    zip_res = generate_password_protected_zip("TAPPolicyInfo.zip", zip_password, generated_tap_password)
    assert zip_res["File"] == "TAPPolicyInfo.zip"
    assert zip_res["ContentsFormat"] == "text"

    try:
        with AESZipFile(zip_file_name, mode="r", compression=ZIP_DEFLATED, encryption=WZ_AES) as zf:
            zf.pwd = bytes(zip_password, "utf-8")
            zip_content = zf.read(txt_file_name)
            assert zip_content.decode("utf-8") == generated_tap_password

    except Exception as e:
        pytest.fail(f"Unexpected error during ZIP file handling: {e}")

    finally:
        clean_up_files(start_time)


def test_create_tap_policy_command_failure_on_empty_response(mocker):
    """
    Tests the behavior of the create_tap_policy_command function when an empty response is returned
    from the Microsoft Graph API for creating a TAP policy.
    Verifies that the command correctly handles the failure and outputs an appropriate error message.

    Given:
        - A mock client instance for the Microsoft Graph API.
    When:
        - Running the create_tap_policy_command.
    Then:
        1. Verify that the human readable output is as expected.
        2. verify that the call count for the mocker was 1
    """
    from MicrosoftGraphUser import MsGraphClient, create_tap_policy_command

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

    args = {"user_id": "123456789", "zip_password": "12345"}

    mock_create_tap_policy = mocker.patch.object(client, "create_tap_policy", return_value=None)
    result = create_tap_policy_command(client, args)

    assert result.readable_output == "Failed to create TAP policy for user: 123456789."
    assert mock_create_tap_policy.call_count == 1


def test_delete_tap_policy_command_success(mocker):
    """
    Tests the behavior of the delete_tap_policy_command function.
    Validates that the human readable is as expected and the command returns CommandResults object.

    Given:
        - A mock client instance for the Microsoft Graph API.
    When:
        - Running the delete_tap_policy_command.
    Then:
        1. Verify that the human readable output is as expected.
    """
    from MicrosoftGraphUser import MsGraphClient, delete_tap_policy_command

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

    args = {"user_id": "123456789", "policy_id": "987654321"}

    mocker.patch.object(client, "delete_tap_policy", return_value=None)
    result = delete_tap_policy_command(client, args)

    expected_output = "Temporary Access Pass Authentication methods policy 987654321 was successfully deleted."
    assert result.readable_output == expected_output


def test_list_tap_policy_command_success(mocker):
    """
    Tests the successful execution of the list_tap_policy_command function in the MicrosoftGraphUser module.
    Validates that the function correctly retrieves and formats the Temporary Access Pass (TAP) policy data.

    Given:
        - A mock client instance for the Microsoft Graph API.
    When:
        - Running the list_tap_policy_command function with the mock client and arguments.
    Then:
        1. Mocks the list_tap_policy API call to return predefined TAP policy data.
        2. Mocks the parse_outputs function to simulate parsed readable and output data.
        3. Asserts that the output prefix is correctly set to 'MSGraphUser.TAPPolicy'.
        4. Confirms that the output key field is 'ID' and the correct TAP policy ID is returned.
        5. Ensures that the readable output contains the correct policy information and user ID.
    """

    from MicrosoftGraphUser import MsGraphClient, list_tap_policy_command

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

    args = {"user_id": "123456789"}

    mock_tap_data = [
        {
            "id": "987654321",
            "startDateTime": "2025-04-28T12:00:00Z",
            "lifetimeInMinutes": 60,
            "isUsableOnce": True,
            "isUsable": True,
            "methodUsabilityReason": "Enabled",
            "TemporaryAccessPass": "test123",
        }
    ]

    mocker.patch.object(client, "list_tap_policy", return_value=mock_tap_data)
    result = list_tap_policy_command(client, args)

    assert result.outputs_prefix == "MSGraphUser.TAPPolicy"
    assert result.outputs_key_field == "ID"
    assert result.outputs["ID"] == "987654321"
    assert "Policy ID" in result.readable_output
    assert "TAP Policy for User ID 123456789" in result.readable_output


def test_create_tap_policy_command_success(mocker):
    """
    Tests the successful execution of the create_tap_policy_command function in the MicrosoftGraphUser module.
    Validates that the function correctly creates a Temporary Access Pass (TAP) policy and returns the expected results.

    Given:
        - A mock client instance for the Microsoft Graph API.
    When:
        - Running the create_tap_policy_command function with the mock client and arguments.
    Then:
        1. Mocks the create_tap_policy API call to return predefined API response for the TAP policy creation.
        2. Mocks the create_zip_with_password function.
        3. Mocks the parse_outputs function to simulate parsed output data.
        4. Confirms that the readable output contains the expected success message for the TAP policy creation.
        5. Ensures that the output prefix is set to 'MSGraphUser.TAPPolicy' and the key field is 'ID'.
        6. Verifies that the correct TAP policy ID is included in the output.
    """

    from MicrosoftGraphUser import MsGraphClient, create_tap_policy_command

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

    args = {
        "user_id": "123456789",
        "zip_password": "securepass123",
        "lifetime_in_minutes": "60",
        "is_usable_once": "true",
        "start_time": "2025-04-29T10:00:00Z",
    }

    mock_api_response = {
        "id": "987654321",
        "startDateTime": "2025-04-29T10:00:00.000Z",
        "lifetimeInMinutes": 60,
        "isUsableOnce": True,
        "isUsable": True,
        "methodUsabilityReason": "Enabled",
        "temporaryAccessPass": "Generated-P@ssword1!",
    }

    mocker.patch.object(client, "create_tap_policy", return_value=mock_api_response)
    mocker.patch("MicrosoftGraphUser.create_zip_with_password")
    result = create_tap_policy_command(client, args)

    expected_output = "Temporary Access Pass Authentication methods policy for user: 123456789 was successfully created."
    assert result.readable_output == expected_output
    assert result.outputs_prefix == "MSGraphUser.TAPPolicy"
    assert result.outputs_key_field == "ID"
    assert result.outputs["ID"] == "987654321"


@pytest.mark.parametrize("password_field", ("password", "nonsensitive_password"))
def test_change_on_premise_password_success(requests_mock, password_field: str):
    from MicrosoftGraphUser import change_password_user_on_premise_command, MsGraphClient

    password = "new_password"
    expected_output = "The password of user user has been changed successfully."

    # authenticate
    requests_mock.post("https://login.microsoftonline.com/tenant_id/oauth2/v2.0/token", json={})
    requests_mock.get(
        "https://graph.microsoft.com/v1.0/users/user/authentication/passwordMethods", json={"value": [{"id": "id"}]}
    )
    mocked_password_change_request = requests_mock.post(
        "https://graph.microsoft.com/v1.0/users/user/authentication/methods/id/resetPassword", json={}, status_code=202
    )

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
    other_password_field = {"password": "nonsensitive_password", "nonsensitive_password": "password"}[password_field]
    output = change_password_user_on_premise_command(
        client=client, args={"user": "user", password_field: password, other_password_field: ""}
    )
    assert mocked_password_change_request.call_count == 1
    assert output.readable_output == expected_output


def test_change_on_premise_password_missing_arg(requests_mock):
    """
    Given
            a MSGraphClient
    When
            calling change_password_user_on_premise
    Then
            make sure the user and password are not empty
    """
    from MicrosoftGraphUser import change_password_user_on_premise_command, MsGraphClient, DemistoException

    requests_mock.post("https://login.microsoftonline.com/tenant_id/oauth2/v2.0/token", json={})
    requests_mock.get(
        "https://graph.microsoft.com/v1.0/users/user/authentication/passwordMethods", json={"value": [{"id": "id"}]}
    )
    requests_mock.post(
        "https://graph.microsoft.com/v1.0/users/user/authentication/methods/id/resetPassword", json={"value": [{"id": "id"}]}
    )

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

    with pytest.raises(DemistoException) as e:
        change_password_user_on_premise_command(client=client, args={"user": "user", "password": "", "nonsensitive_password": ""})

    assert "Password is required. Please provide either 'password' (sensitive) or 'nonsensitive_password' argument." in str(
        e.value
    )


@pytest.mark.parametrize(
    "args", [{"password": "aa", "nonsensitive_password": "aa"}, {"password": "aa"}, {"nonsensitive_password": "aa"}]
)
def test_get_password_valid(args):
    """
    Given
    - arguments for the script
    When
    - running the script on a password locked file
    Then
    - ensure that only one of the arguments 'password' or 'nonsensitive_password' is given or if they are identical.
    """
    from MicrosoftGraphUser import validate_input_password

    assert validate_input_password(args) == "aa"


def test_get_password_invalid():
    """
    Given
    - arguments for the script
    When
    - running the script on a password locked file
    Then
    - ensure that only one of the arguments 'password' or 'nonsensitive_password' is given or if they are identical.
    """
    from MicrosoftGraphUser import validate_input_password, DemistoException

    with pytest.raises(DemistoException) as e:
        validate_input_password({"password": "aa", "nonsensitive_password": "bb"})

    assert (
        "Conflicting passwords provided. The 'password' and 'nonsensitive_password' arguments must have the same value, or use only one of them."  # noqa: E501
        in str(e.value)  # noqa: E501
    )
