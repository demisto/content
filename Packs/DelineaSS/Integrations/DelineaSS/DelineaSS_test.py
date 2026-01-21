import pytest
from CommonServerPython import *

from DelineaSS import (
    Client,
    AuthenticationModel,
    AuthenticationService,
    get_credentials,
    PlatformLogin,
    secret_password_get_command,
    secret_username_get_command,
    secret_get_command,
    secret_password_update_command,
    secret_checkout_command,
    secret_checkin_command,
    secret_delete_command,
    folder_create_command,
    folder_delete_command,
    folder_update_command,
    secret_server_user_delete_command,
    secret_create_command,
    secret_server_user_create_command,
    secret_server_user_update_command,
    secret_rpc_changepassword_command,
    fetch_credentials_command,
    secret_search_name_command,
    secret_search_command,
    folder_search_command,
    secret_server_user_search_command,
    platform_get_all_users_command,
    platform_user_delete_command,
    platform_user_create_command,
    platform_user_get_command,
    platform_user_update_command,
    platform_get_user_searchbytext_command,
)

from test_data.context import (
    GET_PASSWORD_BY_ID_CONTEXT,
    GET_USERNAME_BY_ID_CONTENT,
    SECRET_GET_CONTENT,
    SECRET_PASSWORD_UPDATE_CONTEXT,
    SECRET_CHECKOUT_CONTEXT,
    SECRET_CHECKIN_CONTEXT,
    SECRET_DELETE_CONTEXT,
    FOLDER_CREATE_CONTEXT,
    FOLDER_DELETE_CONTEXT,
    FOLDER_UPDATE_CONTEXT,
    SECRET_SERVER_USER_DELETE_CONTEXT,
    SECRET_CREATE_CONTEXT,
    SECRET_SERVER_USER_CREATE_CONTEXT,
    SECRET_SERVER_USER_UPDATE_CONTEXT,
    SECRET_RPC_CHANGE_PASSWORD_CONTEXT,
    SECRET_GET_CREDENTIALS_CONTEXT,
    SECRET_SEARCH_NAME_CONTEXT,
    SECRET_SEARCH_CONTEXT,
    FOLDER_SEARCH_CONTEXT,
    SECRET_SERVER_USER_SEARCH_CONTEXT,
    PLATFORM_USER_DELETE_CONTEXT,
    PLATFORM_USER_CREATE_CONTEXT,
    PLATFORM_USER_UPDATE_CONTEXT,
    PLATFORM_USER_GET_CONTEXT,
    PLATFORM_GET_ALL_USERS_CONTEXT,
    PLATFORM_USER_SEARCH_TEXT_CONTEXT,
)
from test_data.http_responses import (
    GET_PASSWORD_BY_ID_RAW_RESPONSE,
    GET_USERNAME_BY_ID_RAW_RESPONSE,
    SECRET_CHECKOUT_RAW_RESPONSE,
    SECRET_GET_RAW_RESPONSE,
    SECRET_PASSWORD_UPDATE_RAW_RESPONSE,
    SECRET_CHECKIN_RAW_RESPONSE,
    SECRET_DELETE_RAW_RESPONSE,
    FOLDER_CREATE_RAW_RESPONSE,
    FOLDER_DELETE_RAW_RESPONSE,
    FOLDER_UPDATE_RAW_RESPONSE,
    SECRET_SERVER_USER_DELETE_RAW_RESPONSE,
    SECRET_CREATE_RAW_RESPONSE,
    SECRET_RPC_CHANGE_PASSWORD_RAW_RESPONSE,
    SECRET_SERVER_USER_CREATE_RAW_RESPONSE,
    SECRET_SERVER_USER_UPDATE_RAW_RESPONSE,
    SECRET_GET_CREDENTIALS_RAW_RESPONSE,
    SECRET_SEARCH_NAME_RAW_RESPONSE,
    SECRET_SEARCH_RAW_RESPONSE,
    FOLDER_SEARCH_RAW_RESPONSE,
    SECRET_SERVER_USER_SEARCH_RAW_RESPONSE,
    PLATFORM_USER_DELETE_RAW_RESPONSE,
    PLATFORM_USER_CREATE_RAW_RESPONSE,
    PLATFORM_USER_UPDATE_RAW_RESPONSE,
    PLATFORM_USER_GET_RAW_RESPONSE,
    PLATFORM_GET_ALL_USERS_RAW_RESPONSE,
    PLATFORM_USER_SEARCH_TEXT_RAW_RESPONSE,
)

GET_PASSWORD_BY_ID_ARGS = {"secret_id": "4", "autoComment": "TestGetPassword"}
GET_USERNAME_BY_ID_ARGS = {"secret_id": "4"}
SECRET_GET_ARGS = {"secret_id": "4", "autoComment": "TestGetSecret"}
SECRET_PASSWORD_UPDATE_ARGS = {"secret_id": "4", "newpassword": "NEWPASSWORD1", "autoComment": "TestPasswordUpdate"}
SECRET_CHECKOUT_ARGS = {"secret_id": "3"}
SECRET_CHECKIN_ARGS = {"secret_id": "4"}
SECRET_DELETE_ARGS = {"id": "9", "autoComment": "TestDeleteSecret"}
FOLDER_CREATE_ARGS = {"folderName": "xsoarFolderTest3", "folderTypeId": "1", "parentFolderId": "3"}
FOLDER_DELETE_ARGS = {"folder_id": "9"}
FOLDER_UPDATE_ARGS = {"id": "12", "folderName": "xsoarTF3New"}
SECRET_SERVER_USER_CREATE_ARGS = {
    "displayName": "dispalyName",
    "password": "password",
    "userName": "XSOAR",
    "emailAddress": "example@example.com",
}
SECRET_SERVER_USER_DELETE_ARGS = {"id": "10"}
SECRET_CREATE_ARGS = {
    "name": "xsoarSecret",
    "secrettemplateid": "6003",
    "siteid": "1",
    "checkoutenabled": "true",
    "folderid": "3",
    "machine_item": "my-machine",
    "username_item": "my-username",
    "password_item": "password_item",
}
SECRET_SERVER_USER_UPDATE_ARGS = {"id": "28", "userName": "UserOne"}
SECRET_RPC_CHANGE_PASSWORD_ARGS = {"secret_id": "4", "newpassword": "newPassword", "autoComment": "TestPasswordChange"}
SECRET_GET_CREDENTIALS_ARGS = {"secretids": "4"}
SECRET_SEARCH_NAME_ARGS = {"search_name": "Sayali"}
SEARCH_SECRET_ARGS = {"filter_folderid": "145", "filter_searchfield": "Name", "filter_searchtext": "book"}
SEARCH_FOLDER_ARGS = {"foldername": "admin"}
SECRET_SERVER_SEARCH_USER_ARGS = {"filter_searchfield": "userName", "filter_searchtext": "Adil", "domainId": "-1"}
PLATFORM_USER_DELETE_ARGS = {"id": "10"}
PLATFORM_USER_CREATE_ARGS = {"Name": "Name", "Password": "password", "DisplayName": "XSOAR", "Mail": "example@example.com"}
PLATFORM_USER_UPDATE_ARGS = {"ID": "28", "Name": "UserOne"}
PLATFORM_USER_GET_ARGS = {"userUuidOrUpn": "10"}
PLATFORM_GET_ALL_USERS_ARGS = {"pageSize": "2"}
PLATFORM_USER_SEARCH_TEXT_ARGS = {"pageSize": "2"}


@pytest.mark.parametrize(
    "command, args, http_response, context",
    [
        (secret_password_get_command, GET_PASSWORD_BY_ID_ARGS, GET_PASSWORD_BY_ID_RAW_RESPONSE, GET_PASSWORD_BY_ID_CONTEXT),
        (secret_username_get_command, GET_USERNAME_BY_ID_ARGS, GET_USERNAME_BY_ID_RAW_RESPONSE, GET_USERNAME_BY_ID_CONTENT),
        (secret_get_command, SECRET_GET_ARGS, SECRET_GET_RAW_RESPONSE, SECRET_GET_CONTENT),
        (
            secret_password_update_command,
            SECRET_PASSWORD_UPDATE_ARGS,
            SECRET_PASSWORD_UPDATE_RAW_RESPONSE,
            SECRET_PASSWORD_UPDATE_CONTEXT,
        ),
        (secret_checkout_command, SECRET_CHECKOUT_ARGS, SECRET_CHECKOUT_RAW_RESPONSE, SECRET_CHECKOUT_CONTEXT),
        (secret_checkin_command, SECRET_CHECKIN_ARGS, SECRET_CHECKIN_RAW_RESPONSE, SECRET_CHECKIN_CONTEXT),
        (secret_delete_command, SECRET_DELETE_ARGS, SECRET_DELETE_RAW_RESPONSE, SECRET_DELETE_CONTEXT),
        (folder_create_command, FOLDER_CREATE_ARGS, FOLDER_CREATE_RAW_RESPONSE, FOLDER_CREATE_CONTEXT),
        (folder_delete_command, FOLDER_DELETE_ARGS, FOLDER_DELETE_RAW_RESPONSE, FOLDER_DELETE_CONTEXT),
        (folder_update_command, FOLDER_UPDATE_ARGS, FOLDER_UPDATE_RAW_RESPONSE, FOLDER_UPDATE_CONTEXT),
        (
            secret_server_user_delete_command,
            SECRET_SERVER_USER_DELETE_ARGS,
            SECRET_SERVER_USER_DELETE_RAW_RESPONSE,
            SECRET_SERVER_USER_DELETE_CONTEXT,
        ),
        (secret_create_command, SECRET_CREATE_ARGS, SECRET_CREATE_RAW_RESPONSE, SECRET_CREATE_CONTEXT),
        (
            secret_server_user_create_command,
            SECRET_SERVER_USER_CREATE_ARGS,
            SECRET_SERVER_USER_CREATE_RAW_RESPONSE,
            SECRET_SERVER_USER_CREATE_CONTEXT,
        ),
        (
            secret_server_user_update_command,
            SECRET_SERVER_USER_UPDATE_ARGS,
            SECRET_SERVER_USER_UPDATE_RAW_RESPONSE,
            SECRET_SERVER_USER_UPDATE_CONTEXT,
        ),
        (
            secret_rpc_changepassword_command,
            SECRET_RPC_CHANGE_PASSWORD_ARGS,
            SECRET_RPC_CHANGE_PASSWORD_RAW_RESPONSE,
            SECRET_RPC_CHANGE_PASSWORD_CONTEXT,
        ),
        (
            fetch_credentials_command,
            SECRET_GET_CREDENTIALS_ARGS,
            SECRET_GET_CREDENTIALS_RAW_RESPONSE,
            SECRET_GET_CREDENTIALS_CONTEXT,
        ),
        (secret_search_name_command, SECRET_SEARCH_NAME_ARGS, SECRET_SEARCH_NAME_RAW_RESPONSE, SECRET_SEARCH_NAME_CONTEXT),
        (secret_search_command, SEARCH_SECRET_ARGS, SECRET_SEARCH_RAW_RESPONSE, SECRET_SEARCH_CONTEXT),
        (folder_search_command, SEARCH_FOLDER_ARGS, FOLDER_SEARCH_RAW_RESPONSE, FOLDER_SEARCH_CONTEXT),
        (
            secret_server_user_search_command,
            SECRET_SERVER_SEARCH_USER_ARGS,
            SECRET_SERVER_USER_SEARCH_RAW_RESPONSE,
            SECRET_SERVER_USER_SEARCH_CONTEXT,
        ),
        (
            platform_user_delete_command,
            PLATFORM_USER_DELETE_ARGS,
            PLATFORM_USER_DELETE_RAW_RESPONSE,
            PLATFORM_USER_DELETE_CONTEXT,
        ),
        (
            platform_user_create_command,
            PLATFORM_USER_CREATE_ARGS,
            PLATFORM_USER_CREATE_RAW_RESPONSE,
            PLATFORM_USER_CREATE_CONTEXT,
        ),
        (
            platform_user_update_command,
            PLATFORM_USER_UPDATE_ARGS,
            PLATFORM_USER_UPDATE_RAW_RESPONSE,
            PLATFORM_USER_UPDATE_CONTEXT,
        ),
        (platform_user_get_command, PLATFORM_USER_GET_ARGS, PLATFORM_USER_GET_RAW_RESPONSE, PLATFORM_USER_GET_CONTEXT),
        (
            platform_get_all_users_command,
            PLATFORM_GET_ALL_USERS_ARGS,
            PLATFORM_GET_ALL_USERS_RAW_RESPONSE,
            PLATFORM_GET_ALL_USERS_CONTEXT,
        ),
        (
            platform_get_user_searchbytext_command,
            PLATFORM_USER_SEARCH_TEXT_ARGS,
            PLATFORM_USER_SEARCH_TEXT_RAW_RESPONSE,
            PLATFORM_USER_SEARCH_TEXT_CONTEXT,
        ),
    ],
)
def test_commands(command, args, http_response, context, mocker):
    """Test commands based on login type (Platform or Secret Server)"""

    ss_model = AuthenticationModel("username", "password", "https://test.example.com")

    if command in [
        platform_user_create_command,
        platform_user_update_command,
        platform_user_get_command,
        platform_user_delete_command,
        platform_get_all_users_command,
        platform_get_user_searchbytext_command,
    ]:
        ss_model.set_platform_login(True)
    else:
        ss_model.set_platform_login(False)

    mocker.patch("DelineaSS.is_platform_or_ss", return_value=ss_model)
    mocker.patch.object(Client, "_generate_token", return_value="Bearer TEST_TOKEN")
    mocker.patch.object(Client, "_http_request", return_value=http_response)

    client = Client(
        server_url="https://test.example.com",
        username="username",
        password="password",
        proxy=False,
        verify=False,
    )

    outputs = command(client, **args)
    results = outputs.to_context()

    assert results.get("EntryContext") == context


def test_authenticate_async_secret_server(mocker):
    mocker.patch("DelineaSS.requests.get", return_value=mocker.Mock(text='{"healthy": true}', json=lambda: {"healthy": True}))

    model = AuthenticationModel(server_url="https://ss.example.com")
    service = AuthenticationService()

    result = service.authenticate_async(model)

    assert result.platform_login is False


def test_authenticate_async_platform(mocker):
    mocker.patch(
        "DelineaSS.requests.get",
        side_effect=[
            mocker.Mock(text="", json=dict),  # SS check fails
            mocker.Mock(text="Healthy"),  # Platform check succeeds
        ],
    )

    mocker.patch.object(
        PlatformLogin, "platform_authentication", return_value=AuthenticationModel(platform_login=True, token="token")
    )

    model = AuthenticationModel(server_url="https://pf.example.com")
    result = AuthenticationService().authenticate_async(model)

    assert result.platform_login is True


def test_platform_login_token_failure(mocker):
    mocker.patch("DelineaSS.requests.post", return_value=mocker.Mock(status_code=401, text="Unauthorized"))

    auth = AuthenticationModel(server_url="https://pf.example.com")
    result = PlatformLogin().platform_authentication(auth)

    assert result.error == "Unauthorized"


def test_client_platform_authentication(mocker):
    model = AuthenticationModel(platform_login=True, token="TOKEN", vault_url="https://vault.example.com")

    mocker.patch("DelineaSS.is_platform_or_ss", return_value=model)

    client = Client(server_url="https://pf.example.com", username="u", password="p", proxy=False, verify=False)

    assert client._base_url == "https://vault.example.com"
    assert client._headers["Authorization"] == "Bearer TOKEN"


def test_user_create_on_platform_raises(mocker):
    mock_auth = mocker.Mock(platform_login=True, token="t", vault_url="url", error=None)

    mocker.patch("DelineaSS.is_platform_or_ss", return_value=mock_auth)

    client = Client("url", "u", "p", False, False)

    with pytest.raises(DemistoException):
        client.userCreate(Name="test")


def test_platform_user_create_on_secret_server_raises(mocker):
    mocker.patch("DelineaSS.is_platform_or_ss", return_value=mocker.Mock(platform_login=False))

    mocker.patch.object(Client, "_generate_token", return_value="token")

    client = Client("url", "u", "p", False, False)

    with pytest.raises(DemistoException):
        client.platform_user_create(Name="test")


def test_get_credentials(mocker):
    mock_client = mocker.Mock()
    mock_client.getSecret.return_value = {
        "id": 1,
        "items": [{"fieldName": "Username", "itemValue": "admin"}, {"fieldName": "Password", "itemValue": "pass"}],
    }

    creds = get_credentials(mock_client, "1")

    assert creds["user"] == "admin"
    assert creds["password"] == "pass"


def test_fetch_credentials_empty(mocker):
    mocker.patch("DelineaSS.demisto.args", return_value={})
    mocker.patch("DelineaSS.demisto.credentials")

    client = mocker.Mock()

    result = fetch_credentials_command(client, "")

    assert result.outputs == []


def test_client_authenticate_platform_error(mocker):
    auth_model = mocker.Mock(platform_login=True, error="Auth failed", token=None, vault_url="https://example.com")

    mocker.patch("DelineaSS.is_platform_or_ss", return_value=auth_model)

    with pytest.raises(Exception, match="Auth failed"):
        Client(server_url="https://example.com", username="u", password="p", proxy=False, verify=False)


def test_authentication_model_setters():
    model = AuthenticationModel("u", "p", "url")
    model.set_platform_login(True)
    assert model.platform_login is True
    model.set_platform_login(False)
    assert model.platform_login is False
    assert model.error is None
    model.error = "Some error"
    assert model.error == "Some error"


def test_http_request_raises_exception(mocker):
    mocker.patch(
        "DelineaSS.is_platform_or_ss", return_value=mocker.Mock(platform_login=False, token="t", vault_url="https://example.com")
    )
    mocker.patch.object(Client, "_generate_token", return_value="Bearer token")

    client = Client("https://example.com", "u", "p", False, False)

    # Now force exception in _http_request
    mocker.patch.object(client, "_http_request", side_effect=Exception("Request failed"))

    with pytest.raises(Exception, match="Request failed"):
        client._http_request("GET", "/test")


def test_authentication_model_error_handling():
    model = AuthenticationModel("u", "p", "url")
    assert model.error is None
    model.error = "Some error"
    assert model.error == "Some error"


def test_client_authenticate_non_platform_success(mocker):
    auth_model = mocker.Mock(platform_login=False, token="SS_TOKEN", vault_url="https://example.com", error=None)

    mocker.patch("DelineaSS.is_platform_or_ss", return_value=auth_model)
    mocker.patch.object(Client, "_generate_token", return_value="Bearer SS_TOKEN")

    client = Client(server_url="https://example.com", username="u", password="p", proxy=False, verify=False)

    assert client._token == "Bearer SS_TOKEN"


def test_client_authenticate_platform_success(mocker):
    auth_model = mocker.Mock(platform_login=True, token="PLATFORM_TOKEN", vault_url="https://platform.example.com", error=None)

    mocker.patch("DelineaSS.is_platform_or_ss", return_value=auth_model)

    client = Client(server_url="https://platform.example.com", username="u", password="p", proxy=False, verify=False)

    assert client._token == "PLATFORM_TOKEN"


def test_authenticate_async_invalid_url(mocker):
    mocker.patch("DelineaSS.requests.get", return_value=mocker.Mock(text="", json=dict))

    model = AuthenticationModel(server_url="https://invalid.example.com")
    result = AuthenticationService().authenticate_async(model)

    assert result.error == "Invalid Server URL https://invalid.example.com"


def test_platform_login_no_active_vault(mocker):
    mocker.patch.object(
        PlatformLogin,
        "get_access_token",
        return_value=mocker.Mock(status_code=200, json=lambda: {"access_token": "t", "expires_in": 10}),
    )

    mocker.patch.object(PlatformLogin, "get_vaults", return_value=mocker.Mock(status_code=200, json=lambda: {"vaults": []}))

    model = AuthenticationModel(server_url="https://pf.example.com")
    result = PlatformLogin().platform_authentication(model)

    assert result.error == "No active default vault found"


def test_check_json_response_healthy_string(mocker):
    mocker.patch("DelineaSS.requests.get", return_value=mocker.Mock(text="Healthy", json=dict))

    model = AuthenticationModel(server_url="https://example.com")
    service = AuthenticationService()

    assert service.check_json_response_async("url", model) is True


def test_test_module_failure(mocker):
    from DelineaSS import test_module

    client = mocker.Mock()
    client._token = ""

    result = test_module(client)

    assert "Failed to get authorization token" in result


def test_authenticate_async_exception(mocker):
    mocker.patch("DelineaSS.requests.get", side_effect=Exception("Boom"))

    model = AuthenticationModel(server_url="https://example.com")
    result = AuthenticationService().authenticate_async(model)

    assert result.error is not None
    assert "Invalid Server URL" in result.error or "Authentication failed" in result.error


def test_authenticate_async_runtime_error(mocker):
    mocker.patch.object(AuthenticationService, "check_json_response_async", side_effect=Exception("Crash"))

    model = AuthenticationModel(server_url="https://example.com")

    with pytest.raises(RuntimeError, match="Authentication failed: Crash"):
        AuthenticationService().authenticate_async(model)


def test_platform_handle_error_response():
    model = PlatformLogin().handle_error_response("error")

    assert model.error == "error"
    assert model.platform_login is True


def test_client_platform_authentication_error_message(mocker):
    auth_model = mocker.Mock(platform_login=True, error="Platform error", token=None, vault_url=None)

    mocker.patch("DelineaSS.is_platform_or_ss", return_value=auth_model)

    with pytest.raises(Exception, match="Platform error"):
        Client("https://example.com", "u", "p", False, False)


def test_get_credentials_partial(mocker):
    mock_client = mocker.Mock()
    mock_client.getSecret.return_value = {"id": 1, "items": [{"fieldName": "Username", "itemValue": "admin"}]}

    creds = get_credentials(mock_client, "1")
    assert creds["user"] == "admin"
    assert creds.get("password") is None


def test_check_json_response_invalid_json(mocker):
    mock_response = mocker.Mock()
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_response.text = "Not JSON"
    mocker.patch("DelineaSS.requests.get", return_value=mock_response)
    service = AuthenticationService()
    model = AuthenticationModel("u", "p", "https://example.com")
    assert service.check_json_response_async("url", model) is False


def test_client_generate_token_none(mocker):
    mock_auth = mocker.Mock(platform_login=False, token=None, vault_url="https://url")
    mocker.patch("DelineaSS.is_platform_or_ss", return_value=mock_auth)
    mocker.patch.object(Client, "_generate_token", return_value=None)
    client = Client("https://url", "u", "p", False, False)
    token = client._generate_token()
    assert token is None


def test_client_user_update_on_platform_raises(mocker):
    mock_auth = mocker.Mock(platform_login=True, token="t", vault_url="url", error=None)
    mocker.patch("DelineaSS.is_platform_or_ss", return_value=mock_auth)

    client = Client("https://url", "u", "p", False, False)

    with pytest.raises(DemistoException):
        client.userUpdate(id="1", Name="TestUser")
