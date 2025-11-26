import pytest
import demistomock as demisto  # noqa: F401

from DelineaSS import Client, AuthenticationModel, \
    secret_password_get_command, secret_username_get_command, \
    secret_get_command, secret_password_update_command, \
    secret_checkout_command, secret_checkin_command, \
    secret_delete_command, folder_create_command, \
    folder_delete_command, folder_update_command, \
    secret_server_user_delete_command, secret_create_command, secret_server_user_create_command, \
    secret_server_user_update_command, secret_rpc_changepassword_command, \
    fetch_credentials_command, secret_search_name_command, \
    secret_search_command, folder_search_command, secret_server_user_search_command, \
    platform_get_all_users_command, platform_user_delete_command, platform_user_create_command, \
    platform_user_get_command, platform_user_update_command, platform_get_user_searchbytext_command

from test_data.context import GET_PASSWORD_BY_ID_CONTEXT, \
    GET_USERNAME_BY_ID_CONTENT, SECRET_GET_CONTENT, \
    SECRET_PASSWORD_UPDATE_CONTEXT, SECRET_CHECKOUT_CONTEXT, \
    SECRET_CHECKIN_CONTEXT, SECRET_DELETE_CONTEXT, \
    FOLDER_CREATE_CONTEXT, FOLDER_DELETE_CONTEXT, FOLDER_UPDATE_CONTEXT, \
    SECRET_SERVER_USER_DELETE_CONTEXT, SECRET_CREATE_CONTEXT, SECRET_SERVER_USER_CREATE_CONTEXT, \
    SECRET_SERVER_USER_UPDATE_CONTEXT, SECRET_RPC_CHANGE_PASSWORD_CONTEXT, \
    SECRET_GET_CREDENTIALS_CONTEXT, SECRET_SEARCH_NAME_CONTEXT, \
    SECRET_SEARCH_CONTEXT, FOLDER_SEARCH_CONTEXT, SECRET_SERVER_USER_SEARCH_CONTEXT, \
    PLATFORM_USER_DELETE_CONTEXT, PLATFORM_USER_CREATE_CONTEXT, PLATFORM_USER_UPDATE_CONTEXT, \
    PLATFORM_USER_GET_CONTEXT, PLATFORM_GET_ALL_USERS_CONTEXT, PLATFORM_USER_SEARCH_TEXT_CONTEXT
from test_data.http_responses import (GET_PASSWORD_BY_ID_RAW_RESPONSE,
                                      GET_USERNAME_BY_ID_RAW_RESPONSE, SECRET_CHECKOUT_RAW_RESPONSE,
                                      SECRET_GET_RAW_RESPONSE, SECRET_PASSWORD_UPDATE_RAW_RESPONSE,
                                      SECRET_CHECKIN_RAW_RESPONSE, SECRET_DELETE_RAW_RESPONSE,
                                      FOLDER_CREATE_RAW_RESPONSE, FOLDER_DELETE_RAW_RESPONSE,
                                      FOLDER_UPDATE_RAW_RESPONSE, SECRET_SERVER_USER_DELETE_RAW_RESPONSE,
                                      SECRET_CREATE_RAW_RESPONSE, SECRET_RPC_CHANGE_PASSWORD_RAW_RESPONSE,
                                      SECRET_SERVER_USER_CREATE_RAW_RESPONSE, SECRET_SERVER_USER_UPDATE_RAW_RESPONSE,
                                      SECRET_GET_CREDENTIALS_RAW_RESPONSE,
                                      SECRET_SEARCH_NAME_RAW_RESPONSE, SECRET_SEARCH_RAW_RESPONSE, FOLDER_SEARCH_RAW_RESPONSE,
                                      SECRET_SERVER_USER_SEARCH_RAW_RESPONSE, PLATFORM_USER_DELETE_RAW_RESPONSE,
                                      PLATFORM_USER_CREATE_RAW_RESPONSE,
                                      PLATFORM_USER_UPDATE_RAW_RESPONSE, PLATFORM_USER_GET_RAW_RESPONSE,
                                      PLATFORM_GET_ALL_USERS_RAW_RESPONSE,
                                      PLATFORM_USER_SEARCH_TEXT_RAW_RESPONSE)

GET_PASSWORD_BY_ID_ARGS = {"secret_id": "4", "autoComment": "TestGetPassword"}
GET_USERNAME_BY_ID_ARGS = {"secret_id": "4"}
SECRET_GET_ARGS = {"secret_id": "4", "autoComment": "TestGetSecret"}
SECRET_PASSWORD_UPDATE_ARGS = {"secret_id": "4", "newpassword": "NEWPASSWORD1", "autoComment": "TestPasswordUpdate"}
SECRET_CHECKOUT_ARGS = {"secret_id": "3"}
SECRET_CHECKIN_ARGS = {"secret_id": "4"}
SECRET_DELETE_ARGS = {"id": "9", "autoComment": "TestDeleteSecret"}
FOLDER_CREATE_ARGS = {"folderName": "xsoarFolderTest3", "folderTypeId": "1",
                      "parentFolderId": "3"}
FOLDER_DELETE_ARGS = {"folder_id": "9"}
FOLDER_UPDATE_ARGS = {"id": "12", "folderName": "xsoarTF3New"}
SECRET_SERVER_USER_CREATE_ARGS = {"displayName": "dispalyName", "password": "password",
                                  "userName": "XSOAR", "emailAddress": "example@example.com"}
SECRET_SERVER_USER_DELETE_ARGS = {"id": "10"}
SECRET_CREATE_ARGS = {"name": "xsoarSecret", "secrettemplateid": "6003",
                      "siteid": "1", "checkoutenabled": "true",
                      "folderid": "3", "machine_item": "my-machine",
                      "username_item": "my-username",
                      "password_item": "password_item"}
SECRET_SERVER_USER_UPDATE_ARGS = {"id": "28", "userName": "UserOne"}
SECRET_RPC_CHANGE_PASSWORD_ARGS = {"secret_id": "4", "newpassword": "newPassword", "autoComment": "TestPasswordChange"}
SECRET_GET_CREDENTIALS_ARGS = {"secretids": "4"}
SECRET_SEARCH_NAME_ARGS = {"search_name": "Sayali"}
SEARCH_SECRET_ARGS = {"filter_folderid": "145", "filter_searchfield": "Name", "filter_searchtext": "book"}
SEARCH_FOLDER_ARGS = {"foldername": "admin"}
SECRET_SERVER_SEARCH_USER_ARGS = {"filter_searchfield": "userName", "filter_searchtext": "Adil", "domainId": "-1"}
PLATFORM_USER_DELETE_ARGS = {"id": "10"}
PLATFORM_USER_CREATE_ARGS = {"Name": "Name", "Password": "password",
                             "DisplayName": "XSOAR", "Mail": "example@example.com"}
PLATFORM_USER_UPDATE_ARGS = {"ID": "28", "Name": "UserOne"}
PLATFORM_USER_GET_ARGS = {"userUuidOrUpn": "10"}
PLATFORM_GET_ALL_USERS_ARGS = {"pageSize": "2"}
PLATFORM_USER_SEARCH_TEXT_ARGS = {"pageSize": "2"}


@pytest.mark.parametrize('command, args, http_response, context', [
    (secret_password_get_command, GET_PASSWORD_BY_ID_ARGS, GET_PASSWORD_BY_ID_RAW_RESPONSE, GET_PASSWORD_BY_ID_CONTEXT),
    (secret_username_get_command, GET_USERNAME_BY_ID_ARGS, GET_USERNAME_BY_ID_RAW_RESPONSE, GET_USERNAME_BY_ID_CONTENT),
    (secret_get_command, SECRET_GET_ARGS, SECRET_GET_RAW_RESPONSE, SECRET_GET_CONTENT),
    (secret_password_update_command, SECRET_PASSWORD_UPDATE_ARGS, SECRET_PASSWORD_UPDATE_RAW_RESPONSE,
     SECRET_PASSWORD_UPDATE_CONTEXT),
    (secret_checkout_command, SECRET_CHECKOUT_ARGS, SECRET_CHECKOUT_RAW_RESPONSE, SECRET_CHECKOUT_CONTEXT),
    (secret_checkin_command, SECRET_CHECKIN_ARGS, SECRET_CHECKIN_RAW_RESPONSE, SECRET_CHECKIN_CONTEXT),
    (secret_delete_command, SECRET_DELETE_ARGS, SECRET_DELETE_RAW_RESPONSE, SECRET_DELETE_CONTEXT),
    (folder_create_command, FOLDER_CREATE_ARGS, FOLDER_CREATE_RAW_RESPONSE, FOLDER_CREATE_CONTEXT),
    (folder_delete_command, FOLDER_DELETE_ARGS, FOLDER_DELETE_RAW_RESPONSE, FOLDER_DELETE_CONTEXT),
    (folder_update_command, FOLDER_UPDATE_ARGS, FOLDER_UPDATE_RAW_RESPONSE, FOLDER_UPDATE_CONTEXT),
    (secret_server_user_delete_command, SECRET_SERVER_USER_DELETE_ARGS, SECRET_SERVER_USER_DELETE_RAW_RESPONSE,
     SECRET_SERVER_USER_DELETE_CONTEXT),
    (secret_create_command, SECRET_CREATE_ARGS, SECRET_CREATE_RAW_RESPONSE, SECRET_CREATE_CONTEXT),
    (secret_server_user_create_command, SECRET_SERVER_USER_CREATE_ARGS, SECRET_SERVER_USER_CREATE_RAW_RESPONSE,
     SECRET_SERVER_USER_CREATE_CONTEXT),
    (secret_server_user_update_command, SECRET_SERVER_USER_UPDATE_ARGS, SECRET_SERVER_USER_UPDATE_RAW_RESPONSE,
     SECRET_SERVER_USER_UPDATE_CONTEXT),
    (secret_rpc_changepassword_command, SECRET_RPC_CHANGE_PASSWORD_ARGS,
     SECRET_RPC_CHANGE_PASSWORD_RAW_RESPONSE, SECRET_RPC_CHANGE_PASSWORD_CONTEXT),
    (fetch_credentials_command, SECRET_GET_CREDENTIALS_ARGS, SECRET_GET_CREDENTIALS_RAW_RESPONSE,
     SECRET_GET_CREDENTIALS_CONTEXT),
    (secret_search_name_command, SECRET_SEARCH_NAME_ARGS, SECRET_SEARCH_NAME_RAW_RESPONSE, SECRET_SEARCH_NAME_CONTEXT),
    (secret_search_command, SEARCH_SECRET_ARGS, SECRET_SEARCH_RAW_RESPONSE, SECRET_SEARCH_CONTEXT),
    (folder_search_command, SEARCH_FOLDER_ARGS, FOLDER_SEARCH_RAW_RESPONSE, FOLDER_SEARCH_CONTEXT),
    (secret_server_user_search_command, SECRET_SERVER_SEARCH_USER_ARGS, SECRET_SERVER_USER_SEARCH_RAW_RESPONSE,
     SECRET_SERVER_USER_SEARCH_CONTEXT),
    (platform_user_delete_command, PLATFORM_USER_DELETE_ARGS, PLATFORM_USER_DELETE_RAW_RESPONSE, PLATFORM_USER_DELETE_CONTEXT),
    (platform_user_create_command, PLATFORM_USER_CREATE_ARGS, PLATFORM_USER_CREATE_RAW_RESPONSE,
     PLATFORM_USER_CREATE_CONTEXT),
    (platform_user_update_command, PLATFORM_USER_UPDATE_ARGS, PLATFORM_USER_UPDATE_RAW_RESPONSE,
     PLATFORM_USER_UPDATE_CONTEXT),
    (platform_user_get_command, PLATFORM_USER_GET_ARGS, PLATFORM_USER_GET_RAW_RESPONSE,
     PLATFORM_USER_GET_CONTEXT),
    (platform_get_all_users_command, PLATFORM_GET_ALL_USERS_ARGS, PLATFORM_GET_ALL_USERS_RAW_RESPONSE,
     PLATFORM_GET_ALL_USERS_CONTEXT),
    (platform_get_user_searchbytext_command, PLATFORM_USER_SEARCH_TEXT_ARGS, PLATFORM_USER_SEARCH_TEXT_RAW_RESPONSE,
     PLATFORM_USER_SEARCH_TEXT_CONTEXT),
])
def test_delinea_commands(command, args, http_response, context, mocker):
    ss_model = AuthenticationModel("username", "password", "https://test.example.com")
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
