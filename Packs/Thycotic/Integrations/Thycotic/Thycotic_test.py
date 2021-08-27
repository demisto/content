import pytest

from Thycotic import Client, \
    secret_password_get_command, secret_username_get_command, \
    secret_get_command, secret_password_update_command, secret_checkout_command, secret_checkin_command, \
    secret_delete_command, folder_create_command, folder_delete_command, folder_update_command
from test_data.context import GET_PASSWORD_BY_ID_CONTEXT, GET_USERNAME_BY_ID_CONTENT, \
    SECRET_GET_CONTENT, SECRET_PASSWORD_UPDATE_CONTEXT, SECRET_CHECKOUT_CONTEXT, SECRET_CHECKIN_CONTEXT, \
    SECRET_DELETE_CONTEXT, FOLDER_CREATE_CONTEXT, FOLDER_DELETE_CONTEXT, FOLDER_UPDATE_CONTEXT
from test_data.http_responses import GET_PASSWORD_BY_ID_RAW_RESPONSE, GET_USERNAME_BY_ID_RAW_RESPONSE, \
    SECRET_GET_RAW_RESPONSE, SECRET_PASSWORD_UPDATE_RAW_RESPONSE, SECRET_CHECKOUT_RAW_RESPONSE, \
    SECRET_CHECKIN_RAW_RESPONSE, SECRET_DELETE_RAW_RESPONSE, FOLDER_CREATE_RAW_RESPONSE, FOLDER_DELETE_RAW_RESPONSE, \
    FOLDER_UPDATE_RAW_RESPONSE

GET_PASSWORD_BY_ID_ARGS = {"secret_id": "4"}
GET_USERNAME_BY_ID_ARGS = {"secret_id": "4"}
SECRET_GET_ARGS = {"secret_id": "4"}
SECRET_PASSWORD_UPDATE_ARGS = {"secret_id": "4", "newpassword": "NEWPASSWORD1"}
SECRET_CHECKOUT_ARGS = {"secret_id": "4"}
SECRET_CHECKIN_ARGS = {"secret_id": "4"}
SECRET_DELETE_ARGS = {"id": "9"}
FOLDER_CREATE_ARGS = {"folderName": "xsoarFolderTest3", "folderTypeId": "1", "parentFolderId": "3"}
FOLDER_DELETE_ARGS = {"folder_id": "9"}
FOLDER_UPDATE_ARGS = {"id": "12", "folderName": "xsoarTF3New"}


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
    (folder_update_command, FOLDER_UPDATE_ARGS, FOLDER_UPDATE_RAW_RESPONSE, FOLDER_UPDATE_CONTEXT)
])
def test_thycotic_commands(command, args, http_response, context, mocker):

    mocker.patch.object(Client, '_generate_token')
    client = Client(server_url="https://thss.softwarium.net/SecretServer", username="xsoar1", password="HfpuhXjv123",
                    proxy=False, verify=False)

    mocker.patch.object(Client, '_http_request', return_value=http_response)

    outputs = command(client, **args)
    results = outputs.to_context()

    assert results.get("EntryContext") == context
