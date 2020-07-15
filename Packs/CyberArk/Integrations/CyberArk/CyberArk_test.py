
import pytest

from Packs.CyberArk.Integrations.CyberArk.CyberArk import Client, add_user_command, get_users_command
from Packs.CyberArk.Integrations.CyberArk.test_data.context import ADD_USER_CONTEXT
from Packs.CyberArk.Integrations.CyberArk.test_data.http_resonses import RAW_RESPONSE_ADD_USER, RAW_RESPONSE_GET_USERS

ADD_USER_ARGS = {
  "change_password_on_the_next_logon": "true",
  "description": "new user for test",
  "email": "usertest@test.com",
  "enable_user": "true",
  "first_name": "user",
  "last_name": "test",
  "password": "12345Aa",
  "password_never_expires": "false",
  "profession": "testing integrations",
  "username": "TestUser"
}

UPDATE_USER_ARGS = {
  "change_password_on_the_next_logon": "true",
  "description": "updated description",
  "email": "update@test.com",
  "enable_user": "true",
  "first_name": "test1",
  "last_name": "updated-name",
  "password_never_expires": "false",
  "profession": "test1",
  "userID": "123",
  "username": "TestUser1"
}


@pytest.mark.parametrize('command, args, http_response, context', [
   # (add_user_command, ADD_USER_ARGS, RAW_RESPONSE_ADD_USER, ADD_USER_CONTEXT),
    (get_users_command, {}, RAW_RESPONSE_GET_USERS, ADD_USER_CONTEXT),
])
def test_cyberark_aim_commands(command, args, http_response, context, mocker):
    """Unit test
    Given
    - demisto args
    - raw response of the http request
    When
    - mock the http request result
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client(server_url="https://api.cyberark.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False)

    mocker.patch.object(Client, '_http_request', return_value=http_response)

    outputs = command(client, **args)
    assert outputs.get("EntryContext") == context
