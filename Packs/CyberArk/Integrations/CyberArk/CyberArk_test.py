
import pytest

from Packs.CyberArk.Integrations.CyberArk.CyberArk import Client, add_user_command, get_users_command, \
    update_user_command, add_safe_command, update_safe_command, get_list_safes_command, get_safe_by_name_command, \
    add_safe_member_command, update_safe_member_command, list_safe_members_command, add_account_command, \
    update_account_command, get_list_accounts_command, get_list_account_activity_command
from Packs.CyberArk.Integrations.CyberArk.test_data.context import ADD_USER_CONTEXT, GET_USERS_CONTEXT, \
    UPDATE_USER_CONTEXT, UPDATE_SAFE_CONTEXT, GET_LIST_SAFES_CONTEXT, GET_SAFE_BY_NAME_CONTEXT, ADD_SAFE_CONTEXT, \
    ADD_SAFE_MEMBER_CONTEXT, UPDATE_SAFE_MEMBER_CONTEXT, LIST_SAFE_MEMBER_CONTEXT, ADD_ACCOUNT_CONTEXT, \
    UPDATE_ACCOUNT_CONTEXT, GET_LIST_ACCOUNT_CONTEXT, GET_LIST_ACCOUNT_ACTIVITIES_CONTEXT
from Packs.CyberArk.Integrations.CyberArk.test_data.http_resonses import ADD_USER_RAW_RESPONSE, \
    UPDATE_USER_RAW_RESPONSE, GET_USERS_RAW_RESPONSE, ADD_SAFE_RAW_RESPONSE, UPDATE_SAFE_RAW_RESPONSE, \
    GET_LIST_SAFES_RAW_RESPONSE, GET_SAFE_BY_NAME_RAW_RESPONSE, ADD_SAFE_MEMBER_RAW_RESPONSE, \
    UPDATE_SAFE_MEMBER_RAW_RESPONSE, LIST_SAFE_MEMBER_RAW_RESPONSE, ADD_ACCOUNT_RAW_RESPONSE, \
    UPDATE_ACCOUNT_RAW_RESPONSE, GET_LIST_ACCOUNT_RAW_RESPONSE, GET_LIST_ACCOUNT_ACTIVITIES_RAW_RESPONSE

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

GET_USER_ARGS = {
  "filter": "filteroption",
  "search": "searchoption"
}

ADD_SAFE_ARGS = {
  "description": "safe for tests",
  "number_of_days_retention": "100",
  "safe_name": "TestSafe"
}

UPDATE_SAFE_ARGS = {
  "description": "UpdatedSafe",
  "number_of_days_retention": "150",
  "safe_name": "TestSafe",
  "safe_new_name": "UpdatedName"
}

GET_SAFE_BY_NAME_ARGS = {
  "safe_name": "TestSafe"
}

ADD_SAFE_MEMBER_ARGS = {
  "member_name": "TestUser",
  "requests_authorization_level": "0",
  "safe_name": "TestSafe"
}

UPDATE_SAFE_MEMBER_ARGS = {
  "member_name": "TestUser",
  "permissions": "UseAccounts",
  "requests_authorization_level": "0",
  "safe_name": "TestSafe"
}

LIST_SAFE_MEMBER_ARGS = {
  "safe_name": "TestSafe"
}


ADD_ACCOUNT_ARGS = {
  "account_name": "TestAccount1",
  "address": "/",
  "automatic_management_enabled": "true",
  "password": "12345Aa",
  "platformID": "WinServerLocal",
  "safe_name": "TestSafe",
  "secret_type": "password",
  "username": "TestUser"
}

UPDATE_ACCOUNT_ARGS = {
  "accountID": "77_4",
  "account_name": "NewName"
}

GET_LIST_ACCOUNT_ARGS = {
  "limit": "2",
  "offset": "0"
}

GET_LIST_ACCOUNT_ACTIVITIES_ARGS = {
  "accountID": "77_4"
}


@pytest.mark.parametrize('command, args, http_response, context', [

   (add_user_command, ADD_USER_ARGS, ADD_USER_RAW_RESPONSE, ADD_USER_CONTEXT),
   (update_user_command, UPDATE_USER_ARGS, UPDATE_USER_RAW_RESPONSE, UPDATE_USER_CONTEXT),
   (get_users_command, {}, GET_USERS_RAW_RESPONSE, GET_USERS_CONTEXT),

   (add_safe_command, ADD_SAFE_ARGS, ADD_SAFE_RAW_RESPONSE, ADD_SAFE_CONTEXT),
   (update_safe_command, UPDATE_SAFE_ARGS, UPDATE_SAFE_RAW_RESPONSE, UPDATE_SAFE_CONTEXT),
   (get_list_safes_command, {}, GET_LIST_SAFES_RAW_RESPONSE, GET_LIST_SAFES_CONTEXT),
   (get_safe_by_name_command, GET_SAFE_BY_NAME_ARGS, GET_SAFE_BY_NAME_RAW_RESPONSE, GET_SAFE_BY_NAME_CONTEXT),

   (add_safe_member_command, ADD_SAFE_MEMBER_ARGS, ADD_SAFE_MEMBER_RAW_RESPONSE, ADD_SAFE_MEMBER_CONTEXT),
   (update_safe_member_command, UPDATE_SAFE_MEMBER_ARGS, UPDATE_SAFE_MEMBER_RAW_RESPONSE, UPDATE_SAFE_MEMBER_CONTEXT),
   (list_safe_members_command, LIST_SAFE_MEMBER_ARGS, LIST_SAFE_MEMBER_RAW_RESPONSE, LIST_SAFE_MEMBER_CONTEXT),

   (add_account_command, ADD_ACCOUNT_ARGS, ADD_ACCOUNT_RAW_RESPONSE, ADD_ACCOUNT_CONTEXT),
   (update_account_command, UPDATE_ACCOUNT_ARGS, UPDATE_ACCOUNT_RAW_RESPONSE, UPDATE_ACCOUNT_CONTEXT),
   (get_list_accounts_command, GET_LIST_ACCOUNT_ARGS, GET_LIST_ACCOUNT_RAW_RESPONSE, GET_LIST_ACCOUNT_CONTEXT),
   (get_list_account_activity_command, GET_LIST_ACCOUNT_ACTIVITIES_ARGS, GET_LIST_ACCOUNT_ACTIVITIES_RAW_RESPONSE, GET_LIST_ACCOUNT_ACTIVITIES_CONTEXT),
])
def test_cyberark_aim_commands(command, args, http_response, context, mocker):
    """Unit test
    Given
    - demisto args
    - raw response of the http request
    When
    - mock the http request result
    Then
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(Client, '_generate_token')
    client = Client(server_url="https://api.cyberark.com/", username="user1", password="12345", use_ssl=False,
                    proxy=False)

    mocker.patch.object(Client, '_http_request', return_value=http_response)

    outputs = command(client, **args)
    results = outputs.to_context()
    assert results.get("EntryContext") == context
