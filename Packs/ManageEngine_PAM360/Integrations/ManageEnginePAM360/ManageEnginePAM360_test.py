import pytest

from ManageEnginePAM360 import Client, pam360_fetch_password, pam360_create_resource, \
    pam360_create_account, pam360_update_resource, pam360_update_account, pam360_fetch_account_details, pam360_list_resources, \
    pam360_list_accounts, pam360_update_account_password, pam360_fetch_resource_account_id
from test_data.context import FETCH_PASSWORD_CONTEXT, CREATE_RESOURCE_CONTEXT, \
    CREATE_ACCOUNT_CONTEXT, UPDATE_RESOURCE_CONTEXT, UPDATE_ACCOUNT_CONTEXT, FETCH_ACCOUNT_DETAILS_CONTEXT, \
    LIST_ALL_RESOURCE_CONTEXT, LIST_ALL_ACCOUNTS_CONTEXT, UPDATE_ACCOUNT_PASSWORD_CONTEXT, FETCH_RESOURCE_ACCOUNT_ID_CONTEXT
from test_data.responses import FETCH_PASSWORD_RAW_RESPONSE, \
    CREATE_RESOURCE_RAW_RESPONSE, CREATE_ACCOUNT_RAW_RESPONSE, UPDATE_RESOURCE_RAW_RESPONSE, UPDATE_ACCOUNT_RAW_RESPONSE, \
    FETCH_ACCOUNT_DETAILS_RAW_RESPONSE, LIST_ALL_RESOURCE_RAW_RESPONSE, LIST_ALL_ACCOUNTS_RAW_RESPONSE, \
    UPDATE_ACCOUNT_PASSWORD_RAW_RESPONSE, FETCH_RESOURCE_ACCOUNT_ID_RAW_RESPONSE


FETCH_PASSWORD_ARGS = {
    "resource_id": "1",
    "account_id": "1"
}

CREATE_RESOURCE_ARGS = {
    "resource_name": "SOUTH-FIN-WINSERQA-09",
    "resource_type": "Windows",
    "account_name": "administrator",
    "password": "QA!K>35Hgg(x"
}

CREATE_ACCOUNT_ARGS = {
    "resource_id": "1",
    "account_name": "admin",
    "password": "t8BRq)<6h9g1"
}

UPDATE_RESOURCE_ARGS = {
    "resource_id": "1",
    "resource_name": "SOUTH-FIN-WINSERQA-09",
    "resource_url": "https://pam360:8282"
}

UPDATE_ACCOUNT_ARGS = {
    "resource_id": "1",
    "account_id": "1",
    "account_name": "admin",
    "notes": "Windows server resources reserved for testing API"
}

FETCH_ACCOUNT_DETAILS_ARGS = {
    "resource_id": "1",
    "account_id": "1"
}

LIST_ALL_ACCOUNTS_ARGS = {
    "resource_id": "1"
}

UPDATE_ACCOUNT_PASSWORD_ARGS = {
    "resource_id": "1",
    "account_id": "1",
    "new_password": "A8>ne3J&0Z",
    "reset_type": "LOCAL",
    "reason": "Password Expired",
    "ticket_id": "1"
}

FETCH_RESOURCE_ACCOUNT_ID_ARGS = {
    "resource_name": "SOUTH-FIN-WINSERQA-09",
    "account_name": "administrator"
}


@pytest.mark.parametrize('command, args, http_response, context', [
    (pam360_fetch_password, FETCH_PASSWORD_ARGS, FETCH_PASSWORD_RAW_RESPONSE, FETCH_PASSWORD_CONTEXT),
    (pam360_create_resource, CREATE_RESOURCE_ARGS, CREATE_RESOURCE_RAW_RESPONSE, CREATE_RESOURCE_CONTEXT),
    (pam360_create_account, CREATE_ACCOUNT_ARGS, CREATE_ACCOUNT_RAW_RESPONSE, CREATE_ACCOUNT_CONTEXT),
    (pam360_update_resource, UPDATE_RESOURCE_ARGS, UPDATE_RESOURCE_RAW_RESPONSE, UPDATE_RESOURCE_CONTEXT),
    (pam360_update_account, UPDATE_ACCOUNT_ARGS, UPDATE_ACCOUNT_RAW_RESPONSE, UPDATE_ACCOUNT_CONTEXT),
    (pam360_fetch_account_details, FETCH_ACCOUNT_DETAILS_ARGS, FETCH_ACCOUNT_DETAILS_RAW_RESPONSE, FETCH_ACCOUNT_DETAILS_CONTEXT),
    (pam360_list_resources, {}, LIST_ALL_RESOURCE_RAW_RESPONSE, LIST_ALL_RESOURCE_CONTEXT),
    (pam360_list_accounts, LIST_ALL_ACCOUNTS_ARGS, LIST_ALL_ACCOUNTS_RAW_RESPONSE, LIST_ALL_ACCOUNTS_CONTEXT),
    (pam360_update_account_password, UPDATE_ACCOUNT_PASSWORD_ARGS, UPDATE_ACCOUNT_PASSWORD_RAW_RESPONSE,
     UPDATE_ACCOUNT_PASSWORD_CONTEXT),
    (pam360_fetch_resource_account_id, FETCH_RESOURCE_ACCOUNT_ID_ARGS, FETCH_RESOURCE_ACCOUNT_ID_RAW_RESPONSE,
     FETCH_RESOURCE_ACCOUNT_ID_CONTEXT),
])
def test_manageengine_pam360_commands(command, args, http_response, context, mocker):
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
    client = Client(server_url="https://pam30:8282", app_token="B698EF92-B151-4E5C-969D-CA7B50DF4E9D", verify_certificate=False,
                    proxy=False)

    mocker.patch.object(Client, '_http_request', return_value=http_response)

    outputs = command(client, **args)
    results = outputs.to_context()

    assert results.get("EntryContext") == context
