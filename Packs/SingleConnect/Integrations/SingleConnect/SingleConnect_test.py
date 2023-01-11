import pytest
from pytest import raises

from CommonServerPython import CommandResults, DemistoException
from SingleConnect import Client, list_all_sapm_accounts_command, search_sapm_with_secret_name_command, \
    get_sapm_user_info_command, show_password_command
from test_data.http_responses import SEARCH_SAPM_ACCOUNTS_RESPONSE, EMPTY_SEARCH_SAPM_ACCOUNTS_RESPONSE, \
    GET_SAPM_USER_INFO_RESPONSE, SHOW_PASSWORD_RESPONSE, ERROR_MESSAGE_RESPONSE


UNEXPECTED_RESPONSE_FORMAT = 'Unexpected response format'

ERROR_SINGLE_CONNECT = 'Error in Single Connect API call'

ARGS_SEARCH_SAPM_WITH_SECRET_NAME = {
    "secret_name": "account7"
}

ARGS_GET_SAPM_USER_INFO = {
    "device_ip": "123141"
}

ARGS_SHOW_PASSWORD = {
    "password_expiration_in_minute": 30,
    "sapm_db_id": 642365,
    "comment": "reason for password request"
}

EMPTY_DICT = {}

EMPTY_LIST = []

AUTHENTICATION_ERROR_RESPONSE = "Error in API call [401]"

AUTHENTICATION_ERROR_MESSAGE = "Authentication Error: Make sure username and password are correctly set"

HEADER_XSRF_TOKEN = {"XSRF-TOKEN": "4b6794ebc982f8aa3786d745555d8dc3"}


@pytest.mark.parametrize('search_command, args, invalid_response_type', [
    (list_all_sapm_accounts_command, {}, EMPTY_DICT),
    (search_sapm_with_secret_name_command, ARGS_SEARCH_SAPM_WITH_SECRET_NAME, EMPTY_DICT)
])
def test_search_sapm_account_commands(search_command, args, invalid_response_type, mocker):
    mocker.patch.object(Client, '_generate_token')

    mocker.patch.object(Client, '_http_request', side_effect=[SEARCH_SAPM_ACCOUNTS_RESPONSE,
                                                              EMPTY_SEARCH_SAPM_ACCOUNTS_RESPONSE,
                                                              invalid_response_type,
                                                              ERROR_MESSAGE_RESPONSE])

    client = Client(base_url='https://localhost', username='admin', password='admin', use_ssl=False, proxy=False)

    command_output = search_command(client, **args)
    assert type(command_output) is CommandResults
    assert command_output.outputs == SEARCH_SAPM_ACCOUNTS_RESPONSE.get("searchResults")

    command_output_empty_body = search_command(client, **args)
    assert type(command_output_empty_body) is CommandResults
    assert command_output_empty_body.outputs == EMPTY_SEARCH_SAPM_ACCOUNTS_RESPONSE.get("searchResults")

    with raises(Exception, match=UNEXPECTED_RESPONSE_FORMAT):
        search_command(client, **args)
    with raises(Exception, match=ERROR_SINGLE_CONNECT):
        search_command(client, **args)


@pytest.mark.parametrize('command, args, http_response, invalid_response_type', [
    (get_sapm_user_info_command, ARGS_GET_SAPM_USER_INFO, GET_SAPM_USER_INFO_RESPONSE, EMPTY_DICT),
    (show_password_command, ARGS_SHOW_PASSWORD, SHOW_PASSWORD_RESPONSE, EMPTY_LIST)
])
def test_single_connect_commands(command, args, http_response, invalid_response_type, mocker):
    mocker.patch.object(Client, '_generate_token')

    mocker.patch.object(Client, '_http_request', side_effect=[http_response,
                                                              invalid_response_type,
                                                              ERROR_MESSAGE_RESPONSE])

    client = Client(base_url='https://localhost', username='admin', password='admin', use_ssl=False, proxy=False)

    command_output = command(client, **args)
    assert type(command_output) is CommandResults
    assert command_output.outputs == http_response

    with raises(Exception, match=UNEXPECTED_RESPONSE_FORMAT):
        command(client, **args)
    with raises(Exception, match=ERROR_SINGLE_CONNECT):
        command(client, **args)


def test_generate_token_authentication_fail(mocker):
    mocker.patch.object(Client, '_http_request', side_effect=[DemistoException(AUTHENTICATION_ERROR_RESPONSE)])

    with raises(DemistoException, match=AUTHENTICATION_ERROR_MESSAGE):
        Client(base_url='https://localhost', username='admin', password='admin', use_ssl=False, proxy=False)


def test_generate_token_success(requests_mock):
    requests_mock.post("https://localhost/aioc-rest-web/rest/login", headers=HEADER_XSRF_TOKEN)
    client = Client(base_url='https://localhost', username='admin', password='admin', use_ssl=False, proxy=False)
    assert HEADER_XSRF_TOKEN.get("XSRF-TOKEN") == client._token
