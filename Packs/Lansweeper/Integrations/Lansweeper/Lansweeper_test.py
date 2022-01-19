import io
import json
import os
import time

from unittest.mock import patch

import pytest

from CommonServerPython import (DemistoException, set_integration_context, get_integration_context)
from Lansweeper import MESSAGES


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


COMMON_GRAPHQL_ENDPOINT = "https://api.lansweeper.com/api/v2/graphql"
AUTHENTICATION_ENDPOINT = "https://api.lansweeper.com/api/integrations/oauth/token"
REDIRECT_URL = "https://mock.com"

MOCK_INTEGRATION_CONTEXT = {
    'access_token': "Bearer dummy",
    'valid_until': time.time() + 86400,
    'authorized_sites': [
        {
            "id": "401d153d-2a59-45eb-879a-c291390448ca",
            "name": "api-demo-data"
        },
        {
            "id": "56d4ed4f-b2ad-4587-91b5-07bd453c5c76",
            "name": "api-demo-data-v2"
        }
    ]
}

AUTHENTICATION_RESP_HEADER = {
    "access_token": "dummy",
    "token_type": "Bearer",
    "expires_in": 86400
}


@pytest.fixture()
def client():
    from Lansweeper import Client
    return Client("", False, False, headers={"Authorization": "Token identity_code"})


def test_test_module_when_valid_response_is_returned(mocker):
    """
    To test test_module command when success response come.
    Given
        - A valid response
    When
        - The status code returned is 200
    Then
        - Ensure test module should return success
    """
    from Lansweeper import test_module
    mocked_client = mocker.Mock()
    mocked_client.http_request.return_value = {}
    assert test_module(mocked_client) == 'ok'


@pytest.mark.parametrize("status_code, error_msg", [
    (400, "Authentication error. Please provide valid 'Application Identity Code'."),
    (500, "The server encountered an internal error for Lansweeper and was unable to complete your request.")
])
def test_exception_handler(status_code, error_msg, mocker):
    """
    To test exception handler in various http error code.
    Given
        - a dictionary containing http code
    When
        - they are the error codes
    Then
        - raise DemistoException
    """
    from Lansweeper import Client
    mocked_response = mocker.Mock()
    mocked_response.status_code = status_code
    mocked_response.json.return_value = {}
    with pytest.raises(DemistoException) as err:
        Client.exception_handler(mocked_response)

    assert str(err.value) == error_msg


def test_lansweeper_site_list_command_when_valid_response_is_returned(mocker):
    """
    Test case scenario for successful execution of lnsw-site-list command.
    Given:
        - command arguments for list site command
    When:
        - Calling `lnsw-site-list` command
    Then:
        -  Returns the response data
    """
    from Lansweeper import lansweeper_site_list_command

    response = util_load_json(
        os.path.join("test_data", "site_list_command_response.json"))
    context = util_load_json(
        os.path.join("test_data", "site_list_command_context.json"))
    with open(os.path.join("test_data", "site_list_command_hr.md"), 'r') as f:
        readable_output = f.read()

    mocked_client = mocker.Mock()
    mocked_client.site_list.return_value = response

    command_response = lansweeper_site_list_command(mocked_client)

    assert command_response.outputs_prefix == 'Lansweeper.Site'
    assert command_response.outputs_key_field == "id"
    assert command_response.outputs == context
    assert command_response.readable_output == readable_output


def test_main_unknown_commmand(mocker, monkeypatch, capfd):
    """
    Tests the execution of main function when unknown command name is provided
    Given:
        - unknown command
    When:
        - Calling `main` method
    Then:
        -  Raises exception
    """
    from Lansweeper import main
    monkeypatch.setattr('demistomock.params', lambda: {
        "url": REDIRECT_URL,
        "credentials": {
            "identifier": "client_id",
            "password": "password"

        },
        "authorization_code": "123456"
    })
    monkeypatch.setattr('demistomock.command', lambda: "unknown_command")

    mocked_client = mocker.Mock()
    mocked_client.http_request.return_value = {}

    with pytest.raises(SystemExit):
        capfd.close()
        main()


@patch('demistomock.getIntegrationContext')
def test_lansweeper_ip_hunt_command_when_valid_response_is_returned(mocker_get_context, mocker):
    """
    Test case scenario for successful execution of ls-ip-hunt command.
    Given:
        - command arguments for ip hunt command
    When:
        - Calling `ls-ip-hunt` command
    Then:
        -  Returns the response data
    """
    from Lansweeper import lansweeper_ip_hunt_command
    mocker_get_context.return_value = MOCK_INTEGRATION_CONTEXT
    response = util_load_json(
        os.path.join("test_data", "ip_hunt_command_response.json"))
    context = util_load_json(
        os.path.join("test_data", "ip_hunt_command_context.json"))
    with open(os.path.join("test_data", "ip_hunt_command_hr.md"), 'r') as f:
        readable_output = f.read()

    mocked_client = mocker.Mock()
    mocked_client.asset_list.return_value = response
    args = {
        'site_id': "56d4ed4f-b2ad-4587-91b5-07bd453c5c76",
        'ip': "127.0.0.1"

    }
    command_response = lansweeper_ip_hunt_command(mocked_client, args)

    assert command_response.outputs_prefix == "Lansweeper.IP"
    assert command_response.outputs_key_field == "assetId"
    assert command_response.outputs == context
    assert command_response.readable_output == readable_output


@patch('demistomock.getIntegrationContext')
def test_lansweeper_ip_hunt_command_when_empty_response_is_returned(mocker_get_context, mocker):
    """
    Test case scenario for successful execution of ls-ip-hunt command with an empty response.
    Given:
        - command arguments for hunt ip command
    When:
        - Calling `ls-ip-hunt` command
    Then:
        - Returns no records for the given input arguments
    """
    from Lansweeper import lansweeper_ip_hunt_command
    mocker_get_context.return_value = MOCK_INTEGRATION_CONTEXT
    response = {
        "data": {
            "site": {
                "assetResources": {
                    "total": 0,
                    "pagination": {
                        "limit": 2,
                        "current": None,
                        "next": None,
                        "page": "NEXT"
                    },
                    "items": []
                }
            }
        }
    }
    args = {
        'site_id': "56d4ed4f-b2ad-4587-91b5-07bd453c5c76",
        'ip': "127.0.0.1"

    }
    mocked_client = mocker.Mock()
    mocked_client.asset_list.return_value = response

    command_results = lansweeper_ip_hunt_command(mocked_client, args=args)

    assert command_results.readable_output == '### Asset(s)\n**No entries.**\n'


@pytest.mark.parametrize("args,expected_error", [
    ({"site_id": "abc", "ip": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("ip")),
    ({"site_id": "abc", "ip": "abc,1.1"}, MESSAGES["INVALID_IP"]),
    ({"ip": "127.0.0.1", "limit": 501}, MESSAGES["INVALID_LIMIT"].format("501")),
    ({"ip": "127.0.0.1", "limit": 0}, MESSAGES["INVALID_LIMIT"].format("0")),
])
@patch('demistomock.getIntegrationContext')
def test_lansweeper_ip_hunt_command_when_invalid_args_provided(mocker_get_context, client, args, expected_error):
    """
    Test case scenario when invalid arguments for ip hunt command are provided.
    Given:
        - invalid command arguments for ip hunt command
    When
        - Calling `ls-ip-hunt`
    Then:
        - Returns the response message of invalid input arguments
    """
    from Lansweeper import lansweeper_ip_hunt_command
    mocker_get_context.return_value = MOCK_INTEGRATION_CONTEXT
    with pytest.raises(ValueError) as err:
        lansweeper_ip_hunt_command(client, args)

    assert str(err.value) == expected_error


@patch('demistomock.getIntegrationContext')
def test_lansweeper_mac_hunt_command_when_valid_response_is_returned(mocker_get_context, mocker):
    """
    Test case scenario for successful execution of ls-mac-hunt command.
    Given:
        - command arguments for mac hunt command
    When:
        - Calling `ls-mac-hunt` command
    Then:
        -  Returns the response data
    """
    from Lansweeper import lansweeper_mac_hunt_command
    mocker_get_context.return_value = MOCK_INTEGRATION_CONTEXT
    response = util_load_json(
        os.path.join("test_data", "ip_hunt_command_response.json"))
    context = util_load_json(
        os.path.join("test_data", "mac_hunt_command_context.json"))
    with open(os.path.join("test_data", "ip_hunt_command_hr.md"), 'r') as f:
        readable_output = f.read()

    mocked_client = mocker.Mock()
    mocked_client.asset_list.return_value = response
    args = {
        'site_id': "56d4ed4f-b2ad-4587-91b5-07bd453c5c76",
        'mac_address': "00:0D:3A:2B:7E:B7"

    }
    command_response = lansweeper_mac_hunt_command(mocked_client, args)

    assert command_response.outputs_prefix == "Lansweeper.Mac"
    assert command_response.outputs_key_field == "assetId"
    assert command_response.outputs == context
    assert command_response.readable_output == readable_output


@patch('demistomock.getIntegrationContext')
def test_lansweeper_mac_hunt_command_when_empty_response_is_returned(mocker_get_context, mocker):
    """
    Test case scenario for successful execution of ls-mac-hunt command with an empty response.
    Given:
        - command arguments for hunt mac command
    When:
        - Calling `ls-mac-hunt` command
    Then:
        - Returns no records for the given input arguments
    """
    from Lansweeper import lansweeper_mac_hunt_command
    mocker_get_context.return_value = MOCK_INTEGRATION_CONTEXT
    response = {
        "data": {
            "site": {
                "assetResources": {
                    "total": 0,
                    "pagination": {
                        "limit": 2,
                        "current": None,
                        "next": None,
                        "page": "NEXT"
                    },
                    "items": []
                }
            }
        }
    }
    args = {
        'site_id': "56d4ed4f-b2ad-4587-91b5-07bd453c5c76",
        'mac_address': "00:0D:3A:2B:7E:B7"

    }
    mocked_client = mocker.Mock()
    mocked_client.asset_list.return_value = response

    command_results = lansweeper_mac_hunt_command(mocked_client, args=args)

    assert command_results.readable_output == '### Asset(s)\n**No entries.**\n'


@pytest.mark.parametrize("args,expected_error", [
    ({"site_id": "abc", 'mac_address': ""}, MESSAGES["REQUIRED_ARGUMENT"].format("mac_address")),
    ({"site_id": "abc", "mac_address": "abc,1.1"}, MESSAGES["INVALID_MAC"]),
    ({"mac_address": "02:0C:29:FE:A6:64", "limit": 501}, MESSAGES["INVALID_LIMIT"].format("501")),
    ({"mac_address": "02:0C:29:FE:A6:64", "limit": 0}, MESSAGES["INVALID_LIMIT"].format("0")),
])
@patch('demistomock.getIntegrationContext')
def test_lansweeper_mac_hunt_command_when_invalid_args_provided(mocker_get_context, client, args, expected_error):
    """
    Test case scenario when invalid arguments for mac hunt command are provided.
    Given:
        - invalid command arguments for mac hunt command
    When
        - Calling `ls-mac-hunt`
    Then:
        - Returns the response message of invalid input arguments
    """
    from Lansweeper import lansweeper_mac_hunt_command
    mocker_get_context.return_value = MOCK_INTEGRATION_CONTEXT
    with pytest.raises(ValueError) as err:
        lansweeper_mac_hunt_command(client, args)

    assert str(err.value) == expected_error


@pytest.mark.parametrize(
    "context,client_id,as_expected",
    [
        ({"identity_code": "dummy_id"}, "dummy_id", False),
        ({}, "dummy_id", True),
        ({"identity_code": ""}, "dummy_id", True),
        ({"identity_code": "other_dummy_code"}, "dummy_id", True),
    ],
)
def test_creds_changed(context, client_id, as_expected) -> None:
    """
    Scenario: To detect changes in credentials.
    When:
     - When user changes credentials (identity_code).
    Then:
     - Change in credentials should be detected correctly.
    """
    from Lansweeper import creds_changed

    set_integration_context(context)
    assert creds_changed(get_integration_context(), client_id) is as_expected


@pytest.mark.parametrize(
    "context",
    [
        {},
        {"dummy_key": "dummy_val"},
        {"dummy_key1": "dummy_val1", "dummy_key2": "dummy_val2"},
    ],
)
def test_invalidate_context(context) -> None:
    """
    Scenario: Demisto integration context should be invalidated if credentials are changed.
    Given:
     - User has provided new credentials.
    When:
     - When user changes credentials (identity_code).
    Then:
     - Integration context should be invalidated.
    """
    from Lansweeper import update_context

    set_integration_context(context)
    update_context("new_identity_code")
    assert get_integration_context() == {"identity_code": "new_identity_code"}
