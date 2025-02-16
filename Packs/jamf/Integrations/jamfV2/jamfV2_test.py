"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json

from freezegun import freeze_time
from CommonServerPython import *
import pytest
from jamfV2 import check_authentication_parameters
from CommonServerPython import DemistoException


def load_xml_response(file_name: str) -> str:
    with open(file_name, encoding='utf-8') as xml_file:
        return xml_file.read()


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_computers_command(mocker):
    """
    Given
    - Get computers command with no arguments.
    When
    - Run get computers command
    Then
    - Ensure the response matches the default limit.
    """
    from jamfV2 import Client, get_computers_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {}
    mock_response = util_load_json('test_data/get_computer/get_computer_raw_response.json')

    mocker.patch.object(client, 'get_computers_request', return_value=mock_response)

    computer_response = get_computers_command(client, args)
    expected_response = util_load_json('test_data/get_computer/get_computer_context.json')
    assert computer_response[0].outputs == expected_response


def test_get_computers_limit_command(mocker):
    """
    Given
    - Limit and page arguments
    When
    - Run get computers command
    Then
    - Ensure the result are according to the limit and page
    """
    from jamfV2 import Client, get_computers_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'limit': 10, 'page': 2}
    mock_response = util_load_json('test_data/get_computer/get_computer_raw_response.json')

    mocker.patch.object(client, 'get_computers_request', return_value=mock_response)

    response = get_computers_command(client, args)
    expected_response = util_load_json('test_data/get_computer/get_computer_limit_context.json')
    assert response[0].outputs == expected_response


def test_get_computers_by_id_command(mocker):
    """
    Given
    - Computer ID.
    When
    - Run get computer by id command
    Then
    - Get results on specific computer ID.
    """
    from jamfV2 import Client, get_computer_by_id_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 1}
    mock_response = util_load_json('test_data/get_computer/get_computer_by_id_raw_response.json')

    mocker.patch.object(client, 'get_computers_request', return_value=mock_response)

    response = get_computer_by_id_command(client, args)
    expected_response = util_load_json('test_data/get_computer/get_computer_by_id_context.json')
    assert response.outputs == expected_response


def test_get_computers_by_match_command(mocker):
    """
    Given
    - Match arguments
    When
    - Run get computers command
    Then
    - Ensure the result are according to the id and match args.
    """
    from jamfV2 import Client, get_computers_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'match': '564D26*'}
    mock_response = util_load_json('test_data/get_computer/get_computer_by_match_raw_response.json')

    mocker.patch.object(client, 'get_computers_request', return_value=mock_response)

    response = get_computers_command(client, args)
    expected_response = util_load_json('test_data/get_computer/get_computer_by_match_context.json')
    assert response[0].outputs == expected_response


def test_get_computer_general_subset_command(mocker):
    """
    Given
    - Name of the computer and subset arguments.
    When
    - Run get computer subset command
    Then
    - Ensure the command output matched the given query.
    """
    from jamfV2 import Client, get_computer_subset_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'identifier': 'name', 'identifier_value': 'Computer 95'}
    mock_response_general_subset = util_load_json(
        'test_data/get_computer_subset/get_computer_by_name_general_subset_raw_response.json')
    mocker.patch.object(client, 'get_computer_subset_request', return_value=mock_response_general_subset)

    computer_response = get_computer_subset_command(client, args, 'General')
    expected_response = util_load_json(
        'test_data/get_computer_subset/get_computer_by_name_general_subset_context.json')
    assert computer_response.outputs == expected_response


def test_computer_lock_command(mocker):
    """
    Given
    - Get computers command with no arguments.
    When
    - Run get computers command
    Then
    - Ensure the response matches the default limit.
    """
    from jamfV2 import Client, computer_lock_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 138, 'passcode': 123456, 'lock_msg': 'Test'}
    mock_response = load_xml_response('test_data/computer_lock/computer_lock_raw_response.xml')

    mocker.patch.object(client, 'computer_lock_request', return_value=json.loads(xml2json(mock_response)))

    computer_response = computer_lock_command(client, args)
    expected_response = util_load_json('test_data/computer_lock/computer_lock_context.json')
    assert computer_response.outputs == expected_response


def test_computer_erase_command(mocker):
    """
    Given
    - erase computer command with id and passcode.
    When
    - Run erase computer command
    Then
    - Ensure the response matches .
    """
    from jamfV2 import Client, computer_erase_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 138, 'passcode': 123456}
    mock_response = load_xml_response('test_data/computer_erase/computer_erase_raw_response.xml')

    mocker.patch.object(client, 'computer_erase_request', return_value=json.loads(xml2json(mock_response)))

    computer_response = computer_erase_command(client, args)
    expected_response = util_load_json('test_data/computer_erase/computer_erase_context.json')
    assert computer_response.outputs == expected_response


def test_get_users_command(mocker):
    """
    Given
    - Get users command with no arguments.
    When
    - Run get users command
    Then
    - Ensure the response matches the default limit.
    """
    from jamfV2 import Client, get_users_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {}
    mock_response = util_load_json('test_data/get_users/get_users_raw_response.json')

    mocker.patch.object(client, 'get_users_request', return_value=mock_response)

    users_response = get_users_command(client, args)
    expected_response = util_load_json('test_data/get_users/get_users_context.json')
    assert users_response[0].outputs == expected_response


def test_get_users_limit_command(mocker):
    """
    Given
    - Limit and page arguments
    When
    - Run get users command
    Then
    - Ensure the result are according to the limit and page
    """
    from jamfV2 import Client, get_users_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'limit': 10, 'page': 2}
    mock_response = util_load_json('test_data/get_users/get_users_raw_response.json')

    mocker.patch.object(client, 'get_users_request', return_value=mock_response)

    users_response = get_users_command(client, args)
    expected_response = util_load_json('test_data/get_users/get_users_limit_context.json')
    assert users_response[0].outputs == expected_response


def test_get_mobile_devices_command(mocker):
    """
    Given
    - Get mobile devices command with no arguments.
    When
    - Run get mobile devices command
    Then
    - Ensure the response matches the default limit.
    """
    from jamfV2 import Client, get_mobile_devices_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {}
    mock_response = util_load_json('test_data/get_mobile_devices/get_mobile_devices_raw_response.json')

    mocker.patch.object(client, 'get_mobile_devices_request', return_value=mock_response)

    devices_response = get_mobile_devices_command(client, args)
    expected_response = util_load_json('test_data/get_mobile_devices/get_mobile_devices_context.json')
    assert devices_response[0].outputs == expected_response


def test_get_mobile_devices_limit_command(mocker):
    """
    Given
    - Limit and page arguments
    When
    - Run get mobile devices command
    Then
    - Ensure the result are according to the limit and page
    """
    from jamfV2 import Client, get_mobile_devices_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'limit': 10, 'page': 1}
    mock_response = util_load_json('test_data/get_mobile_devices/get_mobile_devices_raw_response.json')

    mocker.patch.object(client, 'get_mobile_devices_request', return_value=mock_response)

    devices_response = get_mobile_devices_command(client, args)
    expected_response = util_load_json('test_data/get_mobile_devices/get_mobile_devices_limit_context.json')
    assert devices_response[0].outputs == expected_response


def test_get_mobile_devices_by_id_command(mocker):
    """
    Given
    - Mobile device ID.
    When
    - Run get mobile devices command
    Then
    - Get results on specific mobile device ID.
    """
    from jamfV2 import Client, get_mobile_device_by_id_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 1}
    mock_response = util_load_json('test_data/get_mobile_devices/get_mobile_device_by_id_raw_response.json')

    mocker.patch.object(client, 'get_mobile_devices_request', return_value=mock_response)

    devices_response = get_mobile_device_by_id_command(client, args)
    expected_response = util_load_json('test_data/get_mobile_devices/get_mobile_device_by_id_context.json')
    assert devices_response.outputs == expected_response


def test_get_mobile_devices_by_match_command(mocker):
    """
    Given
    - Match argument
    When
    - Run get mobile devices command
    Then
    - Ensure the result are according to the match arg.
    """
    from jamfV2 import Client, get_mobile_devices_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'match': 'ab12cdc060a311e490b812*'}
    mock_response = util_load_json('test_data/get_mobile_devices/get_mobile_device_by_match_raw_response.json')

    mocker.patch.object(client, 'get_mobile_devices_request', return_value=mock_response)

    devices_response = get_mobile_devices_command(client, args)
    expected_response = util_load_json('test_data/get_mobile_devices/get_mobile_device_by_match_context.json')
    assert devices_response[0].outputs == expected_response


def test_get_mobile_device_general_subset_command(mocker):
    """
    Given
    - UDID of the mobile device and subset arguments.
    When
    - Run get mobile device general subset command
    Then
    - Ensure the command output matched the given query.
    """
    from jamfV2 import Client, get_mobile_device_subset_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'identifier': 'udid', 'identifier_value': 'ab12f4c660a311e490b812df261f2c7e'}
    mock_response = util_load_json(
        'test_data/get_mobile_device_subset/get_mobile_device_by_udid_subset_raw_response.json')

    mocker.patch.object(client, 'get_mobile_devices_subset_request', return_value=mock_response)

    device_response = get_mobile_device_subset_command(client, args, 'General')
    expected_response = util_load_json('test_data/get_mobile_device_subset/'
                                       'get_mobile_device_by_udid_subset_context.json')
    assert device_response.outputs == expected_response


def test_get_computers_by_app_command(mocker):
    """
    Given
    - Application argument.
    When
    - Run get computers by app command
    Then
    - Ensure the response matches the default limit.
    """
    from jamfV2 import Client, get_computers_by_app_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'application': 'safar*'}
    mock_response = util_load_json('test_data/get_computer_by_app/get_computer_by_app_raw_response.json')

    mocker.patch.object(client, 'get_computers_by_app_request', return_value=mock_response)

    computer_response = get_computers_by_app_command(client, args)
    expected_response = util_load_json('test_data/get_computer_by_app/get_computer_by_app_context.json')
    assert computer_response[0].outputs == expected_response


def test_mobile_device_lost_command(mocker):
    """
    Given
    - mobile device id and lost-mode message arguments.
    When
    - Run mobile device lost command
    Then
    - Ensure the response matches.
    """
    from jamfV2 import Client, mobile_device_lost_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 114, 'lost_mode_message': 'test'}
    mock_response = load_xml_response('test_data/mobile_device_lost/mobile_device_lost_raw_response.xml')

    mocker.patch.object(client, 'mobile_device_lost_request', return_value=json.loads(xml2json(mock_response)))

    mobile_response = mobile_device_lost_command(client, args)
    expected_response = util_load_json('test_data/mobile_device_lost/mobile_device_lost_context.json')
    assert mobile_response.outputs == expected_response


def test_mobile_device_erase_command(mocker):
    """
    Given
    - Mobile device id and lost-mode message arguments.
    When
    - Run mobile device lost command
    Then
    - Ensure the response matches.
    """
    from jamfV2 import Client, mobile_device_erase_command

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 114}
    mock_response = load_xml_response('test_data/mobile_device_erase/mobile_device_erase_raw_response.xml')

    mocker.patch.object(client, 'mobile_device_erase_request', return_value=json.loads(xml2json(mock_response)))

    computer_response = mobile_device_erase_command(client, args)
    expected_response = util_load_json('test_data/mobile_device_erase/mobile_device_erase_context.json')
    assert computer_response.outputs == expected_response


def test_endpoint_command(mocker):
    """
    Given:
        - endpoint_command
    When:
        - Filtering using both id and hostname
    Then:
        - Verify that duplicates are removed (since the mock is called twice the same endpoint is retrieved, but if
        working properly, only one result should be returned).
    """
    from jamfV2 import endpoint_command, Client
    from CommonServerPython import Common

    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 'id', 'hostname': 'hostname'}
    endpoint_response = util_load_json(
        'test_data/get_computer_subset/get_computer_by_name_general_subset_raw_response.json')
    mocker.patch.object(client, 'get_computer_subset_request', return_value=endpoint_response)

    outputs = endpoint_command(client, args)

    get_endpoints_response = {
        Common.Endpoint.CONTEXT_PATH: [{
            'ID': 1,
            'Hostname': 'Computer 95',
            'OS': 'Mac',
            'Vendor': 'JAMF v2',
            'MACAddress': '12:5B:35:CA:12:56'
        }]
    }
    results = outputs[0].to_context()
    for key, _val in results.get("EntryContext").items():
        assert results.get("EntryContext")[key] == get_endpoints_response[key]
    assert results.get("EntryContext") == get_endpoints_response
    assert len(outputs) == 1


@pytest.mark.parametrize('client_id, client_secret, username, password', [
    ("client_id", "client_secret", None, None),
    (None, None, "username", "password"),
])
def test_check_authentication_parameters__no_exception(client_id, client_secret, username, password):
    """
    Given:
        - client_id, client_secret, username, and password
        case 1: client_id and client_secret are provided, but username, password are not
        case 2: client_id, client_secret are not provided, but username, password are provided
    When:
        - check_authentication_parameters is called
    Then:
        - Ensure the function dose not raise an exception
    """
    check_authentication_parameters(client_id, client_secret, username, password)


@pytest.mark.parametrize('client_id, client_secret, username, password', [
    ("client_id", "client_secret", "username", "password"),
    (None, None, None, None),
    ("client_id", None, "username", None),
    (None, "client_secret", None, "password"),
])
def test_check_authentication_parameters__raises_exception(client_id, client_secret, username, password):
    """
    Given:
        - client_id, client_secret, username, and password
        case 1: None of the parameters are provided
        case 2: client_id and username are provided, but client_secret, password are not
        case 3: client_secret and password are provided, but client_id, username are not

    When:
        - check_authentication_parameters is called
    Then:
        - Ensure the function raises an exception
    """
    with pytest.raises(DemistoException):
        check_authentication_parameters(client_id, client_secret, username, password)


def test_generate_token__basic_auth_no_token(mocker):
    """
    Given:
        - A Client instance with username and password and basic_auth_flag set to True
    When:
        - _generate_token is called but no token is generated
    Then:
        - Ensure the http_request will use the username and password for authentication (basic auth) since
        their is no token, and the basic_auth_flag is set to True

    """

    from jamfV2 import Client
    mocker.patch.object(Client, '_http_request')
    mocker.patch.object(Client, '_get_token', side_effect=DemistoException("Mocked exception"))
    client = Client(base_url="https://example.com", verify=False, proxy=False, token=None,
                    username="username", password="password")
    mocker.patch('jamfV2.get_integration_context')
    mocker.patch('jamfV2.set_integration_context')
    client._classic_api_post(url_suffix="test", data=None, error_handler=None)

    assert client._http_request.call_args.kwargs.get('auth') == ('username', 'password')


@freeze_time("2024-04-01")
def test_generate_basic_auth_token(mocker):
    """
    Given:
        - A Client instance with username and password
    When:
        - generate_basic_auth_token is called
    Then:
        - Ensure the function returns the token and expiration time correctly
        - Ensure the http_request is called with the correct arguments
    """
    from jamfV2 import Client
    mocker.patch.object(Client, '_http_request').return_value = {"token": "mocked token", "expires": "2022-12-31T23:59:59Z"}
    client = Client(base_url="https://example.com", verify=False, proxy=False, username="username", password="password")

    assert client.generate_basic_auth_token() == ('mocked token', 1672531199)
    assert client._http_request.call_args.kwargs == {'method': 'POST', 'url_suffix': 'api/v1/auth/token', 'resp_type': 'json', 'auth': ('username', 'password')}    # noqa


@freeze_time("2024-04-01")
def test_generate_client_credentials_token(mocker):
    """
    Given:
        - A Client instance with client_id and client_secret
    When:
        - generate_client_credentials_token is called
    Then:
        - Ensure the function returns the token and expiration time correctly
        - Ensure the http_request is called with the correct arguments
    """
    from jamfV2 import Client
    mocker.patch.object(Client, '_http_request').return_value = {"access_token": "mocked token",
                                                                 "expires_in": 1119}
    client = Client(base_url="https://example.com",
                    verify=False, proxy=False, client_id="client_id", client_secret="client_secret")
    assert client.generate_client_credentials_token() == ('mocked token', 1711930719.0)
    assert client._http_request.call_args.kwargs["url_suffix"] == "/api/v1/oauth/token"
    assert client._http_request.call_args.kwargs["data"] == {'client_id': 'client_id', 'grant_type': 'client_credentials', 'client_secret': 'client_secret'}    # noqa
    assert client._http_request.call_args.kwargs["headers"] == {'Content-Type': 'application/x-www-form-urlencoded'}


def test_generate_token(mocker):
    """
    Given:
        - A Client instance with client_id and client_secret or username and password
    When:
        - generate_token is called
    Then:
        - Ensure the function calls the correct token generation function based on the provided parameters
    """
    from jamfV2 import Client
    client_credentials_token = mocker.patch.object(
        Client, 'generate_client_credentials_token', return_value=('mocked token', 1711930719.0))
    basic_auth_token = mocker.patch.object(Client, 'generate_basic_auth_token', return_value=('mocked token', 1672531199))

    Client(base_url="https://example.com", verify=False, proxy=False, client_id="client_id", client_secret="client_secret")
    assert client_credentials_token.call_count == 1

    Client(base_url="https://example.com", verify=False, proxy=False, username="username", password="password")
    assert basic_auth_token.call_count == 1


def test_get_computer_configuration_profiles_by_id(mocker):
    """
    Given:
        - Computer ID
    When:
        - get_profile_configuration_osx is called
    Then:
        - Ensure the function returns the correct output
    """
    from jamfV2 import Client, get_profile_configuration_osx
    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 1}
    mock_response = util_load_json('test_data/get_computer_configuration_profiles/'
                                   'get_computer_configuration_profiles_by_id_raw_response.json')
    mocker.patch.object(client, 'get_osxconfigurationprofiles_by_id', return_value=mock_response)

    outputs = get_profile_configuration_osx(client, args)
    assert outputs.outputs["general"]["id"] == 1


def test_get_mobile_configuration_profiles_by_id(mocker):
    """
    Given:
        - Mobile ID
    When:
        - get_profile_configuration_mobile is called
    Then:
        - Ensure the function returns the correct output
    """
    from jamfV2 import Client, get_profile_configuration_mobile
    mocker.patch.object(Client, '_get_token')
    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 1}
    mock_response = util_load_json('test_data/get_mobile_configuration_profiles/'
                                   'get_mobile_configuration_profiles_by_id_raw_response.json')
    mocker.patch.object(client, 'get_mobiledeviceconfigurationprofiles_by_id', return_value=mock_response)

    outputs = get_profile_configuration_mobile(client, args)
    assert outputs.outputs["general"]["id"] == 1
