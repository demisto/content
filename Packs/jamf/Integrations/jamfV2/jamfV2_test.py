"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
from CommonServerPython import *


def load_xml_response(file_name: str) -> str:
    with io.open(file_name, mode='r', encoding='utf-8') as xml_file:
        return xml_file.read()


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
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
    for key, val in results.get("EntryContext").items():
        assert results.get("EntryContext")[key] == get_endpoints_response[key]
    assert results.get("EntryContext") == get_endpoints_response
    assert len(outputs) == 1
