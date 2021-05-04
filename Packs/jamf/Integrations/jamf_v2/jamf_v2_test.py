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

from pytest import raises


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
    from jamf_v2 import Client, get_computers_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {}
    mock_response = util_load_json('test_data/get_computer/get_computer_raw_response.json')

    mocker.patch.object(client, 'get_computers_request', return_value=mock_response)

    computer_response = get_computers_command(client, args)
    expected_response = util_load_json('test_data/get_computer/get_computer_context.json')
    assert computer_response.outputs == expected_response


def test_get_computers_limit_command(mocker):
    """
    Given
    - Limit and page arguments
    When
    - Run get computers command
    Then
    - Ensure the result are according to the limit and page
    """
    from jamf_v2 import Client, get_computers_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'limit': 10, 'page': 2}
    mock_response = util_load_json('test_data/get_computer/get_computer_raw_response.json')

    mocker.patch.object(client, 'get_computers_request', return_value=mock_response)

    response = get_computers_command(client, args)
    expected_response = util_load_json('test_data/get_computer/get_computer_limit_context.json')
    assert response.outputs == expected_response


def test_get_computers_by_id_command(mocker):
    """
    Given
    - Computer ID.
    When
    - Run get computers command
    Then
    - Get results on specific computer ID.
    """
    from jamf_v2 import Client, get_computers_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 1}
    mock_response = util_load_json('test_data/get_computer/get_computer_by_id_raw_response.json')

    mocker.patch.object(client, 'get_computers_request', return_value=mock_response)

    response = get_computers_command(client, args)
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
    from jamf_v2 import Client, get_computers_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'match': '564D26*'}
    mock_response = util_load_json('test_data/get_computer/get_computer_by_match_raw_response.json')

    mocker.patch.object(client, 'get_computers_request', return_value=mock_response)

    response = get_computers_command(client, args)
    expected_response = util_load_json('test_data/get_computer/get_computer_by_match_context.json')
    assert response.outputs == expected_response


def test_get_computer_subset_command(mocker):
    """
    Given
    - Name of the computer and subset arguments.
    When
    - Run get computer subset command
    Then
    - Ensure the command output matched the given query.
    """
    from jamf_v2 import Client, get_computer_subset_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'identifier': 'name', 'identifier_value': 'Computer 95', 'subset': 'Location'}
    mock_response = util_load_json('test_data/get_computer_subset/get_computer_by_name_subset_raw_response.json')

    mocker.patch.object(client, 'get_computer_subset_request', return_value=mock_response)

    computer_response = get_computer_subset_command(client, args)
    expected_response = util_load_json('test_data/get_computer_subset/get_computer_by_name_subset_context.json')
    assert computer_response.outputs == expected_response


def test_get_computer_no_subset_command():
    """
    Given
    - Missing subset argument.
    When
    - Run get computer subset command
    Then
    - Ensure getting an error.
    """
    from jamf_v2 import Client, get_computer_subset_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'identifier': 'name', 'identifier_value': 'Computer 95'}
    error_msg = 'You must specify subset argument.'

    with raises(DemistoException, match=error_msg):
        get_computer_subset_command(client, args)


def test_get_computer_no_identifier_command():
    """
    Given
    - Missing subset argument.
    When
    - Run get computer subset command
    Then
    - Ensure getting an error.
    """
    from jamf_v2 import Client, get_computer_subset_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'identifier': None, 'identifier_value': 'Computer 95', 'subset': 'Location'}
    error_msg = 'You must specify identifier and identifier_value arguments.'

    with raises(DemistoException, match=error_msg):
        get_computer_subset_command(client, args)


def test_computer_lock_command(mocker):
    """
    Given
    - Get computers command with no arguments.
    When
    - Run get computers command
    Then
    - Ensure the response matches the default limit.
    """
    from jamf_v2 import Client, computer_lock_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 138, 'passcode': 123456, 'lock_msg': 'Test'}
    mock_response = load_xml_response('test_data/computer_lock/computer_lock_raw_response.xml')

    mocker.patch.object(client, 'computer_lock_request', return_value=json.loads(xml2json(mock_response)))

    computer_response = computer_lock_command(client, args)
    expected_response = util_load_json('test_data/computer_lock/computer_lock_context.json')
    assert computer_response.outputs == expected_response

BLA = '<?xml version="1.0" encoding="UTF-8"?>' + \
        '<html>' + \
        '<head>' + \
           '<title>Status page</title>' + \
        '</head>' + \
        '<body style="font-family: sans-serif;">' + \
        '<p style="font-size: 1.2em;font-weight: bold;margin: 1em 0px;">Bad Request</p>' + \
        '<p>Unable to match computer </p>' + \
        '<p>You can get technical details <a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.4.1">here</a>.<br>' + \
        'Please continue your visit at our <a href="/">home page</a>.' + \
        '</p>' + \
        '</body>' + \
        '</html>'


def test_computer_lock_no_id_command(mocker):
    """
    Given
    - Computer id which doesnt exists.
    When
    - lock computer
    Then
    - Getting error.
    """
    from jamf_v2 import Client, computer_lock_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 555, 'passcode': 123456, 'lock_msg': 'Test'}

    mock_response = DemistoException("ID doesn't exist.")

    mocker.patch.object(client, '_http_request', return_value=mock_response)
    mocker.patch.object(json, 'loads')

    error_msg = "ID doesn't exist."

    with raises(DemistoException, match=error_msg):
        computer_lock_command(client, args)


def test_computer_erase_command(mocker):
    """
    Given
    - erase computer command with id and passcode.
    When
    - Run erase computer command
    Then
    - Ensure the response matches .
    """
    from jamf_v2 import Client, computer_erase_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 138, 'passcode': 123456}
    mock_response = load_xml_response('test_data/computer_lock/computer_lock_raw_response.xml')

    mocker.patch.object(client, 'computer_erase_request', return_value=json.loads(xml2json(mock_response)))

    computer_response = computer_erase_command(client, args)
    expected_response = util_load_json('test_data/computer_lock/computer_lock_context.json')
    assert computer_response.outputs == expected_response


def test_computer_erase_no_id_command(mocker):
    """
    Given
    - Computer id which doesnt exists.
    When
    - lock computer
    Then
    - Getting error.
    """
    from jamf_v2 import Client, computer_lock_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'id': 555, 'passcode': 123456, 'lock_msg': 'Test'}

    mock_response = DemistoException("ID doesn't exist.")

    mocker.patch.object(client, '_http_request', return_value=mock_response)
    mocker.patch.object(json, 'loads')

    error_msg = "ID doesn't exist."

    with raises(DemistoException, match=error_msg):
        computer_lock_command(client, args)


def test_get_users_command(mocker):
    """
    Given
    - Get users command with no arguments.
    When
    - Run get users command
    Then
    - Ensure the response matches the default limit.
    """
    from jamf_v2 import Client, get_users_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {}
    mock_response = util_load_json('test_data/get_users/get_users_raw_response.json')

    mocker.patch.object(client, 'get_users_request', return_value=mock_response)

    users_response = get_users_command(client, args)
    expected_response = util_load_json('test_data/get_users/get_users_context.json')
    assert users_response.outputs == expected_response


def test_get_users_limit_command(mocker):
    """
    Given
    - Limit and page arguments
    When
    - Run get users command
    Then
    - Ensure the result are according to the limit and page
    """
    from jamf_v2 import Client, get_users_command

    client = Client(base_url='https://paloaltonfr3.jamfcloud.com', verify=False)
    args = {'limit': 10, 'page': 2}
    mock_response = util_load_json('test_data/get_users/get_users_raw_response.json')

    mocker.patch.object(client, 'get_users_request', return_value=mock_response)

    users_response = get_users_command(client, args)
    expected_response = util_load_json('test_data/get_users/get_users_limit_context.json')
    assert users_response.outputs == expected_response

