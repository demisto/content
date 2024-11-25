"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module(mocker):
    """Tests test_module command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the test_module_command does not call
    any external API.
    """
    from USTAAccountTakeoverPrevention import Client, test_module

    mock_response = util_load_json('test_data/auth_success_response.json')

    client = Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )

    mocker.patch.object(client, 'check_auth', return_value=mock_response)

    response = test_module(client)
    assert response == 'ok'

def test_compromised_credentials_search_command(mocker):
    """Tests compromised_credentials_search command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the compromised_credentials_search_command does not call
    any external API.
    """
    from USTAAccountTakeoverPrevention import Client, compromised_credentials_search_command

    mock_response = util_load_json('test_data/compromised_credentials_search_response.json')

    client = Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )
    mocker.patch.object(client, 'compromised_credentials_search_api_request', return_value=mock_response)
    response = compromised_credentials_search_command(client, {'username': 'user'})
    assert response.outputs == mock_response
    

def test_compromised_credentials_search_command_no_results(mocker):
    """Tests compromised_credentials_search command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the compromised_credentials_search_command does not call
    any external API.
    """
    from USTAAccountTakeoverPrevention import Client, compromised_credentials_search_command
    mock_response = util_load_json('test_data/compromised_credentials_search_empty_response.json')

    client = Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )
    mocker.patch.object(client, 'compromised_credentials_search_api_request', return_value=mock_response)
    response = compromised_credentials_search_command(client, {'username': 'user'})
    assert response.outputs == mock_response

def test_fetch_incidents(mocker):
    """Tests fetch_incidents command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the fetch_incidents_command does not call
    any external API.
    """
    from USTAAccountTakeoverPrevention import Client, fetch_incidents, USTA_API_PREFIX

    base_url = f'https://usta.prodaft.com/{USTA_API_PREFIX}'

    mock_response = util_load_json('test_data/fetch_incidents_response.json')
    expected_output = util_load_json('test_data/fetch_incidents_expected_output.json')

    headers: dict = {
        'Authorization': 'token test123',
        'Content-Type': 'application/json'
    }

    client = Client(
        base_url=base_url,
        verify=False,
        headers=headers,
        proxy=False
    )

    mocker.patch.object(client, 'compromised_credentials_api_request', return_value=mock_response)

    next_run, incidents = fetch_incidents(
        client=client,
        max_results=100,
        last_run={},
        first_fetch_time='3 days'
    )
    assert incidents == expected_output
