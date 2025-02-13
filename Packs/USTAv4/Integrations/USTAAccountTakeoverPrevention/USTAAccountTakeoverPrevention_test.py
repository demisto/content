"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import pytest
import demistomock as demisto  # noqa: F401


from USTAAccountTakeoverPrevention import (
    Client, main, check_module, compromised_credentials_search_command,
    fetch_incidents, convert_to_demisto_severity, create_paging_header
)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_check_module(mocker):
    """Tests test_module command function.

    Checks the output of the command function with the expected output.
    """
    mock_response = util_load_json('test_data/auth_success_response.json')

    client = Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )

    mocker.patch.object(client, 'check_auth', return_value=mock_response)

    response = check_module(client)
    assert response == 'ok'


@pytest.mark.parametrize('username, mock_response_file, expected_output_file', [
    ('user1', 'test_data/compromised_credentials_search_response.json', 'test_data/compromised_credentials_search_response.json'),
    ('user2', 'test_data/search_empty_response.json',
     'test_data/search_empty_response.json'),
])
def test_compromised_credentials_search_command(mocker, username, mock_response_file, expected_output_file):
    """Tests compromised_credentials_search command function with multiple test cases.

    Checks the output of the command function with the expected output.

    No mock is needed here because the compromised_credentials_search_command does not call
    any external API.
    """

    mock_response = util_load_json(mock_response_file)
    expected_output = util_load_json(expected_output_file)
    _count = len(mock_response.get('results', []))

    client = Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )
    mocker.patch.object(client, 'compromised_credentials_search_api_request', return_value=mock_response)
    response = compromised_credentials_search_command(client, {'username': username})
    assert response.readable_output.startswith(f'Showing {_count} results')
    assert response.outputs == expected_output


def test_fetch_incidents(mocker):
    """Tests fetch_incidents command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the fetch_incidents_command does not call
    any external API.
    """

    mock_response = util_load_json('test_data/compromised_credentials_fetch_incidents_response.json')
    expected_output = util_load_json('test_data/compromised_credentials_fetch_incidents_expected_output.json')

    client = Client(
        base_url='',
        verify=False,
        headers={},
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
    assert len(incidents) == 1
    assert next_run['last_ids'] == [7668573]


def test_subsequent_run(mocker):
    """
    Given:
        - A last run with a last fetch time and list of last incident IDs
    When:
        - Fetch incidents is called with the last run
        - First fetch time is provided
    Then:
        - Returned incidents should have occurred after last fetch
        - Number of returned incidents should match max results
        - Next run should have new updated last incident IDs
    """
    last_run = {'last_fetch': '2021-02-01T00:00:00Z', 'last_ids': [1, 2, 3]}
    first_fetch = last_run.get('last_fetch')
    mock_response = util_load_json('test_data/compromised_credentials_fetch_incidents_response.json')
    expected_output = util_load_json('test_data/compromised_credentials_fetch_incidents_expected_output.json')

    client = Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )

    mocker.patch.object(client, 'compromised_credentials_api_request', return_value=mock_response)

    next_run, incidents = fetch_incidents(
        client=client,
        max_results=3,
        last_run=last_run,
        first_fetch_time=first_fetch
    )

    assert len(incidents) == 1
    assert incidents[0]['occurred'] > first_fetch
    assert incidents == expected_output
    assert next_run['last_ids'] == [7668573]


@pytest.mark.parametrize('hello_world_severity, expected_xsoar_severity', [
    ('low', 1), ('medium', 2), ('high', 3), ('critical', 4), ('unknown', 0)
])
def test_convert_to_demisto_severity(hello_world_severity, expected_xsoar_severity):
    """
        Given:
            - A string represents a HelloWorld severity.

        When:
            - Running the 'convert_to_demisto_severity' function.

        Then:
            - Verify that the severity was correctly translated to a Cortex XSOAR severity.
    """
    assert convert_to_demisto_severity(hello_world_severity) == expected_xsoar_severity


def test_convert_to_demisto_severity_invalid():
    """
        Given:
            - An invalid HelloWorld severity.

        When:
            - Running the 'convert_to_demisto_severity' function.

        Then:
            - Verify that the function raises a ValueError.
    """
    with pytest.raises(KeyError):
        convert_to_demisto_severity('invalid')


def test_create_paging_header():
    """
        Given:
            - A number of results, page number and page size.

        When:
            - Running the 'create_paging_header' function.

        Then:
            - Verify that the function returns the correct paging header.
    """
    results_num = 10
    page = 2
    size = 5

    expected_output = 'Showing 10 results, Size=5, from Page 2\n'
    assert create_paging_header(results_num, page, size) == expected_output


def test_compromised_credentials_search_api_request(mocker):
    """
        Given:
            - A client and a status.

        When:
            - Running the 'compromised_credentials_search_api_request' function.

        Then:
            - Verify that the function returns the correct response.
    """
    mock_response = util_load_json('test_data/compromised_credentials_search_response.json')

    client = Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )

    mocker.patch.object(client, '_http_request', return_value=mock_response)

    response = client.compromised_credentials_search_api_request(status=1, start='2021-02-01T00:00:00Z', size=100)

    assert response == mock_response


def test_main_search_cmd(mocker):
    """
    Given:
        - A command to execute.
    When:
        - Running the main function.
    Then:
        - Verify that the correct command function is called with the correct arguments.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://example.com',
        'api_key': 'API_KEY',
        'insecure': True,
        'proxy': False,
        'first_fetch': '3 days',
        'status': 'open',
        'max_fetch': 50
    })

    Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )
    mocker.patch.object(demisto, 'args', return_value={'username': 'user1'})
    mocker.patch.object(demisto, 'command', return_value='usta-atp-search-username')
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(Client, 'check_auth')
    mocker.patch.object(Client, 'compromised_credentials_search_api_request',
                        return_value=util_load_json('test_data/compromised_credentials_search_response.json'))

    main()

    demisto.results.assert_called_once()
    demisto.setLastRun.assert_not_called()
    demisto.incidents.assert_not_called()


def test_main_fetch_incidents_cmd(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://example.com',
        'api_key': 'API_KEY',
        'insecure': True,
        'proxy': False,
        'first_fetch': '3 days',
        'status': 'open',
        'max_fetch': 50
    })

    Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )
    mock_response = util_load_json('test_data/compromised_credentials_fetch_incidents_response.json')
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(Client, 'compromised_credentials_api_request', return_value=mock_response)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')
    main()

    demisto.incidents.assert_called_once()
    demisto.results.assert_not_called()
    demisto.setLastRun.assert_called_once()
