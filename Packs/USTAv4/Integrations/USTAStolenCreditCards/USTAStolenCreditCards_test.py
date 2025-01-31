"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import demistomock as demisto  # noqa: F401

from USTAStolenCreditCards import (
    Client, check_module, fetch_incidents, stolen_credit_cards_search_command, main, create_paging_header
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


def test_fetch_incidents(mocker):
    """Tests fetch_incidents function.

    Checks the output of the function with the expected output.
    """
    mock_response = util_load_json('test_data/stolen_credit_cards_incidents_response.json')
    expected_output = util_load_json('test_data/stolen_credit_cards_incidents_expected_output.json')

    client = Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )

    mocker.patch.object(client, 'stolen_credit_cards_incidents', return_value=mock_response)

    last_run = {}
    first_fetch_time = '2023-01-01T00:00:00Z'
    max_results = 10
    status = 'open'

    next_run, incidents = fetch_incidents(client, max_results, last_run, first_fetch_time, status)

    assert len(incidents) == len(mock_response)
    assert incidents == expected_output
    assert next_run['last_fetch'] == mock_response[0]['created']


def test_stolen_credit_cards_search_command(mocker):
    """Tests stolen_credit_cards_search_command function.

    Checks the output of the command function with the expected output.
    """
    mock_response = util_load_json('test_data/search_empty_response.json')

    client = Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )

    mocker.patch.object(client, 'stolen_credit_cards_search_api_request', return_value=mock_response)

    args = {
        'card_number': '1234567890123456',
        'page_size': 10,
        'page': 1
    }

    result = stolen_credit_cards_search_command(client, args)

    assert result.outputs == mock_response
    assert result.outputs_prefix == 'USTA.StolenCreditCards'
    assert result.outputs_key_field == 'id'


def test_stolen_credit_cards_search_command_no_result(mocker):
    """Tests stolen_credit_cards_search_command function when there are no results.

    Checks the output of the command function with the expected output.
    """
    mock_response = util_load_json('test_data/search_empty_response.json')

    client = Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )

    mocker.patch.object(client, 'stolen_credit_cards_search_api_request', return_value=mock_response)

    args = {
        'card_number': '1234567890123456',
        'page_size': 10,
        'page': 1
    }

    result = stolen_credit_cards_search_command(client, args)

    # make sure result.readable_output contains "No results found"
    assert result.readable_output == 'Showing 0 results, Size=10, from Page 1\n### Stolen Credit Cards\n**No entries.**\n'
    assert len(result.outputs['results']) == 0


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


def test_subsequent_run(mocker):
    """Tests fetch_incidents function.

    Checks the output of the function with the expected output.
    """
    mock_response = util_load_json('test_data/stolen_credit_cards_incidents_response.json')
    util_load_json('test_data/stolen_credit_cards_incidents_expected_output.json')

    client = Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )

    mocker.patch.object(client, 'stolen_credit_cards_incidents', return_value=mock_response)

    last_run = {'last_fetch': '2024-11-27T08:04:45.106412Z'}
    first_fetch_time = '2024-11-27T08:04:45.106412Z'
    max_results = 10
    status = 'open'

    next_run, incidents = fetch_incidents(client, max_results, last_run, first_fetch_time, status)

    assert len(incidents) == 2
    assert next_run['last_fetch'] == '2024-11-27T08:04:45.106412Z'
    assert next_run['last_ids'] == [13371337]


def test_main_fetch_incidents_cmd(mocker):
    """Tests main function.

    Checks the output of the function with the expected output.
    """
    mock_response = util_load_json('test_data/stolen_credit_cards_incidents_response.json')

    Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )

    mocker.patch.object(Client, 'stolen_credit_cards_incidents', return_value=mock_response)

    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://example.com',
        'api_key': 'API_KEY',
        'insecure': True,
        'proxy': False,
        'first_fetch': '3 days'
    })
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')
    main()

    demisto.incidents.assert_called_once()
    demisto.results.assert_not_called()
    demisto.setLastRun.assert_called_once()


def test_main_test_module_cmd(mocker):
    """Tests main function.

    Checks the output of the function with the expected output.
    """
    mock_response = util_load_json('test_data/stolen_credit_cards_search_response.json')

    Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://example.com',
        'api_key': 'API_KEY',
        'insecure': True,
        'proxy': False,
        'first_fetch': '3 days'
    })
    mocker.patch.object(Client, 'check_auth', return_value=mock_response)
    mocker.patch.object(Client, 'stolen_credit_cards_search_api_request', return_value=mock_response)
    mocker.patch.object(demisto, 'command', return_value='usta-scc-search')
    mocker.patch.object(demisto, 'args', return_value={
        'card_number': '1234567890123456',
    })
    main()

    # make sure check_module and return_results functions were called
