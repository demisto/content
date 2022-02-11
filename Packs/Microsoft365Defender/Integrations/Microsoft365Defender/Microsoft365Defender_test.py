"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io

import pytest

import demistomock as demisto
from Microsoft365Defender import Client, fetch_incidents, _query_set_limit, main


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_convert_incident():
    from Microsoft365Defender import convert_incident_to_readable
    empty_incident = util_load_json("./test_data/empty_incident.json")
    assert convert_incident_to_readable(None) == empty_incident
    raw_incident = util_load_json("./test_data/raw_incident.json")
    converted_incident = util_load_json("./test_data/converted_incident.json")
    assert convert_incident_to_readable(raw_incident) == converted_incident


def mock_client(mocker, function: str = None, http_response=None):
    mocker.patch.object(demisto, 'getIntegrationContext',
                        return_value={'current_refresh_token': 'refresh_token', 'access_token': 'access_token'})
    client = Client(
        app_id='app_id',
        verify=False,
        proxy=False,
        base_url='https://api.security.microsoft.com'
    )
    if http_response:
        mocker.patch.object(client, function, return_value=http_response)
    return client


def check_api_response(results, results_mock):
    assert results.outputs_prefix == results_mock['outputs_prefix']
    assert results.outputs_key_field == results_mock['outputs_key_field']
    assert results.readable_output == results_mock['readable_output']
    assert results.outputs == results_mock['outputs']


def test_microsoft_365_defender_incidents_list_command(mocker):
    from Microsoft365Defender import microsoft_365_defender_incidents_list_command
    client = mock_client(mocker, 'incidents_list', util_load_json('./test_data/incidents_list_response.json'))
    results = microsoft_365_defender_incidents_list_command(client, {'limit': 10})
    check_api_response(results, util_load_json('./test_data/incidents_list_results.json'))


def test_microsoft_365_defender_incident_update_command(mocker):
    from Microsoft365Defender import microsoft_365_defender_incident_update_command
    client = mock_client(mocker, 'update_incident', util_load_json('./test_data/incident_update_response.json'))
    args = {'id': '263', 'tags': 'test1,test2', 'status': 'Active', 'classification': 'Unknown',
            'determination': 'Other'}
    results = microsoft_365_defender_incident_update_command(client, args)
    check_api_response(results, util_load_json('./test_data/incident_update_results.json'))


def test_microsoft_365_defender_advanced_hunting_command(mocker):
    from Microsoft365Defender import microsoft_365_defender_advanced_hunting_command
    client = mock_client(mocker, 'advanced_hunting', util_load_json('./test_data/advanced_hunting_response.json'))
    args = {'query': 'AlertInfo'}
    results = microsoft_365_defender_advanced_hunting_command(client, args)
    check_api_response(results, util_load_json('./test_data/advanced_hunting_results.json'))


def fetch_check(mocker, client, last_run, first_fetch_time, fetch_limit, mock_results):
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
    results = fetch_incidents(client, first_fetch_time, fetch_limit)
    assert len(results) == len(mock_results)
    for incident, mock_incident in zip(results, mock_results):
        assert incident['name'] == mock_incident['name']
        assert incident['occurred'] == mock_incident['occurred']
        assert incident['rawJSON'] == mock_incident['rawJSON']


def test_fetch_incidents(mocker):
    """
    This test check for 4 fetch cycles.
        First - get all the incidents and fill the queue 127, returns 50
        Second - get 50 incidents from the queue
        Third - tries to fill the queue with new incidents but there are no new ones so returns all the remaining
                incidents in the queue
        Forth - tries to fill the queue with new incidents but there are no new ones so returns empty list
    """
    response_dict = util_load_json('./test_data/fetch_response.json')
    client = Client(
        app_id='app_id',
        verify=False,
        proxy=False,
        base_url='https://api.security.microsoft.com'
    )
    mocker.patch.object(demisto, 'getIntegrationContext',
                        return_value={'current_refresh_token': 'refresh_token', 'access_token': 'access_token'})
    response_list = response_dict['response_list']
    mocker.patch.object(client, 'incidents_list', side_effect=response_list)

    first_fetch_time = "3000 days"
    fetch_limit = 50
    results = util_load_json('./test_data/fetch_results.json')

    for current_flow in ['first', 'second', 'third', 'forth']:
        fetch_check(mocker, client, response_dict[f'{current_flow}_last_run'], first_fetch_time, fetch_limit,
                    results[f'{current_flow}_result'])


@pytest.mark.parametrize('query, limit, result', [("a | b | limit 5", 10, "a | b | limit 10 "),
                                                  ("a | b ", 10, "a | b | limit 10 "),
                                                  ("a | b | limit 1 | take 1", 10, "a | b | limit 10 | limit 10 "),
                                                  ])
def test_query_set_limit(query: str, limit: int, result: str):
    assert _query_set_limit(query, limit) == result


def test_params(mocker):
    """
    Given:
      - Configuration parameters
    When:
      - The required parameter app_id is missed.
    Then:
      - Ensure the exception message as expected.
    """

    mocker.patch.object(demisto, 'params', return_value={'_tenant_id': '_tenant_id', 'credentials': {'password': '1234'}})
    mocker.patch.object(demisto, 'error')
    return_error_mock = mocker.patch('Microsoft365Defender.return_error')

    main()

    assert 'Application ID must be provided.' in return_error_mock.call_args[0][0]
