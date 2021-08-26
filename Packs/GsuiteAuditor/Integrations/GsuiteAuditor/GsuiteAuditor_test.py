"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
import time

import pytest
import demistomock as demisto

from GSuiteAuditor import activities_list_command, fetch_incidents, get_new_last_run, GSuiteClient

MOCKER_HTTP_METHOD = 'GSuiteApiModule.GSuiteClient.http_request'

with open('test_data/service_account_json.txt') as j:
    TEST_JSON = j.read()


@pytest.fixture
def gsuite_client():
    headers = {
        'Content-Type': 'application/json'
    }
    return GSuiteClient(GSuiteClient.safe_load_non_strict_json(TEST_JSON), verify=False, proxy=False, headers=headers)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def fetch_check(mocker, client, last_run, first_fetch_time, fetch_limit, applications, mock_results):
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
    results = fetch_incidents(client, first_fetch_time, fetch_limit, applications)
    assert len(results) == len(mock_results)
    for incident, mock_incident in zip(results, mock_results):
        assert incident['name'] == mock_incident['name']
        assert incident['occurred'] == mock_incident['occurred']
        assert incident['rawJSON'] == mock_incident['rawJSON']


def test_activities_list_command(gsuite_client, mocker):
    """
        Scenario: gsuite-activities-list command is called with valid arguments.

        Given:
        - Command args.

        When:
        - Calling activities_list with command arguments.

        Then:
        - Ensure CommandResult should return data as expected. with and without results
        """

    arguments = {
        'user_key': 'all',
        'application_name': 'admin'
    }
    api_response = util_load_json('test_data/activities_list_response.json')
    expected_entry_context = util_load_json('test_data/activities_list_entry_context.json')

    mocker.patch.object(gsuite_client, 'http_request', return_value=api_response)

    command_result = activities_list_command(gsuite_client, arguments)
    assert command_result.readable_output == expected_entry_context['readable_output']
    assert command_result.outputs == expected_entry_context['outputs']
    assert command_result.raw_response == expected_entry_context['raw_response']


def test_fetch_incidents_leftover_check(gsuite_client, mocker):
    """
    Test several fetches one by one-
    1. Fetch new incidents (first run), fetch more then limit and have leftover (return 3 keep 4)
    2. Run again, return items from leftovers only (return 3 keep 1)
    3. Run again, take some items from leftovers and make request to receive more (1 leftover, 2 new)
    """
    response_dict = util_load_json('./test_data/fetch_response.json')
    fetch_limit = 3
    first_fetch_time = "1 hours"
    applications = ['token']

    mocker.patch.object(gsuite_client, 'http_request', return_value=response_dict['First run'])
    fetch_check(mocker, gsuite_client, {}, first_fetch_time, fetch_limit, applications,
                response_dict['First results']['incidents'])

    fetch_check(mocker, gsuite_client, response_dict['First results']['last_run'], first_fetch_time, fetch_limit,
                applications, response_dict['Second results']['incidents'])

    mocker.patch.object(gsuite_client, 'http_request', return_value=response_dict['Second run'])
    fetch_check(mocker, gsuite_client, response_dict['Second results']['last_run'], first_fetch_time, fetch_limit,
                applications, response_dict['Third results']['incidents'])


def test_get_new_last_run(gsuite_client, mocker):
    """
    Test several scenarios one by one-
    1. new incidents were fetched , run_time is updated by incidents
    2. no incidents were fetched, still not in real time- run_time is updated
    3. no incidents were fetched, now in real time- run time is not updated
    """

    response_dict = util_load_json('./test_data/fetch_response.json')
    end_time = "2021-08-19T07:00:00.000Z"
    last_run = "2021-08-19T06:00:00.000Z"

    last_leftover_item = response_dict['First results']['last_run']['last_leftover_items'][-1]
    assert get_new_last_run(last_leftover_item, None, end_time, last_run) == "2021-08-19T06:01:01.465000Z"

    mocker.patch.object(time, 'ctime', return_value="2021-08-19T08:00:00Z")
    assert get_new_last_run(None, None, end_time, last_run) == end_time

    mocker.patch.object(time, 'ctime', return_value="2021-08-19T06:30:00Z")
    assert get_new_last_run(None, None, end_time, last_run) == last_run


def test_fetch_with_multiple_apps(gsuite_client, mocker):
    """
       Scenario: fetch command is called and results are fetched

       Given:
       - 3 different applications

       Then: make sure results are correct
    """
    response_dict = util_load_json('./test_data/fetch_response_mult_app.json')
    fetch_limit = 5
    first_fetch_time = "1 hours"
    applications = ['admin', 'login', 'drive']

    mocker.patch.object(gsuite_client, 'http_request', side_effect=response_dict['responses'])
    fetch_check(mocker, gsuite_client, {}, first_fetch_time, fetch_limit, applications,
                response_dict['results']['incidents'])
