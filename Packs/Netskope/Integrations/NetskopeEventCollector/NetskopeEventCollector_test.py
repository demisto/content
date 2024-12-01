import json
import re
import time
from unittest.mock import MagicMock
import demistomock as demisto
import dateparser
import pytest
from NetskopeEventCollector import ALL_SUPPORTED_EVENT_TYPES, RATE_LIMIT_REMAINING, RATE_LIMIT_RESET, Client


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_events_entry.json')
EVENTS_RAW = util_load_json('test_data/events_raw.json')
EVENTS_PAGE_RAW = util_load_json('test_data/multiple_events_raw.json')
BASE_URL = 'https://netskope.example.com'
FIRST_LAST_RUN = {'alert': {'operation': 1680182467}, 'application': {'operation': 1680182467},
                  'audit': {'operation': 1680182467}, 'network': {'operation': 1680182467}, 'page': {'operation': 1680182467}}


def test_test_module(mocker):
    """
    Given:
        - raw_response of an event (as it returns from the api)
    When:
        - Running the test_module command
    Then:
        - Verify that 'ok' is returned.
    """
    from NetskopeEventCollector import test_module
    client = Client(BASE_URL, 'dummy_token', False, False, event_types_to_fetch=ALL_SUPPORTED_EVENT_TYPES)
    mocker.patch.object(client, 'perform_data_export', return_value=EVENTS_RAW)
    results = test_module(client, last_run=FIRST_LAST_RUN, max_fetch=1)
    assert results == 'ok'


def test_populate_prepare_events():
    """
    Given:
        - Event from the API of type audit
    When:
        - Running the command
    Then:
        - Make sure the _time, evnet_id, and source_log_event fields are populated properly.
    """
    from NetskopeEventCollector import prepare_events
    event = EVENTS_RAW.get('result')[0]
    prepare_events([event], event_type='audit')
    assert event.get('_time') == '2022-01-18T19:58:07.000Z'
    assert event.get('source_log_event') == 'audit'
    assert event.get('event_id') == 'f0e9b2cadd17402b59b3938b'


def test_get_all_events(requests_mock):
    """
    Given:
        - netskope-get-events call
    When:
        - Running the get_all_events command
    Then:
        - Make sure the number of events returns as expected
        - Make sure that the _time and event_id fields are populated as expected
        - Make sure the new_last_run is set.
    """

    def json_callback(request, _):
        endpoint = request.path.split('/')[-1]
        return EVENTS_PAGE_RAW[endpoint]

    from NetskopeEventCollector import get_all_events
    client = Client(BASE_URL, 'netskope_token', validate_certificate=False,
                    proxy=False, event_types_to_fetch=ALL_SUPPORTED_EVENT_TYPES)
    url_matcher = re.compile('https://netskope[.]example[.]com/events/dataexport/events')
    requests_mock.get(url_matcher, json=json_callback)
    events = []
    new_last_run = get_all_events(client, FIRST_LAST_RUN, all_event_types=events)
    assert len(events) == 26
    assert events[0].get('event_id') == '1'
    assert events[0].get('_time') == '2023-05-22T10:30:16.000Z'
    assert all(new_last_run[event_type]['operation'] == 'next' for event_type in ALL_SUPPORTED_EVENT_TYPES)


def test_get_events_command(mocker):
    """
    Given:
        - netskope-get-events call
    When:
        - Running the get_events_command
    Then:
        - Make sure the number of events returns as expected
        - Make sure that human_readable returned as expected
        - Make sure the outputs are set correctly.
    """
    from NetskopeEventCollector import get_events_command
    client = Client(BASE_URL, 'dummy_token', False, False, event_types_to_fetch=ALL_SUPPORTED_EVENT_TYPES)
    mocker.patch('NetskopeEventCollector.get_all_events', return_value={})
    mocker.patch.object(time, "sleep")
    results, events = get_events_command(client, args={}, last_run=FIRST_LAST_RUN, events=MOCK_ENTRY)
    assert 'Events List' in results.readable_output
    assert len(events) == 9
    assert results.outputs_prefix == 'Netskope.Event'
    assert results.outputs == MOCK_ENTRY


@pytest.mark.parametrize('headers, endpoint, expected_sleep', [
    ({RATE_LIMIT_REMAINING: 1}, 'test_endpoint', None),
    ({}, 'test_endpoint', None),
    ({RATE_LIMIT_REMAINING: 0, RATE_LIMIT_RESET: 2}, 'test_endpoint', 2),
    ({RATE_LIMIT_REMAINING: 0}, 'test_endpoint', 1),
])
def test_honor_rate_limiting(mocker, headers, endpoint, expected_sleep):
    """
    Given:
        Case a: Netskope response headers with RATE_LIMIT_REMAINING = 1
        Case b: Netskope with response headers
        Case c: Netskope with response headers RATE_LIMIT_REMAINING = 1 and RATE_LIMIT_RESET = 2
        Case c: Netskope with response headers RATE_LIMIT_REMAINING = 0

    When:
        Checking if sleeping is required

    Then:
        Case a: validate that there is no sleeping
        Case b: validate that there is no sleeping
        Case c: validate that we sleep for 2 secs (which is the reset time)
        Case c: validate that we sleep for 1 sec (which is the default in case not rest time is given)
    """
    time_mock = mocker.patch.object(time, "sleep")
    from NetskopeEventCollector import honor_rate_limiting
    honor_rate_limiting(headers=headers, endpoint=endpoint)
    if expected_sleep:
        time_mock.assert_called_once_with(expected_sleep)
    else:
        time_mock.assert_not_called()


@pytest.mark.parametrize('last_run_dict, expected_operation_value', [
    ({}, 1672567200),
    ({'application': {'operation': 'next'},
      'alert': {'operation': 'next'},
      'page': {'operation': 'next'},
      'audit': {'operation': 'next'},
      'network': {'operation': 'next'},
      'incident': {'operation': 'next'}}, 'next'),
])
def test_setup_last_run(mocker, last_run_dict, expected_operation_value):
    """
    Given:
        Case a: previous empty last run
        Case a: previous last run with operation= 'next' for all event types

    When:
        Setting the last run values for the current run

    Then:
        Case a: make sure all event types in last run are saved with operation= 1672567200
        Case b: make sure all event types in last run are saved with operation= 'next'

    """
    from NetskopeEventCollector import setup_last_run
    first_fetch = dateparser.parse('2023-01-01T10:00:00Z')
    mocker.patch.object(dateparser, "parse", return_value=first_fetch)
    last_run = setup_last_run(last_run_dict, ALL_SUPPORTED_EVENT_TYPES)
    assert all(val.get('operation') == expected_operation_value for _, val in last_run.items())


@pytest.mark.parametrize('event_types_to_fetch_param, expected_value', [
    ('Application', ['application']),
    ('Alert, Page, Audit', ['alert', 'page', 'audit']),
    (['Application', 'Audit', 'Network', 'Incident'], ['application', 'audit', 'network', 'incident']),
    ('Incident', ['incident']),
    (None, ALL_SUPPORTED_EVENT_TYPES),
])
def test_event_types_to_fetch_parameter_handling(event_types_to_fetch_param, expected_value):
    """
    Given:
        Case a: event_types_to_fetch parameter has a single value
        Case b: event_types_to_fetch parameter has multiple values
        Case c: event_types_to_fetch parameter is a pythonic list
        Case d: event_types_to_fetch parameter is None

    When:
        Handling the event_types_to_fetch parameter

    Then:
        - Make sure the parameter converts into a valid pythonic list
        - The values are lowercase
        - In the case event_types_to_fetch in None, default ALL_SUPPORTED_EVENT_TYPES is used as parameter

    """
    from NetskopeEventCollector import handle_event_types_to_fetch
    assert handle_event_types_to_fetch(event_types_to_fetch_param) == expected_value


@pytest.mark.parametrize('num_fetched_events, max_fetch_events, new_next_run, expected_result',
                         [(200, 250, {'key': 'value'}, {'nextTrigger': '0', 'key': 'value'}),
                          (1000, 5000, {'nextTrigger': '0'}, {}),
                          (0, 0, {'key': 'value'}, {'key': 'value'}),
                          (0, 0, {}, {}),
                          (2500, 5000, {'nextTrigger': '0'}, {}),
                          (2501, 5000, {'key': 'value', 'nextTrigger': '0'}, {'key': 'value', 'nextTrigger': '0'})])
def test_next_trigger_time(num_fetched_events, max_fetch_events, new_next_run, expected_result):
    """
    Given:
        - The number of fetched events and the max_fetch integration parameter.

    When:
        - Setting the new last_run

    Then:
        - Check that the last run is modified with the nextTrigger: '0',
            only if more than half of the max_fetch amount was fetched.
    """
    from NetskopeEventCollector import next_trigger_time
    next_trigger_time(num_fetched_events, max_fetch_events, new_next_run)
    assert new_next_run == expected_result


@pytest.mark.parametrize(
    "last_run, supported_event_types, expected_result",
    [
        (
            {
                "alert": {"operation": "next"},
                "audit": {"operation": "next"},
                "network": {"operation": "next"},
                "nextTrigger": "0",
                "page": {"operation": "next"},
            },
            ["alert"],
            {"nextTrigger": "0", "alert": {"operation": "next"}},
        ),
        ({}, ["alert"], {}),
        (
            {
                "alert": {"operation": "next"},
                "audit": {"operation": "next"},
                "network": {"operation": "next"},
            },
            ["audit", "network"],
            {"audit": {"operation": "next"}, "network": {"operation": "next"}},
        ),
    ],
)
def test_fix_last_run(last_run, supported_event_types, expected_result):
    """
    Given:
        - last run dict and supported event types.
    When:
        - preparing the last_run before execution.
    Then:
        - remove unsupported event types.
    """
    from NetskopeEventCollector import remove_unsupported_event_types
    remove_unsupported_event_types(last_run, supported_event_types)
    assert last_run == expected_result


def test_incident_endpoint(mocker):
    """
    Given:
        - Netskope client set to fetch incident events.
    When:
        - Fetching events.
    Then:
        - Assert that the Netskope end point is called with the proper url and paras.
    """
    from datetime import datetime
    from NetskopeEventCollector import handle_data_export_single_event_type
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationInstance': 'test_instance'}})
    mocker.patch('NetskopeEventCollector.is_execution_time_exceeded', return_value=False)
    mocker.patch('NetskopeEventCollector.print_event_statistics_logs')
    client = Client(BASE_URL, 'dummy_token', False, False, event_types_to_fetch=['incident'])
    mock_response = MagicMock()
    mock_response.json.return_value = {'result': EVENTS_RAW['result'], 'wait_time': 0}
    request_mock = mocker.patch.object(Client, '_http_request', return_value=mock_response)
    handle_data_export_single_event_type(client, 'incident', 'next', limit=50,
                                         execution_start_time=datetime.now(), all_event_types=[])
    kwargs = request_mock.call_args.kwargs
    assert kwargs['url_suffix'] == 'events/dataexport/events/incident'
    assert kwargs['params'] == {'index': 'xsoar_collector_test_instance_incident', 'operation': 'next'}
