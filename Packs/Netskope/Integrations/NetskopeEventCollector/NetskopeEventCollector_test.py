import io
import json
import re
import time

import dateparser
import pytest

from NetskopeEventCollector import Client, ALL_SUPPORTED_EVENT_TYPES, RATE_LIMIT_REMAINING, RATE_LIMIT_RESET


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
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
    client = Client(BASE_URL, 'dummy_token', False, False)
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
    client = Client(BASE_URL, 'netskope_token', validate_certificate=False, proxy=False)
    url_matcher = re.compile('https://netskope[.]example[.]com/events/dataexport/events')
    requests_mock.get(url_matcher, json=json_callback)
    events, new_last_run = get_all_events(client, FIRST_LAST_RUN)
    assert len(events) == 25
    assert events[0].get('event_id') == '1'
    assert events[0].get('_time') == '2023-05-22T10:30:16.000Z'
    assert all([new_last_run[event_type]['operation'] == 'next' for event_type in ALL_SUPPORTED_EVENT_TYPES])


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
    client = Client(BASE_URL, 'dummy_token', False, False)
    mocker.patch('NetskopeEventCollector.get_all_events', return_value=[MOCK_ENTRY, {}])
    mocker.patch.object(time, "sleep")
    results, events = get_events_command(client, args={}, last_run=FIRST_LAST_RUN)
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
      'network': {'operation': 'next'}}, 'next'),
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
    last_run = setup_last_run(last_run_dict)
    assert all([val.get('operation') == expected_operation_value for key, val in last_run.items()])
