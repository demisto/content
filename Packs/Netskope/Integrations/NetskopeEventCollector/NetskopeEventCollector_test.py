import io
import json
import re
from NetskopeEventCollector import Client, ALL_SUPPORTED_EVENT_TYPES


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_events_entry.json')
EVENTS_RAW = util_load_json('test_data/events_raw.json')
# EVENTS_RAW_V2_MULTI = util_load_json('test_data/events_raw_v2_2_results.json')
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
    url_matcher = re.compile('https://netskope.example.com/events/dataexport/events')
    requests_mock.get(url_matcher, json=json_callback)
    events, new_last_run = get_all_events(client, FIRST_LAST_RUN, limit=6, is_command=False)
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
    results, events = get_events_command(client, args={}, last_run=FIRST_LAST_RUN, is_command=True)
    assert 'Events List' in results.readable_output
    assert len(events) == 9
    assert results.outputs_prefix == 'Netskope.Event'
    assert results.outputs == MOCK_ENTRY
