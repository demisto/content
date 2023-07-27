import io
import json

from NetskopeEventCollector import Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_events.json')
EVENTS_RAW_V2 = util_load_json('test_data/events_raw_v2.json')
EVENTS_RAW_V2_MULTI = util_load_json('test_data/events_raw_v2_2_results.json')
EVENTS_PAGE_RAW_V1 = util_load_json('test_data/page_raw_v1.json')
BASE_URL = 'https://netskope.example.com'
FIRST_LAST_RUN = {'alert': 1680182467, 'alert-ids': [], 'application': 1680182467, 'application-ids': [],
                  'audit': 1680182467, 'audit-ids': [], 'network': 1680182467, 'network-ids': [],
                  'page': 1680182467, 'page-ids': []}


def test_dedup_by_id():
    """
    Given:
        - Results from the API
    When:
        - Running the dedup_by_id command
    Then:
        - Make sure only the limited number of events return.
        - Make sure that first comes the event that with the earlier timestamp
        - Make sure that the last_run timestamp has been updated
        - Make sure that the correct last_run_ids returned.
    """
    from NetskopeEventCollector import dedup_by_id
    results = EVENTS_PAGE_RAW_V1.get('data')
    events, new_last_run = dedup_by_id(last_run=FIRST_LAST_RUN, event_type='page', limit=4, results=results)
    assert events[0].get('timestamp') == 1684751415
    assert len(events) == 4
    assert new_last_run == {'page': 1684751416, 'page-ids': ['3757761212778242bfda29cd', '9e99b72b957416a43222fa7a',
                                                             '66544bf5fda515f229592644', '98938eb19b4f9bea24ef9a8c']}


def test_test_module_v2(mocker):
    """
    Given:
        - raw_response of an event (as it returns from the api)
    When:
        - Running the test_module command
    Then:
        - Verify that 'ok' is returned.
    """
    from NetskopeEventCollector import test_module
    client = Client(BASE_URL, 'dummy_token', 'v2', False, False)
    mocker.patch.object(client, 'get_events_request_v2', return_value=EVENTS_RAW_V2)
    results = test_module(client, api_version='v2', last_run=FIRST_LAST_RUN, max_fetch=1)
    assert results == 'ok'


def test_populate_parsing_rule_fields():
    """
    Given:
        - Event from the API of type audit
    When:
        - Running the command
    Then:
        - Make sure the field _time is populated properly.
    """
    from NetskopeEventCollector import populate_parsing_rule_fields
    event = EVENTS_RAW_V2.get('result')[0]
    populate_parsing_rule_fields(event, event_type='audit')
    assert event.get('_time') == '2022-01-18T19:58:07.000Z'


def test_get_all_events(mocker):
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
    from NetskopeEventCollector import get_all_events
    client = Client(BASE_URL, 'netskope_token', 'v1', validate_certificate=False, proxy=False)
    mocker.patch.object(client, 'get_alerts_request_v1', return_value=EVENTS_PAGE_RAW_V1)
    mocker.patch.object(client, 'get_events_request_v1', return_value=EVENTS_PAGE_RAW_V1)
    events, new_last_run = get_all_events(client, FIRST_LAST_RUN, api_version='v1', limit=6, is_command=False)
    assert len(events) == 25
    assert events[0].get('event_id') == '3757761212778242bfda29cd'
    assert events[0].get('_time') == '2023-05-22T10:30:15.000Z'
    assert new_last_run['page'] == 1684751416
    assert new_last_run['page-ids'] == ['3757761212778242bfda29cd', '9e99b72b957416a43222fa7a',
                                        '66544bf5fda515f229592644', '98938eb19b4f9bea24ef9a8c',
                                        'fe6d7f3a9a1d4e1abce21713']


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
    client = Client(BASE_URL, 'dummy_token', 'v2', False, False)
    mocker.patch('NetskopeEventCollector.get_all_events', return_value=[MOCK_ENTRY, {}])
    results, events = get_events_command(client, args={}, last_run=FIRST_LAST_RUN, api_version='v2',
                                         is_command=True)
    assert 'Events List' in results.readable_output
    assert len(events) == 9
    assert results.outputs_prefix == 'Netskope.Event'
    assert results.outputs == MOCK_ENTRY
