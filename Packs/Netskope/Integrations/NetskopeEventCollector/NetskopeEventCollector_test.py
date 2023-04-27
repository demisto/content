import io
import json

from NetskopeEventCollector import get_sorted_events_by_type, Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_events.json')
EVENTS_RAW_V2 = util_load_json('test_data/events_raw_v2.json')
EVENTS_RAW_V2_MULTI = util_load_json('test_data/events_raw_v2_2_results.json')
BASE_URL = 'https://netskope.example.com/'
FIRST_LAST_RUN = {'alert': 1680182467, 'alert-ids': [], 'application': 1680182467, 'application-ids': [],
                  'audit': 1680182467, 'audit-ids': [], 'network': 1680182467, 'network-ids': [],
                  'page': 1680182467, 'page-ids': []}


def test_get_sorted_events_by_type():
    """
    Given:
        - an event type = audit
    When:
        - Running the command get_sorted_events_by_type
    Then:
        - Make sure that the audit events returned and are sorted.
    """
    assert get_sorted_events_by_type(MOCK_ENTRY, event_type='audit') == [
        {
            "timestamp": 1658381961,
            "type": "admin_audit_logs",
            "user": "testing@test.com",
            "severity_level": 2,
            "audit_log_event": "Logout Successful",
            "supporting_data": {
                "data_type": "reason",
                "data_values": [
                    "Logged out due to inactivity"
                ]
            },
            "organization_unit": "test-unit",
            "ur_normalized": "testing@test.com",
            "ccl": "unknown",
            "count": 1,
            "_insertion_epoch_timestamp": 1658382261,
            "_id": "c8d6aed8f613f5de0fa5e123",
            "source_log_event": "audit"
        },
        {
            "timestamp": 1658384700,
            "type": "admin_audit_logs",
            "user": "testing@test.com",
            "severity_level": 2,
            "audit_log_event": "Login Successful",
            "supporting_data": {
                "data_type": "user",
                "data_values": [
                    "1.1.1.1",
                    "testing@test.com"
                ]
            },
            "organization_unit": "test-unit",
            "ur_normalized": "testing@test.com",
            "ccl": "unknown",
            "count": 1,
            "_insertion_epoch_timestamp": 1658385000,
            "_id": "d3ad748bf011262fa142123",
            "source_log_event": "audit"
        }]


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
    results = test_module(client, api_version='v2', last_run=FIRST_LAST_RUN)
    assert results == 'ok'


def test_v2_get_events_command(mocker):
    """
    Given:
        - netskope-get-events call
    When:
        - Running the command
    Then:
        - Make sure all the events are returned as part of the CommandResult.
    """
    from NetskopeEventCollector import v2_get_events_command
    client = Client(BASE_URL, 'netskope_token', 'v2', validate_certificate=False, proxy=False)
    mocker.patch('NetskopeEventCollector.get_events_v2', return_value=MOCK_ENTRY)
    args = {
        'limit': 2
    }
    response, _ = v2_get_events_command(client, args, FIRST_LAST_RUN)
    assert response.raw_response == MOCK_ENTRY
    assert len(response.outputs) == 9
    assert 'Events List' in response.readable_output


def test_get_events_v2(mocker):
    """
    Given:
        - netskope-get-events call
    When:
        - Running the command
    Then:
        - Make sure only the events returns.
    """
    from NetskopeEventCollector import get_events_v2, ALL_SUPPORTED_EVENT_TYPES
    client = Client(BASE_URL, 'netskope_token', 'v2', validate_certificate=False, proxy=False)
    mocker.patch.object(client, 'get_events_request_v2', return_value=EVENTS_RAW_V2)
    response = get_events_v2(client, FIRST_LAST_RUN, 1)
    assert len(response) == len(ALL_SUPPORTED_EVENT_TYPES)
    assert 'results' not in response


def test_get_events_v2__multi_page__end_at_limit(mocker):
    """
    Given:
        - netskope-get-events call
        - 2 pages are available per type
        - page size is set to 1
        - limit is set to 2 per event type
    When:
        - Running the command
    Then:
        - Make sure 2 * ALL_SUPPORTED_EVENT_TYPES is returned
    """
    import NetskopeEventCollector as NEC
    client = Client(BASE_URL, 'netskope_token', 'v2', validate_certificate=False, proxy=False)
    mocker.patch.object(client, 'get_events_request_v2', side_effect=[EVENTS_RAW_V2 for _ in range(10)])
    NEC.MAX_EVENTS_PAGE_SIZE = 1
    response = NEC.get_events_v2(client, FIRST_LAST_RUN, 2)
    assert len(response) == (2 * len(NEC.ALL_SUPPORTED_EVENT_TYPES))


def test_get_events_v2__multi_page__end_before_limit(mocker):
    """
    Given:
        - netskope-get-events call
        - 2 pages are available per type (last type only 1 page)
        - page size is set to 2
        - limit is set to 4 per event type
    When:
        - Running the command
    Then:
        - Make sure (4 * ALL_SUPPORTED_EVENT_TYPES - 1) is returned
    """
    import NetskopeEventCollector as NEC
    client = Client(BASE_URL, 'netskope_token', 'v2', validate_certificate=False, proxy=False)
    side_effect = [EVENTS_RAW_V2_MULTI for _ in range(9)] + [EVENTS_RAW_V2]
    mocker.patch.object(client, 'get_events_request_v2', side_effect=side_effect)
    NEC.MAX_EVENTS_PAGE_SIZE = 2
    response = NEC.get_events_v2(client, FIRST_LAST_RUN, 4)
    assert len(response) == (4 * len(NEC.ALL_SUPPORTED_EVENT_TYPES) - 1)
    assert 'results' not in response
