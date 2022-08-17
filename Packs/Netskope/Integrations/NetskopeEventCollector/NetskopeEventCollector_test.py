import io
import json

from NetskopeEventCollector import get_sorted_events_by_type, create_last_run, Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_events.json')
EVENTS_RAW_V2 = util_load_json('test_data/events_raw_v2.json')
BASE_URL = 'https://netskope.example.com/'


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
            "event_type": "audit"
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
            "event_type": "audit"
        }]


def test_create_last_run():
    """
    Given:
        - List of events
        - Empty list of events
    When:
        - Running the command create_last_run
    Then:
        - Verify that when a list of events exists, it will take the last timestamp
        - Verify that when there are no events yet (first fetch) the timestamp for all will be as the first fetch
    """
    assert create_last_run(MOCK_ENTRY, {}) == {'alert': 1657199110, 'audit': 1658384700, 'application': 1656892798,
                                               'network': 1657693986}

    # Still no events - last run should be from first_fetch
    assert create_last_run([], {'alert': 86400, 'application': 86400, 'audit': 86400, 'network': 86400}) == \
           {'alert': 86400, 'application': 86400, 'audit': 86400, 'network': 86400}


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

    results = test_module(client, api_version='v2', last_run={})
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
    response, _ = v2_get_events_command(client, args, {})
    assert response.raw_response == MOCK_ENTRY
    assert len(response.outputs) == 8
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
    from NetskopeEventCollector import get_events_v2
    client = Client(BASE_URL, 'netskope_token', 'v2', validate_certificate=False, proxy=False)
    mocker.patch.object(client, 'get_events_request_v2', return_value=EVENTS_RAW_V2)
    response = get_events_v2(client, {}, 1)
    assert len(response) == 4
    assert 'results' not in response
