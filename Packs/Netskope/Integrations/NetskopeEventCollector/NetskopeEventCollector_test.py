import io
import json

from NetskopeEventCollector import get_sorted_events_by_type, get_last_run, Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_events.json')
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


def test_get_last_run():
    assert get_last_run(MOCK_ENTRY, {}) == {'alert': 1657199079, 'application': 1656892796, 'audit': 1658384700,
                                            'network': 1657693921}

    # Still no events - last run should be from first_fetch
    assert get_last_run([], {'alert': 86400, 'application': 86400, 'audit': 86400, 'network': 86400}) == \
           {'alert': 86400, 'application': 86400, 'audit': 86400, 'network': 86400}


def test_get_events(mocker):
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
    mocker.patch.object(client, 'get_events_request_v2', return_value=MOCK_ENTRY)
    last_run = {}
    args = {
        'limit': 2
    }

    response = v2_get_events_command(client, args, last_run)
    assert response.raw_response == MOCK_ENTRY
    assert len(response.outputs) == 8


def test_test_module(mocker):
    """
    Given:
        - test-module call
    When:
        - A response with an OK status_code is retrieved from the API call.
    Then:
        - Make sure 'ok' is returned.
    """
    from NetskopeEventCollector import test_module
    alert_response = [
        {
            "_category_id": "10061",
            "_category_name": "Web Outlook Allowed",
            "_category_tags": [
                "10079",
                "10027"
            ],
            "_content_version": 1656927640,
            "_mladc": [
                "ur"
            ],
            "_nshostname": "_hostname",
            "_session_begin": "0",
            "_skip_geoip_lookup": "no",
            "_src_epoch_now": 1657184640,
            "access_method": "Client",
            "acked": "false",
            "action": "anomaly_detection",
            "activity": "Create",
            "alert": "yes",
            "alert_id": "1234e70cda66bd71a9c46e82de86b9fde",
            "alert_name": "user_shared_credentials",
            "alert_type": "uba"
        }
    ]
    client = Client(BASE_URL, 'netskope_token', 'v2', validate_certificate=False, proxy=False)
    mocker.patch.object(client, 'get_events_request_v2', return_value=alert_response)

    assert test_module(client, 'v2', {}) == 'ok'


def test_failed_test_module(mocker):
    """
    Given:
        - test-module call
    When:
        - A response with non-ok status_code is retrieved from the API call.
    Then:
        - Make sure error is returned.
    """
    from NetskopeEventCollector import test_module
    alert_response = []
    client = Client(BASE_URL, 'netskope_token', 'v2', validate_certificate=False, proxy=False)
    mocker.patch.object(client, 'get_events_request_v2', return_value=alert_response)

    assert test_module(client, 'v2', {}) == 'Test failed - Make sure the URL and the API Token are correctly set.'
