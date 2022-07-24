import io
import json

from NetskopeEventCollector import get_sorted_events_by_type, get_last_run


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json('test_data/mock_events.json')


def test_get_sorted_events_by_type():
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
