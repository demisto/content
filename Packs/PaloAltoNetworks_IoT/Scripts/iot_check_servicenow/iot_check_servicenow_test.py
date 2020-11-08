import demistomock as demisto
import iot_check_servicenow
from iot_check_servicenow import check_servicenow_and_close


_INCIDENTS = [
    {
        'id': 1,
        'status': 0,
        'type': 'IoT Alert'
    },
    {
        'id': 2,
        'status': 1,
        'type': 'IoT Vulnerability',
        'CustomFields': {
            'servicenowtablename': 'incident',
            'servicenowrecordid': 'snow_id'
        }
    }
]


def test_check_servicenow_and_close(monkeypatch):
    """
    Scenario: checking opened XSOAR IoT incidents.
    If there's a ServiceNow ticket created, query its status, then close it accordingly

    Given
    - An opened incident with a ServiceNow ticket created for this

    When
    - Closing this incident

    Then
    - Ensure the ServiceNow query command 'servicenow-get-record' is run
    - Ensure the close investigation is happening
    """
    monkeypatch.setattr(iot_check_servicenow, 'get_opened_iot_incidents', lambda: _INCIDENTS)

    monkeypatch.setattr(demisto, "executeCommand", lambda command, args: {
        'servicenow-get-record': [{
            'Type': 1,
            'Contents': {
                'result': {
                    'close_code': 'Duplicate Ticket',
                    'incident_state': '7'
                }
            }
        }],
        'closeInvestigation': [{
            'Type': 1
        }]
    }.get(command))

    assert check_servicenow_and_close() == 'found 2 incidents, closed 1 incidents'
