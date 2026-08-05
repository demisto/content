import demistomock as demisto
import device_security_check_servicenow
from device_security_check_servicenow import check_servicenow_and_close

_INCIDENTS = [
    {"id": 1, "status": 0, "type": "Device Security Alert"},
    {
        "id": 2,
        "status": 1,
        "type": "Device Security Vulnerability",
        "CustomFields": {"devicesecurityservicenowtablename": "incident", "devicesecurityservicenowrecordid": "snow_id"},
    },
]


def test_check_servicenow_and_close(monkeypatch):
    """
    Scenario: checking opened XSOAR Device Security incidents.
    If there's a ServiceNow ticket created, query its status, then close it accordingly

    Given
    - An opened incident with a ServiceNow ticket created for this

    When
    - Closing this incident

    Thens
    - Ensure the ServiceNow query command 'servicenow-get-record' is run
    - Ensure the close investigation is happening
    """
    monkeypatch.setattr(device_security_check_servicenow, "get_opened_device_security_incidents", lambda: _INCIDENTS)

    monkeypatch.setattr(
        demisto,
        "executeCommand",
        lambda command, args: {
            "servicenow-get-record": [
                {"Type": 1, "Contents": {"result": {"close_code": "Duplicate Ticket", "incident_state": "7"}}}
            ],
            "closeInvestigation": [{"Type": 1}],
        }.get(command),
    )

    assert check_servicenow_and_close() == "found 2 incidents, closed 1 incidents"
