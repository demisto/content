import demistomock as demisto
import iot_alert_post_processing
from iot_alert_post_processing import iot_resolve_alert

_INCIDENT = {
    'id': 28862,
    'labels': [
        {
            'type': 'id',
            'value': '5ed08587fe03d30d000016e8'
        }
    ]
}


def test_iot_resolve_alert(monkeypatch, mocker):
    """
    Scenario: resolving alert in post processing after closing the XSOAR incident

    Given
    - An alert incident

    When
    - Resolving an alert in IoT Security Portal

    Then
    - Ensure the correct parameters to the iot-security-resolve-alert command
    """
    monkeypatch.setattr(iot_alert_post_processing, "_get_incident", lambda: _INCIDENT)
    execute_mocker = mocker.patch.object(demisto, 'executeCommand')
    expected_command = 'iot-security-resolve-alert'
    expected_args = {
        'id': '5ed08587fe03d30d000016e8',
        'reason': 'resolved by XSOAR incident 28862',
        'reason_type': 'No Action Needed'
    }
    iot_resolve_alert()
    execute_mocker.assert_called_with(expected_command, expected_args)
