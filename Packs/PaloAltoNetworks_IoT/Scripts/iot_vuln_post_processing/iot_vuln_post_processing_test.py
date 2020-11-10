import demistomock as demisto
import iot_vuln_post_processing
from iot_vuln_post_processing import iot_resolve_vuln

_INCIDENT = {
    'id': 28862,
    'labels': [
        {
            'type': 'zb_ticketid',
            'value': 'vuln-99124066'
        },
        {
            'type': 'vulnerability_name',
            'value': 'SMB v1 Usage'
        }
    ]
}


def test_iot_resolve_alert(monkeypatch, mocker):
    """
    Scenario: resolving vulnerability in post processing after closing the XSOAR incident

    Given
    - A vulnerability incident

    When
    - Resolving a vulnerability in IoT Security Portal

    Then
    - Ensure the correct parameters to the iot-security-resolve-vuln command
    """
    monkeypatch.setattr(iot_vuln_post_processing, "_get_incident", lambda: _INCIDENT)
    execute_mocker = mocker.patch.object(demisto, 'executeCommand')
    expected_command = 'iot-security-resolve-vuln'
    expected_args = {
        'id': 'vuln-99124066',
        'full_name': 'SMB v1 Usage',
        'reason': 'resolved by XSOAR incident 28862'
    }
    iot_resolve_vuln()
    execute_mocker.assert_called_with(expected_command, expected_args)
