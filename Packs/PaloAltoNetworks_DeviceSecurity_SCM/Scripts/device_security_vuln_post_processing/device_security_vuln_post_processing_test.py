import demistomock as demisto
import device_security_vuln_post_processing
from device_security_vuln_post_processing import device_security_resolve_vuln

_INCIDENT = {
    "id": 28862,
    "labels": [{"type": "zb_ticketid", "value": "vuln-99124066"}, {"type": "vulnerability_name", "value": "SMB v1 Usage"}],
}


def test_device_security_resolve_alert(monkeypatch, mocker):
    """
    Scenario: resolving vulnerability in post processing after closing the XSOAR incident

    Given
    - A vulnerability incident

    When
    - Resolving a vulnerability in Device Security Portal

    Then
    - Ensure the correct parameters to the device-security-resolve-vuln command
    """
    monkeypatch.setattr(device_security_vuln_post_processing, "_get_incident", lambda: _INCIDENT)
    execute_mocker = mocker.patch.object(demisto, "executeCommand")
    expected_command = "device-security-resolve-vuln"
    expected_args = {"id": "vuln-99124066", "full_name": "SMB v1 Usage", "reason": "resolved by XSOAR incident 28862"}
    device_security_resolve_vuln()
    execute_mocker.assert_called_with(expected_command, expected_args)
