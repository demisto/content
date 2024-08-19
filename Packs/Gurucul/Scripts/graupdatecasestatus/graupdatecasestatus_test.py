import demistomock as demisto
import graupdatecasestatus
from graupdatecasestatus import closeCase

_INCIDENT = {
    'id': 28862,
    'sourceInstance': 'instance_name',
    'labels': [
        {
            'type': 'caseId',
            'value': 'CS-9999'
        }
    ]
}


def test_gra_update_case_status(monkeypatch, mocker):
    """
    Scenario: This script executes the 'gra-case-action' command to resolve case status as closed.

    Given
    - An alert incident

    When
    - Resolving case status

    Then
    - Ensure the correct parameters to the gra-case-action command
    """
    monkeypatch.setattr(graupdatecasestatus, "_get_incident", lambda: _INCIDENT)
    execute_mocker = mocker.patch.object(demisto, 'executeCommand')
    expected_command = 'gra-case-action'
    expected_args = {
        'action': 'closeCase',
        'subOption': 'True Incident',
        'caseId': 'CS-9999',
        'caseComment': '',
        'using': 'instance_name'
    }
    closeCase()
    execute_mocker.assert_called_with(expected_command, expected_args)
