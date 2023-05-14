import demistomock as demisto
from unittest.mock import MagicMock


def test_change_jira_transition():
    """Tests the order of the demisto.executeCommand, and checks if it was run with the correct arguments.
    """
    from ScriptJiraChangeTransition import apply_transition
    demisto.incidents = MagicMock(return_value=[{
        'dbotMirrorId': '1234',
        'CustomFields': {
            'jiratransitions': 'To New Status'
        }
    }])
    execute_command_mocker = demisto.executeCommand = MagicMock(side_effect=[None, [{
        'Type': 1,
        'Contents': {'fields': {'status': {'name': 'New Status'}, 'updated': '2023-01-01'}}
    }], None, None, None])
    apply_transition()
    call_args_list = execute_command_mocker.call_args_list
    assert call_args_list[0][0] == ('jira-edit-issue', {'issueId': '1234', 'transition': 'To New Status', 'issue_id': '1234'})
    assert call_args_list[1][0] == ('jira-get-issue', {'issueId': '1234', 'issue_id': '1234'})
    assert call_args_list[2][0] == ('setIncident', {'jirastatus': 'New Status'})
    assert call_args_list[3][0] == ('setIncident', {'jiratransitions': 'Select'})
    assert call_args_list[4][0] == ('setIncident', {'lastupdatetime': '2023-01-01'})
