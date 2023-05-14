import demistomock as demisto
from unittest.mock import MagicMock


def test_change_jira_status():
    """Tests the order of the demisto.executeCommand, and checks if it was run with the correct arguments.
    """
    from ScriptJiraChangeStatus import apply_status
    demisto.incidents = MagicMock(return_value=[{
        'dbotMirrorId': '1234',
        'CustomFields': {
            'jirastatus': 'New Status'
        }
    }])
    execute_command_mocker = demisto.executeCommand = MagicMock(side_effect=[None, [{
        'Type': 1,
        'Contents': {'fields': {'status': {'name': 'New Status'}, 'updated': '2023-01-01'}}
    }], None, None])
    apply_status()
    call_args_list = execute_command_mocker.call_args_list
    assert call_args_list[0][0] == ('jira-edit-issue', {'issueId': '1234', 'status': 'New Status', 'issue_id': '1234'})
    assert call_args_list[1][0] == ('jira-get-issue', {'issueId': '1234', 'issue_id': '1234'})
    assert call_args_list[2][0] == ('setIncident', {'jirastatus': 'New Status'})
    assert call_args_list[3][0] == ('setIncident', {'lastupdatetime': '2023-01-01'})
