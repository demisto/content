import demistomock as demisto
from unittest.mock import MagicMock
import pytest
from CommonServerPython import *


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
    }], None, None, None, None])
    apply_transition()
    call_args_list = execute_command_mocker.call_args_list
    assert call_args_list[0][0] == ('jira-edit-issue', {'issueId': '1234', 'transition': 'To New Status', 'issue_id': '1234'})
    assert call_args_list[1][0] == ('jira-get-issue', {'issueId': '1234', 'issue_id': '1234'})
    assert call_args_list[2][0] == ('setIncident', {'jirastatus': 'New Status'})
    assert call_args_list[3][0] == ('setIncident', {'jirav3status': 'New Status'})
    assert call_args_list[4][0] == ('setIncident', {'jiratransitions': 'Select'})
    assert call_args_list[5][0] == ('setIncident', {'lastupdatetime': '2023-01-01'})


def test_new_status_not_found_error():
    """Tests that an error is returned when the new status cannot be extracted after executing the command
    !jira-get-issue.
    """
    from ScriptJiraChangeTransition import apply_transition
    demisto.incidents = MagicMock(return_value=[{
        'dbotMirrorId': '1234',
        'CustomFields': {
            'jiratransitions': 'To New Status'
        }
    }])
    demisto.executeCommand = MagicMock(side_effect=[None, [{
        'Type': 1,
        'Contents': {'fields': {'status': {'dummy_key': 'dummy value'}, 'updated': '2023-01-01'}}
    }], None, None, None])
    with pytest.raises(DemistoException) as e:
        apply_transition()
    assert "Could not find: the issue's status name" in str(e)


def test_new_updated_time_not_found_error():
    """Tests that an error is returned when the new updated time cannot be extracted after executing the command
    !jira-get-issue.
    """
    from ScriptJiraChangeTransition import apply_transition
    demisto.incidents = MagicMock(return_value=[{
        'dbotMirrorId': '1234',
        'CustomFields': {
            'jiratransitions': 'To New Status'
        }
    }])
    demisto.executeCommand = MagicMock(side_effect=[None, [{
        'Type': 1,
        'Contents': {'fields': {'status': {'name': 'New Status'}}}
    }], None, None, None])
    with pytest.raises(DemistoException) as e:
        apply_transition()
    assert 'could not find the issue\'s updated time' in str(e)
