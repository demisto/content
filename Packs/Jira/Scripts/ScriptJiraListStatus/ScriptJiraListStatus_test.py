import demistomock as demisto
from unittest.mock import MagicMock
import pytest


@pytest.mark.parametrize('dbotMirrorId, sourceBrand, execute_command_args',
                         [('1234', 'Jira V3', ('jira-list-transitions', {'issue_id': '1234', 'using-brand': 'Jira V3'})),
                          ('1234', 'jira-v2', ('jira-list-transitions', {'issueId': '1234', 'using-brand': 'jira-v2'}))])
def test_list_status(dbotMirrorId, sourceBrand, execute_command_args):
    """Tests if the script is able to extract the statuses from the !jira-list-transitions command.
    """
    from ScriptJiraListStatus import main
    demisto.incidents = MagicMock(return_value=[{
        'dbotMirrorId': dbotMirrorId,
        'sourceBrand': sourceBrand
    }])
    execute_command_mocker = demisto.executeCommand = MagicMock(
        return_value=[{'Type': '1', 'Contents': {'transitions': [{'to': {'name': 'Status 1'}}, {'to': {'name': 'Status 2'}}]}}])
    demisto_results_mocker = demisto.results = MagicMock(side_effect=demisto.results)
    expected_statuses_names = ['Status 1', 'Status 2']
    main()
    assert execute_command_mocker.call_args_list[0][0] == execute_command_args
    assert demisto_results_mocker.call_args_list[0][0][0] == ({'hidden': False, 'options': expected_statuses_names})
