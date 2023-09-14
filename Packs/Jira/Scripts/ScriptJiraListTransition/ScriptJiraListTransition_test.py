import demistomock as demisto
from unittest.mock import MagicMock


def test_list_transition_for_v3_brand():
    """Tests if the script is able to extract the transitions from the !jira-list-transitions command, when
    using the Jira V3 brand.
    """
    from ScriptJiraListTransition import main
    demisto.incidents = MagicMock(return_value=[{
        'dbotMirrorId': '1234',
        'sourceBrand': 'Jira V3'
    }])
    execute_command_mocker = demisto.executeCommand = MagicMock(
        return_value=[{'Type': '1', 'Contents': {'transitions': [{'name': 'Transition 1'}, {'name': 'Transition 2'}]}}])
    demisto_results_mocker = demisto.results = MagicMock(side_effect=demisto.results)
    expected_statuses_names = ['Transition 1', 'Transition 2']
    main()
    assert execute_command_mocker.call_args_list[0][0] == ('jira-list-transitions',
                                                           {'issue_id': '1234', 'using-brand': 'Jira V3'})
    assert demisto_results_mocker.call_args_list[0][0][0] == ({'hidden': False, 'options': expected_statuses_names})


def test_list_transition_for_v2_brand():
    """Tests if the script is able to extract the statuses from the !jira-list-transitions command, when
    using the Jira V2 brand.
    """
    from ScriptJiraListTransition import main
    demisto.incidents = MagicMock(return_value=[{
        'dbotMirrorId': '1234',
        'sourceBrand': 'jira-v2'
    }])
    execute_command_mocker = demisto.executeCommand = MagicMock(
        return_value=[{'Type': '1', 'Contents': ['Transition 1', 'Transition 2']}])
    demisto_results_mocker = demisto.results = MagicMock(side_effect=demisto.results)
    expected_statuses_names = ['Transition 1', 'Transition 2']
    main()
    assert execute_command_mocker.call_args_list[0][0] == ('jira-list-transitions',
                                                           {'issueId': '1234', 'using-brand': 'jira-v2'})
    assert demisto_results_mocker.call_args_list[0][0][0] == ({'hidden': False, 'options': expected_statuses_names})
