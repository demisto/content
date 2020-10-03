import demistomock as demisto
from GetFailedTasks import main
from test_data.constants import INCIDENTS_RESULT, TASKS_RESULT


def mock_execute_command(command_name, args):
    if command_name == 'getIncidents':
        return INCIDENTS_RESULT
    elif command_name == 'demisto-api-post':
        return TASKS_RESULT


def test_get_failed_tasks(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=mock_execute_command)
    mocker.patch.object(demisto, 'results')

    main()

    human_readable = demisto.results.call_args[0][0].get('HumanReadable')
    assert '|Incident Created Date|Incident ID|Task Name|Task ID|Playbook Name|Command Name|Error Entry ID|' in \
           human_readable
    assert human_readable.count('AutoFocusPolling') == 3

    entry_context = demisto.results.call_args[0][0].get('EntryContext')
    assert entry_context.get('NumberofFailedIncidents', [])[0].get('Number of total errors') == 6
    assert entry_context.get('NumberofFailedIncidents', [])[0].get('total of failed incidents') == 3

    assert entry_context.get('GetFailedTasks', [])[1] == {'Command Description': 'RunPollingCommand',
                                                          'Command Name': 'RunPollingCommand',
                                                          'Error Entry ID': ['4@7', '5@7'],
                                                          'Incident Created Date': '2020-09-29 14:02:45.82647067Z',
                                                          'Incident ID': '3',
                                                          'Incident Owner': 'admin',
                                                          'Number of Errors': 2,
                                                          'Playbook Name': 'AutoFocusPolling',
                                                          'Task ID': '3',
                                                          'Task Name': 'RunPollingCommand'}
