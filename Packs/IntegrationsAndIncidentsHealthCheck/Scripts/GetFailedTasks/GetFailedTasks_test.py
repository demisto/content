import demistomock as demisto
import pytest
import json
from GetFailedTasks import main, get_failed_tasks_output
from test_data.constants import INCIDENTS_RESULT, TASKS_RESULT


def test_get_failed_tasks(mocker):
    mocker.patch.object(demisto, 'executeCommand', return_value=INCIDENTS_RESULT)
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=TASKS_RESULT)
    mocker.patch.object(demisto, 'results')

    main()

    human_readable = demisto.results.call_args[0][0].get('HumanReadable')
    assert '|Incident Created Date|Incident ID|Task Name|Task ID|Playbook Name|Command Name|Error Entry ID|' in \
           human_readable
    assert human_readable.count('AutoFocusPolling') == 3

    entry_context = demisto.results.call_args[0][0].get('EntryContext')
    assert entry_context.get('NumberofFailedIncidents', [])[0].get('Number of total errors') == 6
    assert entry_context.get('NumberofFailedIncidents', [])[0].get('total of failed incidents') == 3

    assert entry_context.get('GetFailedTasks', [])[1] == {'Command Name': '',
                                                          'Error Entry ID': ['8@3', '9@3'],
                                                          'Incident Created Date': '2020-09-29T14:02:45.82647067Z',
                                                          'Incident ID': '3',
                                                          'Incident Owner': 'admin',
                                                          'Number of Errors': 2,
                                                          'Playbook Name': 'AutoFocusPolling',
                                                          'Task ID': '1',
                                                          'Task Name': 'Fail',
                                                          'Command Description': 'command desc'}


@pytest.mark.parametrize('tasks,expected_outputs', [
    ([], ([], 0)),
    (json.loads(TASKS_RESULT.get('body')), ([{
        'Command Name': '',
        'Error Entry ID': ['8@3', '9@3'],
        'Incident Created Date': '2020-09-29T14:02:45.82647067Z',
        'Incident ID': '3',
        'Incident Owner': 'admin',
        'Number of Errors': 2,
        'Playbook Name': 'AutoFocusPolling',
        'Task ID': '1',
        'Task Name': 'Fail',
        'Command Description': 'command desc'
    }], 2))
])
def test_get_failed_tasks_output(tasks, expected_outputs):
    """
        Given:
            - A list of tasks

        When:
            - Running the get_failed_tasks_output function

        Then:
            - Validates that the response is as expected.
    """
    tasks_res, num_tasks = get_failed_tasks_output(tasks, INCIDENTS_RESULT[0].get('Contents').get('data')[1])

    assert tasks_res == expected_outputs[0]
    assert num_tasks == expected_outputs[1]
