import pytest

from GetIncidentTasks import format_title, is_task_match, get_states, get_playbook_tasks, get_task_command
SAMPLE_TASKS = {
    "1": {
        "id": "1",
        "state": "Completed",
        "task": {
            "id": "66d67e04-f10b-46e6-8453-762558555c4d",
            "name": "Example Task Name",
            "tags": ["testtag"]
        },
        "taskId": "66d67e04-f10b-46e6-8453-762558555c4d",
        "type": "regular"
    },
    "2": {
        "id": "1",
        "state": "Completed",
        "task": {
            "id": "66d67e04-f10b-46e6-8453-762558555c4d",
            "name": "Example Task Name",
            "tags": []
        },
        "taskId": "66d67e04-f10b-46e6-8453-762558555c4d",
        "type": "regular"
    },
    "3": {
        "id": "3",
        "state": "Completed",
        "subPlaybook": {
            "id": "31",
            "state": "completed",
            "tasks": {
                "4": {
                    "id": "4",
                    "state": "Completed",
                    "task": {
                        "name": "Sub-playbook Tasks",
                        "type": "regular"
                    },
                    "type": "regular"
                }
            }
        },
        "task": {
            "name": "Process Sub-playbook",
            "type": "playbook",
            "version": 8
        },
        "type": "playbook"
    }
}


@pytest.mark.parametrize('name, tag, states, output', [('test', None, 'Completed',
                                                        'Tasks with name "test" and states "Completed"'),
                                                       (None, None, 'Completed,Skipped',
                                                        'Tasks with states "Completed,Skipped"'),
                                                       (None, 'testtag', None, 'Tasks with tag "testtag"')])
def test_format_title(name, tag, states, output):
    assert format_title(name, tag, states) == output


@pytest.mark.parametrize('task, name, tag, states, output', [(SAMPLE_TASKS['1'],
                                                              'Example Task Name', None, ['Completed'], True),
                                                             (SAMPLE_TASKS['1'],
                                                              None, 'testtag', ['Completed'], True),
                                                             (SAMPLE_TASKS['2'],
                                                              '', 'testtag', ['Completed'], False),
                                                             (SAMPLE_TASKS['1'], None, 'testtag', [], True)])
def test_is_task_match(task, name, tag, states, output):
    assert is_task_match(task, name, tag, states) == output


@pytest.mark.parametrize('states, output', [(['Completed'], ['Completed']),
                                            ([], ['', 'inprogress', 'Completed', 'Waiting', 'Error',
                                                  'LoopError', 'WillNotBeExecuted', 'Blocked']),
                                            (['error'], ['Error', 'LoopError'])])
def test_get_states(states, output):
    assert get_states(states) == output


@pytest.mark.parametrize('tasks, output', [([SAMPLE_TASKS['1']], [SAMPLE_TASKS['1']]),
                                           ([SAMPLE_TASKS['3']], [SAMPLE_TASKS['3']['subPlaybook']['tasks']['4'],
                                                                  SAMPLE_TASKS['3']]),
                                           ([], [])])
def test_get_playbook_tasks(tasks, output):
    assert get_playbook_tasks(tasks) == output


@pytest.mark.parametrize('args', [({'name': 'task name'})])
def test_get_task_command_missing(args):
    with pytest.raises(KeyError):
        get_task_command(args)


@pytest.mark.parametrize('args', [({'inc_id': '1', 'name': 'task name'})])
def test_get_task_command_failure(args):
    with pytest.raises(Exception):
        get_task_command(args)
