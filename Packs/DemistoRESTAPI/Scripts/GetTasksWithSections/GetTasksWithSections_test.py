import json
from GetTasksWithSections import traverse_tasks, find_start_task, get_tasks_and_readable


def load_json(file):
    with open(file, 'r') as f:
        return json.load(f)


tasks = load_json('test_data/tasks_example.json')


def test_find_start_task():
    """
    Given:
        tasks from `/investigation/{incident_id}/workplan` endpoint
    When:
        Needed to find the start task in order to traverse the tasks
    Then:
        Get a task which it's type is `start`
    """
    start_task = find_start_task(tasks)
    assert start_task.get('type') == 'start'


def test_traverse_tasks():
    """
    Given:
        tasks from `/investigation/{incident_id}/workplan` endpoint
    When:
        Needed to traverse the tasks to construct nested task dictionary
    Then:
        The results will be in a nested form, without skipped or condition tasks (playbook tasks are included)`
    """
    start_task = find_start_task(tasks)
    nested_task_results = {}
    traverse_tasks(tasks, start_task, nested_task_results)
    expected_results = {'Start': {'1', '2', '7'},
                        'Section 1': {'Section 2': {'5', '8'}, 'Section 4': {'13'}},
                        'Section 3': {'10'}}

    for k1, v1 in nested_task_results.items():
        if 'tasks' in v1:
            actual_result = set([task.get('id') for task in v1.get('tasks')])
        else:
            actual_result = {k2: {task.get('id') for task in v2.get('tasks')} for k2, v2 in v1.items()}
        assert actual_result == expected_results[k1]
    all_tasks, _ = get_tasks_and_readable(nested_task_results)
    assert set([task.get('id') for task in all_tasks]) == {'1', '2', '5', '7', '8', '10', '13'}
