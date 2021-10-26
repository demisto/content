import json
import pytest
from GetTasksWithSections import traverse_tasks, find_start_task


def load_json(file):
    with open(file, 'r') as f:
        return json.load(f)


tasks = load_json('test_data/tasks_example.json')


def test_find_start_task():
    start_task = find_start_task(tasks)
    assert start_task.get('type') == 'start'


EXPECTED_RESULTS = {'Start': {'1', '2', '7'}, 'Section 1': {'Section 2': {'5', '8'}}, 'Section 3': {'10'}}


def test_traverse_tasks():
    start_task = find_start_task(tasks)
    results = {}
    traverse_tasks(tasks, start_task, results)

    for k1, v1 in results.items():
        if 'tasks' in v1:
            actual_result = set([task.get('id') for task in v1.get('tasks')])
        else:
            actual_result = {k2: {task.get('id') for task in v2.get('tasks')} for k2, v2 in v1.items()}
        assert actual_result == EXPECTED_RESULTS[k1]
