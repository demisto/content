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


def test_traverse_tasks():
    start_task = find_start_task(tasks)
    results = {}
    traverse_tasks(tasks, start_task, results)
    expected_results = load_json('test_data/tasks_results.json')
    assert results == expected_results