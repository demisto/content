import pytest

from GetIncidentTasks import format_title, is_task_match, get_states, map_to_array


@pytest.mark.parametrize('name, tag, states, output', [('test', None, 'Completed',
                                                        'Tasks with name "test" and states "Completed"'),
                                                       (None, None, 'Completed,Skipped',
                                                        'Tasks with states "Completed,Skipped"')])
def test_format_title(name, tag, states, output):
    assert format_title(name, tag, states) == output


@pytest.mark.parametrize('task, name, tag, states, output', [({'state': 'Completed',
                                                               'task': {'name': 'Example Task Name', 'tags': []}},
                                                              'Example Task Name', None, {'Completed': True}, True),
                                                             ({'state': 'Completed', 'task': {'name': 'Example Task Name',
                                                                                              'tags': ['exampletag']}},
                                                              None, 'exampletag', {'Completed': True}, True),
                                                             ({'state': 'Completed', 'task': {'name': 'Example Task Name',
                                                                                              'tags': []}},
                                                              '', 'exampletag', {'Completed': True}, False)])
def test_is_task_match(task, name, tag, states, output):
    assert is_task_match(task, name, tag, states) == output


@pytest.mark.parametrize('states, output', [('Completed', {'Completed': True}),
                                            ('', {'': True, 'inprogress': True, 'Completed': True,
                                                  'Waiting': True, 'Error': True, 'LoopError': True,
                                                  'WillNotBeExecuted': True, 'Blocked': True})])
def test_get_states(states, output):
    assert get_states(states) == output


@pytest.mark.parametrize('map, output', [({'a': 'first', 'b': 'second'}, ['first', 'second'])])
def test_map_to_array(map, output):
    assert map_to_array(map) == output
