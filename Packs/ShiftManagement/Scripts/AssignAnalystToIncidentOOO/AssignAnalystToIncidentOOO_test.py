import io
import json

import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


user_data = util_load_json('test_data/user_data.json')
away_user_data = util_load_json('test_data/away_user_data.json')
ooo_user_data = util_load_json('test_data/ooo_user_data.json')


def execute_command_mock(command, args):
    if command == 'getUsers':
        return [{'Type': 6, 'Contents': user_data}]
    if command == 'GetAwayUsers':
        return [{'Type': 6, 'EntryContext': {'AwayUsers': away_user_data}}]
    if command == 'GetUsersOOO':
        return [{'Type': 6, 'EntryContext': {'ShiftManagment.OOOUsers': ooo_user_data}}]
    if command == 'setOwner':
        assert 'admin' in args['owner']
        return [{'Type': 6}]
    if command == 'AssignAnalystToIncident':
        assert 'admin' in args['username']
        return [{'Type': 6}]
    raise Exception(f'Unexpected command: {command}')


@pytest.mark.parametrize('args', [({'assignAll': False}), ({'assignAll': True})])
def test_script_flow(mocker, args):
    """
    Given:
    - Cortex XSOAR args.

    When:
    - Calling AssignAnalystToIncidentOOO.

    Then:
    - Ensure expected behaviour.

    Behaviour of expected given args for commands are checked via the `execute_command_mock` function.

    """
    from AssignAnalystToIncidentOOO import main
    import demistomock as demisto
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command_mock)
    mocker.patch.object(demisto, 'args', return_value=args)
    main()
