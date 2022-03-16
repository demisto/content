"""Base Script for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing
"""

import pytest


@pytest.mark.parametrize('action', ['isolate', 'unisolate'])
def test_create_command_executers(mocker, action):
    """
    Given:
        the action to perform (allow or block)
    When:
        Calling `create_command_wrappers` to get all the command wrappers for the script.
    Then:
        Ensure the right commands wrappers are being returned.

    """
    from IsolationAssetWrapper import demisto, create_commands, MSDE_ACTIONS, XDR_ACTIONS, \
        CROWDSTRIKE_ACTIONS
    device_ids = ['device1',
                  'device2',
                  'device3']
    mocker.patch.object(demisto, 'incident', return_value={'id': 1})
    msde_command, msde_args = MSDE_ACTIONS[action]
    msde_args.update({'using-brand': 'Microsoft Defender Advanced Threat Protection'})
    commands = create_commands(device_ids, action)
    assert len(commands) == 3
    for command in commands:
        command_names = set(command.commands)
        if msde_command in command_names:
            assert command.commands == [msde_command]
            assert command.args_lst == [msde_args]
        if XDR_ACTIONS.get(action) in command_names:
            assert len(command.commands) == len(device_ids)
            assert len(command.args_lst) == len(device_ids)
            assert set(command.commands) == {XDR_ACTIONS.get(action)}
            assert command.args_lst == [{'endpoint_id': device_id} for device_id in device_ids]
        if CROWDSTRIKE_ACTIONS.get(action) in command_names:
            assert command.commands == [CROWDSTRIKE_ACTIONS.get(action)]
            assert command.args_lst == [{'ids': ','.join(device_ids)}]
