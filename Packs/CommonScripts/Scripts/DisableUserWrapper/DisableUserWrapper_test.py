from CommonServerPython import CommandRunner
from DisableUserWrapper import disable_user
import pytest


def commands_are_equal(command1: CommandRunner.Command, command2: CommandRunner.Command) -> bool:
    """Return True if command and args_lst of the commands are equal, False otherwise."""
    if command1.commands != command2.commands:
        return False
    if command1.args_lst != command2.args_lst:
        return False
    return True


def test_disable_user(mocker):
    """Test disable_user happy flow

    Given:
        incident_id
        ad-get-user successful response
        username
        approve_action = yes
    When:
        running DisableUserWrapper script
    Then:
        assert the result returned is the run_commands_with_summary result
        assert run_commands_with_summary is called with the right commands
    """
    commands_patch = mocker.patch.object(CommandRunner, 'run_commands_with_summary',
                                         return_value='run_commands_response')

    expected_commands = [CommandRunner.Command(commands='ad-disable-account',
                                               args_lst={'username': 'some_user'}),
                         CommandRunner.Command(commands='iam-disable-user',
                                               args_lst={'user-profile': {
                                                   'user_name': 'some_user',
                                                   'sAMAccountName': 'some_user'}}),
                         CommandRunner.Command(commands='okta-deactivate-user',
                                               args_lst={'username': 'some_user'}),
                         CommandRunner.Command(commands='msgraph-user-account-disable',
                                               args_lst={'user': 'some_user'}),
                         CommandRunner.Command(commands='identityiq-disable-account',
                                               args_lst={'id': 'some_user'})]

    result = disable_user({'username': 'some_user', 'approve_action': 'yes'})

    assert result == 'run_commands_response'

    returned_commands, _ = commands_patch.call_args

    for returned_command in returned_commands[0]:
        returned_command_is_expected = False
        for expected_command in expected_commands:
            if commands_are_equal(returned_command, expected_command) and not returned_command_is_expected:
                returned_command_is_expected = True
        assert returned_command_is_expected, f'Returned command {returned_command.commands} is not expected.'

    assert len(returned_commands[0]) == len(expected_commands)


def test_disable_user_disapproved():
    """
    Given:
        username
        approve_action = no
    When:
        running DisableUserWrapper
    Then:
        assert the right ValueError is raised.
    """
    result = disable_user({'username': 'some_user', 'approve_action': 'no'})
    assert 'approve_action must be `yes`' in result


def test_disable_user_no_username():
    """
    Given:
        no username
        approve_action = yes
    When:
        running DisableUserWrapper
    Then:
        assert the right ValueError is raised.
    """
    with pytest.raises(ValueError) as e:
        disable_user({'username': '', 'approve_action': 'yes'})
    assert 'username is not specified' in str(e)
