import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback


def create_commands(username: str) -> List[CommandRunner.Command]:
    """Create commands to disable user.

    Args:
        username (str): The username to create disable-user commands with.

    Returns:
        list of CommandRunner.Commands to disable the user.
    """

    commands: list = [
        CommandRunner.Command(
            commands='ad-disable-account',
            args_lst={'username': username}),
        CommandRunner.Command(
            commands='iam-disable-user',
            args_lst={'user-profile': {'user_name': username, 'sAMAccountName': username}}),
        CommandRunner.Command(
            commands='okta-deactivate-user',
            args_lst={'username': username}),
        CommandRunner.Command(
            commands='msgraph-user-account-disable',
            args_lst={'user': username}),
        CommandRunner.Command(
            commands='identityiq-disable-account',
            args_lst={'id': username})]

    return commands


def disable_user(args: dict):
    """Disable user from supported integrations.

    Will not return errors on un-supported commands unless there is no supported ones.

    args (dict):
        args[approve_action]: Must be yes in order for the command to work.
        args[username]: The username to disable.

    Returns:
        The CommandResults of all the supported commands.
    """
    if not argToBoolean(args.get('approve_action', False)):
        return 'approve_action must be `yes`'
    username = args.get('username')
    if not username:
        raise ValueError('username is not specified')

    command_executors = create_commands(username)
    return CommandRunner.run_commands_with_summary(command_executors)


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    try:
        return_results(disable_user(demisto.args()))
    except Exception as e:
        error_msg = f'Failed to execute DisableUserWrapper. Error: {str(e)}\n {traceback.format_exc()}'
        if 'The commands that run are not supported in this Instance' in str(e):
            error_msg = 'No disable-user supported integrations were found in this instance.'

        return_error(error_msg)


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):   # pragma: no cover
    main()
