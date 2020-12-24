"""
bla bla bla
"""
from CommonServerPython import *


def is_command_available(instance_name: str, command: str) -> dict:
    available_commands = demisto.getAllSupportedCommands()
    if commands := available_commands.get(instance_name):
        try:
            return list(filter(lambda item: item['name'] == command, commands))[0]
        except IndexError:
            raise DemistoException(f'Could not find command {command} in instance {instance_name}')
    else:
        raise DemistoException(f'Could not find instance {instance_name}')


def set_default_arg(command_entry, given_args) -> dict:
    if 'default' in given_args:
        default_value = given_args.pop('default')
        for command in command_entry:
            if (default_arg := command.get('default')) is True:
                given_args[default_arg] = default_value
            return given_args
        raise DemistoException(f'Found a default argument, but no default argument exists in instance.')


def create_args(command_entry: dict, args: List[str]) -> dict:
    new_args = {}
    for arg in args:
        cmd_arg = arg.split('=', maxsplit=1)
        if len(cmd_arg) == 1:  # default parameter
            new_args['default'] = cmd_arg
        else:
            new_args[cmd_arg[0]] = cmd_arg[1]
    new_args = set_default_arg(command_entry, new_args)
    return new_args


def are_args_available(command_entry: dict, given_args: dict) -> dict:
    non_existing_args = list()
    for arg in given_args.keys():
        if arg not in command_entry:
            non_existing_args.append(arg)
    if non_existing_args:
        raise DemistoException(
            f'Found the following arguments that does not exists in the command: {", ".join(non_existing_args)}'
        )
    return given_args


def main(args):
    try:
        instance_name = args.get('instance_name')
        command: str = args.get('command_line')
        splitted = command.split()
        command = splitted[0]
        command_entry = is_command_available(instance_name, command)
        given_args = create_args(command_entry, splitted[1:])
        are_args_available(command_entry, given_args)
        human_readable = tableToMarkdown('Command args validated', given_args)
        return_outputs(human_readable, given_args)
    except Exception as exc:
        return_error(exc)


if __name__ in ("__main__", "builtin", "builtins"):
    main(demisto.args())
