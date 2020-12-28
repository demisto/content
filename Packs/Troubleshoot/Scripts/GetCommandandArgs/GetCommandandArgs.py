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


def set_default_arg(command_entry: dict, given_args: dict) -> dict:
    if 'default' in given_args:
        default_value = given_args.pop('default')
        for command in command_entry:
            if (default_arg := command.get('default')) is True:
                given_args[default_arg] = default_value
            return given_args
        raise DemistoException('Found a default argument, but no default argument exists in instance.')
    return given_args


def create_args(command_entry: dict, args: List[str]) -> dict:
    new_args = {}
    for arg in args:
        cmd_arg = arg.split('=', maxsplit=1)
        if len(cmd_arg) == 1:  # default parameter
            new_args['default'] = cmd_arg
        else:
            key, value = cmd_arg[0], cmd_arg[1]
            if not isinstance(value, str):
                value = json.dumps(value)
            new_args[key] = str(value)  # type: ignore[assignment]
    new_args = set_default_arg(command_entry, new_args)
    return new_args


def get_required_args(arguments_entry: list) -> list:
    return [entry['name'] for entry in arguments_entry if entry.get('required') is True]


def are_args_available(arguments_entry: dict, given_args: dict) -> dict:
    non_existing_args = list()
    arguments_list = [entry['name'] for entry in arguments_entry]
    args = list(given_args.keys())
    for arg in args:
        if arg not in arguments_list:
            non_existing_args.append(arg)
    if non_existing_args:
        raise DemistoException(
            f'Found the following arguments that does not exists in the command: {", ".join(non_existing_args)}'
        )
    required_args = set(get_required_args(arguments_list))

    if missing_args := required_args - set(args):
        raise DemistoException(
            f'Found missing required args {",".join(missing_args)}'
        )
    return given_args


def main():
    try:
        args = demisto.args()
        instance_name = args.get('instance_name')
        command: str = args.get('command_line')
        splitted = command.split()
        command_name = splitted[0].strip('!')
        command_entry = is_command_available(instance_name, command_name)
        given_args = create_args(command_entry, splitted[1:])
        are_args_available(command_entry.get('arguments', {}), given_args)
        given_args['using'] = instance_name
        context_entry = {
            'CommandArgs(val.instance_name === obj.instance_name)': {
                'instance_name': instance_name,
                'Arguments': given_args,
                'command': command_name,
                'full_command': f'{command_name} {" ".join(f"{key}={value}" for key, value in given_args.items())}'
            }
        }
        human_readable = tableToMarkdown('Command args validated', given_args)
        return_outputs(human_readable, context_entry)
    except Exception as exc:
        return_error(exc)


if __name__ in ("__main__", "builtin", "builtins"):
    main()
