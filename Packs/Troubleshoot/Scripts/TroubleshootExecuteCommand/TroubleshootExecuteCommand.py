"""
Command execute:
    Executes command with debug-mode
"""
from CommonServerPython import *


def _execute_command(command: str, arguments: dict):
    return demisto.executeCommand(command, arguments)


def get_errors(response: Union[list, dict]) -> List[str]:
    errors = list()
    if is_error(response):
        if isinstance(response, dict):
            errors.append(response['Contents'])

        for entry in response:
            is_error_entry = type(entry) is dict and entry['Type'] == entryTypes['error']
            if is_error_entry:
                errors.append(entry['Contents'])
    return errors


def get_log_file(response: Union[list, dict]):
    logs: List[dict]
    if isinstance(response, list):
        logs = [
            {
                'File': entry['File'],
                'FileID': entry['FileID']
            } for entry in response if entry.get('File', '').endswith('.log')
        ]
    elif response.get('File', '').endswith('.log'):
        logs = [
            {
                'File': response['File'],
                'FileID': response['FileID']
            }
        ]
    else:
        raise DemistoException('Could not find the log file')
    return logs


def main():
    args = demisto.args()
    command = args.get('command')
    arguments = args.get('arguments')
    if not arguments:
        arguments = {}
    elif isinstance(arguments, str) and arguments:
        arguments = json.loads(arguments)

    if isinstance(arguments, str):
        arguments = json.loads(arguments)
    instance_name = args.get('instance_name')
    arguments['using'] = instance_name
    arguments['debug-mode'] = True
    response = _execute_command(command, arguments)
    errors = get_errors(response)
    log_files = get_log_file(response)
    for log_file in log_files:
        with open(demisto.getFilePath(log_file['FileID'])['path']) as stream:
            demisto.results(fileResult(log_file['File'], stream.read()))
    if errors:
        human_readable = tableToMarkdown(
            f'Errors found for command {command}:\n',
            errors,
            ['Errors']
        )
    else:
        human_readable = f'No errors for command {command}!'
    context = {
        'TroubleshootExecuteCommand(obj.command === val.command && obj.instance_name === val.instance_name)': {
            'command': command,
            'instance_name': instance_name,
            'Error': errors
        }
    }
    return_outputs(human_readable, context)


if __name__ in ("__main__", "builtin", "builtins"):
    main()
