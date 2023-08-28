import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


def execute_ssh_command():
    """Execute the `ssh` command to get the server logs and return the result to the war room.
    """
    file = '/var/log/demisto/server.log'
    res = demisto.executeCommand('ssh', {'cmd': f'tail {file}', 'using': 'localhost'})

    output = f'File: {file}\n'
    output += res[0].get('Contents').get('output')
    output = re.sub(r' \(source: .*\)', '', output)

    return_results(output)


def main():
    try:
        execute_ssh_command()
    except ValueError as e:
        demisto.error(str(e))
        return_error('The script could not execute the `ssh` command. Please create an instance of the'
                     '`RemoteAccess` integration and try to run the script again.')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
