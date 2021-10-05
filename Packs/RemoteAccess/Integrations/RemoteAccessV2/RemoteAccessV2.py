import traceback
from typing import Dict, Any

import requests
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' HELPER FUNCTIONS '''
''' COMMAND FUNCTIONS '''


# TODO make sure support all kind of terminals
def execute_shell_command(client: SSHClient, args: Dict[str, Any]) -> CommandResults:
    command: str = args.get('command', '')
    # exec_command returns a tuple of stdin, stdout, stderr. No need to parse stdin because it does not contain data.
    _, stdout, std_err = client.exec_command(command)
    outputs: List[Dict] = [{
        'stdout': stdout.read().decode(),
        'std_error': std_err.read().decode()
    }]
    return CommandResults(
        outputs_prefix='RemoteAccess.Command',
        outputs=outputs,
        readable_output=tableToMarkdown(f'Command {command} Outputs', outputs)
    )


def copy_to_command(ssh_client: SSHClient, args: Dict[str, Any]) -> CommandResults:
    entry_id: str = args.get('entry_id', '')
    # if not (file_path := demisto.getFilePath(entry_id).get('path', '')):
    #     raise DemistoException('Could not find given entry ID path. Please assure given entry ID is correct.')
    # TODO delete after checks
    file_path = args.get('file_path', '')
    destination_path: str = args.get('destination_path', file_path)

    with SCPClient(ssh_client.get_transport()) as scp_client:
        scp_client.put(file_path, destination_path)
    return CommandResults(readable_output=f'### The file corresponding to entry ID: {entry_id} was copied to remote'
                                          'host.')


def copy_from_command(ssh_client: SSHClient, args: Dict[str, Any]) -> fileResult:
    file_path = args.get('file_path', '')
    file_name: str = args.get('file_name', '')

    with SCPClient(ssh_client.get_transport()) as scp_client:
        os.mkdir('tmp')
        scp_client.get(file_path, f'tmp/{file_path}')
        with open(f'tmp/{file_path}', 'r') as f:
            remote_file_data = f.read()

    file_name = file_name or os.path.basename(file_path)
    return fileResult(file_name, remote_file_data)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    credentials: Dict = params.get('credentials', {})
    user: Optional[str] = credentials.get('identifier')
    password: Optional[str] = credentials.get('password')

    host_name: str = params.get('hostname', '')

    ciphers: List[str] = argToList(params.get('ciphers'))

    interactive_terminal_mode: bool = argToBoolean(params.get('interactive_terminal_mode', False))
    # verify_certificate = not demisto.params().get('insecure', False)
    # proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    client = None
    try:
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(hostname=host_name, username=user, password=password, port=22)
        if demisto.command() == 'test-module':
            return_results('ok')
        elif command == 'remote-access-ssh':
            return_results(execute_shell_command(client, args))
        elif command == 'remote-access-copy-to':
            return_results(copy_to_command(client, args))
        elif command == 'remote-access-copy-from':
            return_results(copy_from_command(client, args))

        else:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')
        client.close()

    # Log exceptions and return errors
    except Exception as e:
        if client:
            client.close()
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
