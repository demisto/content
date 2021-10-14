import tempfile

from paramiko import SSHClient, AutoAddPolicy, transport, Transport
from scp import SCPClient, SCPException

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' HELPER FUNCTIONS '''


def perform_copy_command(ssh_client: SSHClient, file_path: str, destination_path: str, copy_to_remote: bool) -> str:
    """
    Function to perform copy to or copy from remote machine.
    This helper function was separated from command functions mainly for easier mocking in tests.
    Args:
        ssh_client (SSHClient): SSH client to perform copy from or to.
        file_path (str):
        - Copy to remote machine from Cortex XSOAR - the Cortex XSOAR file path.
        - Copy to Cortex XSOAR from remote machine - the remote machine file path.
        destination_path (str):
        - Copy to remote machine from Cortex XSOAR - the remote machine file path to contain the copied data.
        - Copy to Cortex XSOAR from remote machine - Temp file name to save the file, before extracting its data.
        copy_to_remote (bool): Whether a request to copy to remote was made.

    Returns:
        (str): Empty str if command requested was copy to.
        (str): Str containing the copied file from remote machine data.
    Raises:
        (Exception):  if unexpected behaviour occurred.
    """
    try:
        with SCPClient(ssh_client.get_transport()) as scp_client:
            if copy_to_remote:
                scp_client.put(file_path, destination_path)
                return ''
            else:
                with tempfile.TemporaryDirectory() as temp_dir:
                    scp_client.get(file_path, f'{temp_dir}/{destination_path}')
                    with open(f'{temp_dir}/{destination_path}', 'r') as f:
                        remote_file_data = f.read()
                        return remote_file_data
    except FileNotFoundError as e:
        if 'No such file or directory' in str(e):
            raise DemistoException(f'Could not find the given path {file_path} in the local machine.\n'
                                   'Please verify the path is correct.') from e
        raise e
    except SCPException as e:
        if 'Not a directory' in str(e):
            raise DemistoException(f'Given destination path: {destination_path} does not exist in remote machine.\n'
                                   'Please verify destination path is valid.') from e
        if 'No such file or directory' in str(e):
            raise DemistoException(f'Could not find the given path {file_path} in the remote machine.\n'
                                   'Please verify the path is correct.') from e
        raise e


def get_available_ciphers() -> Set[str]:
    """
    Gets a set of the available ciphers supported by server.
    Returns:
        (Set[str]): Set of supported ciphers.
    """
    tmp_socket = socket.socket()
    opts = transport.Transport(tmp_socket).get_security_options()
    tmp_socket.close()
    return set(opts.ciphers)


def create_paramiko_ssh_client(host_name: str, user_name: str, password: str, ciphers: Set[str]) -> SSHClient:
    """
    Creates the Paramiko SSH client.
    Args:
        host_name (str): Hostname of the machine to create the SSH for.
        user_name (str): User to create the SSH session with the given host.
        password (str): Password of the given user.
        ciphers (Set[str]): List of ciphers to be used, if given.

    Returns:
        (SSHClient): Paramiko SSH client if connection was successful, exception otherwise.
    """
    if ciphers:
        # Getting available ciphers from server, in order to print an appropriate error message upon no cipher match.
        available_ciphers = get_available_ciphers()
        if not ciphers.intersection(available_ciphers):
            raise DemistoException(f'Given ciphers are not available in server.\nCiphers given are: {ciphers}\n'
                                   f'Ciphers available in server are: {available_ciphers}')
        Transport._preferred_ciphers = (*ciphers,)
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(hostname=host_name, username=user_name, password=password, port=22)
    return client


''' COMMAND FUNCTIONS '''


def execute_shell_command(ssh_client: SSHClient, args: Dict[str, Any]) -> CommandResults:
    """
    Executes shell command.
    Args:
        ssh_client (SSHClient): SSH client to perform the command with.
        args (Dict[str, Any]): Cortex XSOAR arguments.

    Returns:
        (CommandResults).
    """
    command: str = args.get('command', '')
    # exec_command returns a tuple of stdin, stdout, stderr. No need to parse stdin because it does not contain data.
    _, stdout, std_err = ssh_client.exec_command(command)
    stdout_str: str = stdout.read().decode()
    std_error_str: str = std_err.read().decode()
    if stdout_str or std_error_str:
        outputs: Optional[List[Dict]] = [{
            'stdout': stdout_str,
            'std_error': std_error_str
        }]
        readable_output = tableToMarkdown(f'Command {command} Outputs', outputs, removeNull=True)
    else:
        outputs = None
        readable_output = f'### Command {command} Was Executed Successfully Without Any Outputs.'
    return CommandResults(
        outputs_prefix='RemoteAccess.Command',
        outputs=outputs,
        readable_output=readable_output
    )


def copy_to_command(ssh_client: SSHClient, args: Dict[str, Any]) -> CommandResults:
    """
    Executes a safe copy from Cortex XSSOAR to remote machine.
    Args:
        ssh_client (SSHClient): SSH client to perform the command with.
        args (Dict[str, Any]): Cortex XSOAR arguments.

    Returns:
        (CommandResults).
    """
    entry_id: str = args.get('entry_id', '')
    if not (file_path := demisto.getFilePath(entry_id).get('path', '')):
        raise DemistoException('Could not find given entry ID path. Please assure given entry ID is correct.')
    destination_path: str = args.get('destination_path', file_path)
    perform_copy_command(ssh_client, file_path, destination_path, copy_to_remote=True)
    return CommandResults(readable_output=f'### The file corresponding to entry ID: {entry_id} was copied to remote'
                                          ' host.')


def copy_from_command(ssh_client: SSHClient, args: Dict[str, Any]) -> Dict:
    """
    Executes a safe copy from remote machine to Cortex XSOAR machine.
    Args:
        ssh_client (SSHClient): SSH client to perform the command with.
        args (Dict[str, Any]): Cortex XSOAR arguments.

    Returns:
        (Dict): FileResult data.
    """
    file_path: str = args.get('file_path', '')
    file_name: str = args.get('file_name', os.path.basename(file_path))
    remote_file_data = perform_copy_command(ssh_client, file_path, file_name, copy_to_remote=False)

    return fileResult(file_name, remote_file_data)


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    credentials: Dict[str, Any] = params.get('credentials', {})
    user: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')

    host_name: str = params.get('hostname', '')

    ciphers: Set[str] = set(argToList(params.get('ciphers')))

    # interactive_terminal_mode: bool = argToBoolean(params.get('interactive_terminal_mode', False))
    demisto.debug(f'Command being called is {demisto.command()}')
    client = None
    try:
        client = create_paramiko_ssh_client(host_name, user, password, ciphers)
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
