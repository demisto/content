from paramiko import SSHClient, AutoAddPolicy, transport, Transport, SSHException
from scp import SCPClient, SCPException
import shutil
import tempfile
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' HELPER FUNCTIONS '''


def create_paramiko_ssh_client(host_name: str, user_name: str, password: str, ciphers: List[str],
                               key_algorithms: List[str]) -> SSHClient:
    available_ciphers, available_keys = 'Did not retrieve ciphers from server', 'Did not retrieve algorithm keys ' \
                                                                                'from server '
    try:
        opts = transport.Transport(socket.socket()).get_security_options()
        available_ciphers = opts.ciphers
        available_keys = opts.kex
        if ciphers:
            Transport._preferred_ciphers = (*ciphers,)
        # if key_algorithms:
        #     Transport._preferred_keys = (*key_algorithms,)
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(hostname=host_name, username=user_name, password=password, port=22)
        return client
    except SSHException as e:
        err_message = str(e)
        if 'Incompatible ssh server (no acceptable ciphers)' in err_message:
            raise DemistoException(f'Given ciphers are not available in server.\nCiphers given are: {ciphers}\n'
                                   f'Ciphers available in server are: {available_ciphers}') from e
        if 'Incompatible ssh peer (no acceptable host key)':
            raise DemistoException(f'Given algorithm key  are not available in server.\n'
                                   f'Key algorithms given are: {key_algorithms}\n'
                                   f'Key algorithms available in server are: {available_keys}') from e


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
    file_path = 'lol'# args.get('file_path', '')
    file_name: str = args.get('file_name', os.path.basename(file_path))
    try:
        with SCPClient(ssh_client.get_transport()) as scp_client, tempfile.TemporaryDirectory() as temp_dir:
            scp_client.get(file_path, f'{temp_dir}/{file_name}')
            with open(f'{temp_dir}/{file_name}', 'r') as f:
                remote_file_data = f.read()
    except SCPException as e:
        if 'No such file or directory' in str(e):

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
    key_algorithms: List[str] = argToList(params.get('key_algorithms'))

    interactive_terminal_mode: bool = argToBoolean(params.get('interactive_terminal_mode', False))
    # verify_certificate = not demisto.params().get('insecure', False)
    # proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    client = None
    try:
        client = create_paramiko_ssh_client(host_name, user, password, ciphers, key_algorithms)
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
