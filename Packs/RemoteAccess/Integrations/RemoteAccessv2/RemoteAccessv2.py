import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import StringIO
import paramiko
import urllib3
from paramiko import SSHClient, AutoAddPolicy, transport, Transport
from paramiko.ssh_exception import NoValidConnectionsError
from scp import SCPClient, SCPException

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member
DEFAULT_TIMEOUT = 10.0
DEFAULT_PORT = 22
''' HELPER FUNCTIONS '''


def perform_copy_command(ssh_client: SSHClient, file_path: str, destination_path: str, copy_to_remote: bool,
                         socket_timeout: float) -> Union[str, bytes]:
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
        socket_timeout(float): Socket timeout.

    Returns:
        (str): Empty str if command requested was copy to.
        (str): Str containing the copied file from remote machine data.
    Raises:
        (Exception):  if unexpected behaviour occurred.
    """
    try:
        with SCPClient(ssh_client.get_transport(), socket_timeout=socket_timeout) as scp_client:
            if copy_to_remote:
                scp_client.put(file_path, destination_path)
                return ''
            else:
                with tempfile.TemporaryDirectory() as temp_dir:
                    scp_client.get(file_path, f'{temp_dir}/{destination_path}')
                    with open(f'{temp_dir}/{destination_path}', 'rb') as f:
                        return f.read()
    except (FileNotFoundError, SCPException) as e:
        if 'No such file or directory' in str(e):
            raise DemistoException(f'Could not find the given path {file_path} in the local machine.\n'
                                   'Please verify the path is correct.') from e
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


def get_available_key_algorithms() -> Set[str]:
    """
    Gets a set of the available key algorithms supported by server.
    Returns:
        (Set[str]): Set of supported ciphers.
    """
    tmp_socket = socket.socket()
    opts = transport.Transport(tmp_socket).get_security_options()
    tmp_socket.close()
    return set(opts.kex)


def create_paramiko_ssh_client(
        host_name: str, user_name: str, password: str, ciphers: Set[str], key_algorithms: Set[str], private_key: str = '',
        port: int = DEFAULT_PORT) -> SSHClient:
    """
    Creates the Paramiko SSH client.

    Args:
        host_name (str): Hostname of the machine to create the SSH for.
        user_name (str): User to create the SSH session with the given host.
        password (str): Password of the given user.
        ciphers (Set[str]): Set of ciphers to be used, if given.
        key_algorithms (Set[str]): Set of key algorithms to be used, if given.
        private_key (str): The SSH certificate (should be PEM file based certificate only).
        port (int): The port to connect to.

    Returns:
        (SSHClient): Paramiko SSH client if connection was successful, exception otherwise.
    """
    if ciphers:
        # Getting available ciphers from server, in order to print an appropriate error message upon no cipher match.
        available_ciphers = get_available_ciphers()
        if not ciphers.intersection(available_ciphers):
            raise DemistoException(f'Given ciphers are not available in server.\n'
                                   f'Ciphers available in server are: {available_ciphers}')
        Transport._preferred_ciphers = (*ciphers,)  # type: ignore
    if key_algorithms:
        available_key_args = get_available_key_algorithms()
        if not key_algorithms.intersection(available_key_args):
            raise DemistoException(f'Given key algorithms are not available in server.\n'
                                   f'Key algorithms available in server are: {available_key_args}')
        Transport._preferred_kex = (*key_algorithms,)  # type: ignore
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    try:
        rsa_private_key = None
        if private_key:
            # authenticating with private key only works for certificates which are based on PEM files.
            # (RSA private keys)
            rsa_private_key = paramiko.RSAKey.from_private_key(StringIO(private_key))  # type: ignore # [assignment]
        client.connect(hostname=host_name, username=user_name, password=password, port=port, pkey=rsa_private_key)
    except NoValidConnectionsError as e:
        raise DemistoException(f'Unable to connect to port {port} on {host_name}') from e
    return client


def find_nonexistent_systems(given_systems: List[str], given_hosts: List[str]):
    investigation = demisto.investigation()
    if not investigation:
        return None

    systems = investigation.get('systems')
    investigation_id = investigation.get('id')
    demisto.debug(f'Available systems on investigation {investigation_id} are {systems}.')
    if not systems:
        return None

    systems_names = [system_properties.get('name') for system_properties in systems]
    not_found_systems = []
    for given_system in given_systems:
        if given_system not in systems_names:
            not_found_systems.append(given_system)

    systems_hosts = [system_properties.get('host') for system_properties in systems]
    not_found_hosts = []
    for given_host in given_hosts:
        if given_host not in systems_hosts:
            not_found_hosts.append(given_host)

    if not not_found_hosts and not not_found_systems:
        return None

    return f'{f"Systems {not_found_systems}" if not_found_systems else ""}' \
           f'{" and " if not_found_systems and not_found_hosts else ""}' \
           f'{f"Hosts {not_found_hosts}" if not_found_hosts else ""} ' \
           f'not found on investigation {investigation_id}. ' \
           f'Available systems by name are {systems_names}, and by host are {systems_hosts}.'


def create_clients(host_name: str, user: str, password: str, ciphers: Set[str], key_algorithms: Set[str], certificate: str,
                   systems: List[str], hosts: List[str], port: int = DEFAULT_PORT) -> List[SSHClient]:
    clients = [create_paramiko_ssh_client(system, user, password, ciphers, key_algorithms, certificate, port)
               for system in systems]
    clients.extend([create_paramiko_ssh_client(host, user, password, ciphers, key_algorithms, certificate, port)
                    for host in hosts])

    if not clients and host_name:
        client = create_paramiko_ssh_client(host_name, user, password, ciphers, key_algorithms, certificate, port)
        clients.append(client)

    return clients


def close_clients(clients: List[SSHClient]):
    for client in clients:
        client.close()


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
    command: str = args.get('cmd', '')
    timeout: Optional[int] = arg_to_number(args.get('timeout'))
    # exec_command returns a tuple of stdin, stdout, stderr. No need to parse stdin because it does not contain data.
    _, stdout, std_err = ssh_client.exec_command(command, timeout=timeout)
    stdout_str: str = stdout.read().decode()
    std_error_str: str = std_err.read().decode()
    if stdout_str or std_error_str:
        outputs: Optional[List[Dict]] = [{
            'output': stdout_str,
            'error': std_error_str,
            'command': command,
            'success': not std_error_str
        }]
        readable_output = tableToMarkdown(f'Command {command} Outputs', outputs, removeNull=True)
    else:
        outputs = None
        readable_output = f'### Command {command} was executed successfully without any outputs.'
    return CommandResults(
        outputs_prefix='RemoteAccess.Command',
        outputs=outputs,
        readable_output=readable_output
    )


def copy_to_command(ssh_client: SSHClient, args: Dict[str, Any]) -> CommandResults:
    """
    Executes a safe copy from Cortex XSOAR to remote machine.
    Args:
        ssh_client (SSHClient): SSH client to perform the command with.
        args (Dict[str, Any]): Cortex XSOAR arguments.

    Returns:
        (CommandResults).
    """
    dest_dir_arg = args.get('dest-dir', '')
    destination_path_arg = args.get('destination_path', '')
    if dest_dir_arg and destination_path_arg:
        raise DemistoException('Please provide at most one of "dest-dir" argument or "destination_path", not both.')

    # Support `entry` argument to maintain BC:
    entry: str = args.get('entry', '')
    entry_id: str = args.get('entry_id', entry)
    if not entry_id:
        raise DemistoException('No entry ID path given. Please provide one of the "entry_id" (recommended) or "entry" inputs.')

    if timeout := args.get('timeout'):
        timeout = float(timeout)
    else:
        timeout = DEFAULT_TIMEOUT
    file_path_data = demisto.getFilePath(entry_id)
    if not (file_path := file_path_data.get('path', '')):
        raise DemistoException('Could not find given entry ID path. Please assure given entry ID is correct.')
    file_name = file_path_data.get('name', '')

    if dest_dir_arg:
        destination_path = os.path.join(dest_dir_arg, file_name)
        destination_dir = dest_dir_arg
    elif destination_path_arg:
        destination_path = destination_path_arg
        destination_dir = os.path.split(destination_path)[0]
    else:
        destination_path = file_name
        destination_dir = ''

    # Create all folders to destination_path in the remote machine
    if destination_dir:
        try:
            execute_shell_command(ssh_client, args={'cmd': f'mkdir -p {destination_dir}'})
        except Exception as e:
            # ignore the error of creating the dir, as sometime is already exist and the error are due to permission
            # otherwise the next operation will fail.
            demisto.debug(f'Ignoring the error: {str(e)}, occurred when run the command: mkdir -p {destination_dir}')

    perform_copy_command(ssh_client, file_path, destination_path, copy_to_remote=True, socket_timeout=timeout)
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
    if timeout := args.get('timeout'):
        timeout = float(timeout)
    else:
        timeout = DEFAULT_TIMEOUT
    # Support `file` argument to maintain BC:
    file: str = args.get('file', '')
    file_path: str = args.get('file_path', file)
    file_name: str = args.get('file_name', os.path.basename(file_path))
    remote_file_data = perform_copy_command(ssh_client, file_path, file_name, copy_to_remote=False,
                                            socket_timeout=timeout)

    return fileResult(file_name, remote_file_data)


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    credentials: Dict[str, Any] = params.get('credentials') or {}
    user: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    certificate: str = (credentials.get('credentials') or {}).get('sshkey', '')

    host_name: str = params.get('hostname', '')
    ciphers: Set[str] = set(argToList(params.get('ciphers')))
    key_algorithms: Set[str] = set(argToList(params.get('key_algorithms')))

    demisto.debug(f'Command being called is {demisto.command()}')
    if password_param := params.get('additional_password', {}).get('password'):
        if command != 'test-module' and password_param != args.get('additional_password'):
            raise DemistoException('Additional password to use the module have been supplied.\n'
                                   'Please supply "additional_password" argument that matches the "Additional Password"'
                                   ' parameter value.')

    systems = argToList(args.get('system'))
    hosts = argToList(args.get('host'))
    port = args.get('port') or DEFAULT_PORT

    clients = []
    try:
        if nonexistent_systems_result := find_nonexistent_systems(systems, hosts):
            raise DemistoException(nonexistent_systems_result)
        clients = create_clients(host_name, user, password, ciphers, key_algorithms, certificate, systems, hosts, port)

        commands = {
            'ssh': execute_shell_command,
            'copy-to': copy_to_command,
            'copy-from': copy_from_command,
        }

        if command == 'test-module':
            return_results('ok')
        elif command in commands:
            if not clients:
                raise DemistoException('Command can\'t be executed because no hostname, system, or host was provided.')

            results = []
            with ThreadPoolExecutor(max_workers=len(clients)) as executor:
                future_results = [executor.submit(commands[command], ssh_client=client, args=args) for client in clients]
                for future in as_completed(future_results):
                    results.append(future.result())

            return_results(results)

        else:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')

    finally:
        close_clients(clients)


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
