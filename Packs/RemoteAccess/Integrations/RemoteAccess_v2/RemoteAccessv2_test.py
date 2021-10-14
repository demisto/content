import io
import json

import pytest
from RemoteAccessV2 import CommandResults, DemistoException


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('ciphers', [({'diffie-hellman-group14-sha256'}),
                                     ({'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha128'})])
def test_create_paramiko_ssh_client_valid(mocker, ciphers):
    """
    Given:
    - Parameters to create SSH client.

    When:
    - Given parameters are valid.

    Then:
    - Ensure SSH client is created.
    """
    from RemoteAccessV2 import create_paramiko_ssh_client
    mocker.patch('paramiko.SSHClient.connect')
    mocker.patch('RemoteAccessV2.get_available_ciphers', return_value=ciphers)
    create_paramiko_ssh_client('host', 'user', 'password', [])


@pytest.mark.parametrize('ciphers', [({'diffie-hellman-group14-sha256'}),
                                     ({'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha128'})])
def test_create_paramiko_ssh_client_invalid_ciphers(mocker, ciphers):
    """
    Given:
    - Parameters to create SSH client.

    When:
    - Given ciphers do not match the server ciphers.

    Then:
    - Ensure DemistoException is thrown as expected.
    """
    from RemoteAccessV2 import create_paramiko_ssh_client
    server_ciphers = {'diffie-hellman-group14-sha512'}
    mocker.patch('RemoteAccessV2.get_available_ciphers', return_value=server_ciphers)
    expected_err_msg: str = f"Given ciphers are not available in server.\nCiphers given are: {ciphers}\n" \
                            f"Ciphers available in server are: {server_ciphers}"
    with pytest.raises(DemistoException, match=expected_err_msg):
        create_paramiko_ssh_client('host', 'user', 'password', ciphers)


@pytest.mark.parametrize('command, mock_std_output, mock_std_error',
                         [('echo lol', 'lol', ''), ('cat invalid_path_file', '', 'cat: lol: No such file or directory'),
                          ('non-known-command', '', 'command not found: non-known-command')])
def test_execute_shell_command(mocker, command, mock_std_output, mock_std_error):
    """
    Given:
    - Cortex XSOAR arguments.

    When:
    - Executing shell command.

    Then:
    - Ensure expected output and error are returned.
    """
    from RemoteAccessV2 import execute_shell_command, CommandResults, tempfile
    from paramiko import SSHClient
    mock_client: SSHClient = SSHClient()
    with tempfile.TemporaryDirectory() as temp_dir:
        with open(f'{temp_dir}/std_out', 'wb') as f_output, open(f'{temp_dir}/std_err', 'wb') as f_err:
            f_output.write(mock_std_output.encode('utf-8'))
            f_err.write(mock_std_error.encode('utf-8'))

        with open(f'{temp_dir}/std_out', 'rb') as f_output, open(f'{temp_dir}/std_err', 'rb') as f_err:
            mocker.patch.object(mock_client, 'exec_command', return_value=(None, f_output, f_err))
            results: CommandResults = execute_shell_command(mock_client, {'command': command})
    assert results.outputs_prefix == 'RemoteAccess.Command'
    assert results.outputs == [{
        'stdout': mock_std_output,
        'std_error': mock_std_error
    }]


def test_copy_to_command_valid(mocker):
    """
    Given:
    - Cortex XSOAR arguments

    When:
    - Calling the remote-access-copy-to command.

    Then:
    - Ensure expected readable output is returned upon successful copy.
    """
    from RemoteAccessV2 import copy_to_command
    from paramiko import SSHClient
    mock_client: SSHClient = SSHClient()
    mocker.patch('RemoteAccessV2.perform_copy_command', return_value='')
    results: CommandResults = copy_to_command(mock_client, {'entry_id': 123})
    assert results.readable_output == '### The file corresponding to entry ID: 123 was copied to remote host.'


def test_copy_to_command_invalid_entry_id(mocker):
    """
    Given:
    - Cortex XSOAR arguments

    When:
    - Calling the remote-access-copy-to command with invalid entry ID input.

    Then:
    - Ensure DemistoException is thrown with expected error message.
    """
    from RemoteAccessV2 import copy_to_command
    from paramiko import SSHClient
    import demistomock as demisto
    mock_client: SSHClient = SSHClient()
    mocker.patch.object(demisto, 'getFilePath', return_value={})
    with pytest.raises(DemistoException,
                       match='Could not find given entry ID path. Please assure given entry ID is correct.'):
        copy_to_command(mock_client, {'entry_id': 123})


@pytest.mark.parametrize('file_name, expected_file_name', ([None, 'mock_path.txt'], ['Name', 'Name']))
def test_copy_from_command_valid(mocker, file_name, expected_file_name):
    """
    Given:
    - Cortex XSOAR arguments

    When:
    - Calling the remote-access-copy-to command.
    Case a: Calling the command without specified file name.
    Case b: Calling the command with specified file name.

    Then:
    - Ensure expected fileResult object is returned.
    """
    from RemoteAccessV2 import copy_from_command
    from paramiko import SSHClient
    import RemoteAccessV2
    mock_client: SSHClient = SSHClient()
    mocker_results = mocker.patch.object(RemoteAccessV2, 'fileResult')
    mocker.patch('RemoteAccessV2.perform_copy_command', return_value='RemoteFileData')
    args = {'file_path': 'mock_path.txt'}
    if file_name:
        args['file_name'] = file_name
    copy_from_command(mock_client, args)
    assert mocker_results.call_args[0][0] == expected_file_name
    assert mocker_results.call_args[0][1] == 'RemoteFileData'
