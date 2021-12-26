import io
import json

import pytest
from RemoteAccessv2 import CommandResults, DemistoException
import demistomock as demisto


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('cipher_arg, key_arg, server_ciphers, server_key_algorithms',
                         [(set(), set(), set(), set()), (set(), {'diffie-hellman-group14-sha256'}, set(),
                                                         {'diffie-hellman-group14-sha256',
                                                          'diffie-hellman-group14-sha128'}),
                          ({'aes128-cbc'}, set(), {'aes128-cbc'}, set()),
                          ({'aes128-cbc'}, {'diffie-hellman-group14-sha256'}, {'aes128-cbc'},
                           {'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha128'})])
def test_create_paramiko_ssh_client_valid(mocker, cipher_arg, key_arg, server_ciphers, server_key_algorithms):
    """
    Given:
    - Parameters to create SSH client.

    When:
    - Given parameters are valid.
    Cases:
    - Case a: No ciphers and no key algorithms to be used have been given by the user.
    - Case b: No ciphers to be used, but key algorithm to be used which is supported by server where given by the user.
    - Case c: Cipher to be used that is supported by server, but no key algorithm were given by the user.
    - Case d: Both cipher and key algorithm have been requested by the user, both are supported by server.


    Then:
    - Ensure SSH client is created.
    """
    from RemoteAccessv2 import create_paramiko_ssh_client
    mocker.patch('paramiko.SSHClient.connect')
    if server_ciphers:
        mocker.patch('RemoteAccessv2.get_available_ciphers', return_value=server_ciphers)
    if server_key_algorithms:
        mocker.patch('RemoteAccessv2.get_available_key_algorithms', return_value=server_key_algorithms)
    create_paramiko_ssh_client('host', 'user', 'password', cipher_arg, key_arg)


@pytest.mark.parametrize('cipher_arg, key_arg, server_ciphers, server_key_algorithms',
                         [({'unsupported cipher'}, set(), {'aes128-cbc'}, set()),
                          (set(), {'unsupported key'}, set(), {'diffie-hellman-group14-sha256'})])
def test_create_paramiko_ssh_client_invalid(mocker, cipher_arg, key_arg, server_ciphers, server_key_algorithms):
    """
    Given:
    - Parameters to create SSH client.

    When:
    - Given ciphers do not match the server ciphers.
    Cases:
    Case a: Cipher which is not supported by server was given by the user.
    Case b: Key algorithm which is not supported by server was given by the user.

    Then:
    - Ensure DemistoException is thrown as expected.
    """
    from RemoteAccessv2 import create_paramiko_ssh_client
    server_ciphers = {'diffie-hellman-group14-sha512'}
    expected_err_msg: str = ''
    if server_ciphers:
        expected_err_msg = f'Given ciphers are not available in server.\n' \
                           f'Ciphers available in server are: {server_ciphers}'
        mocker.patch('RemoteAccessv2.get_available_ciphers', return_value=server_ciphers)
    if server_key_algorithms:
        expected_err_msg = f'Given key algorithms are not available in server.\n' \
                           f'Key algorithms available in server are: {server_key_algorithms}'
        mocker.patch('RemoteAccessv2.get_available_key_algorithms', return_value=server_key_algorithms)
    with pytest.raises(DemistoException, match=expected_err_msg):
        create_paramiko_ssh_client('host', 'user', 'password', cipher_arg, key_arg)


@pytest.mark.parametrize('command, mock_std_output, mock_std_error, success',
                         [('echo lol', 'lol', '', True),
                          ('cat invalid_path_file', '', 'cat: lol: No such file or directory', False),
                          ('non-known-command', '', 'command not found: non-known-command', False)])
def test_execute_shell_command(mocker, command, mock_std_output, mock_std_error, success):
    """
    Given:
    - Cortex XSOAR arguments.

    When:
    - Executing shell command.

    Then:
    - Ensure expected output and error are returned.
    """
    from RemoteAccessv2 import execute_shell_command, CommandResults, tempfile
    from paramiko import SSHClient
    mock_client: SSHClient = SSHClient()
    with tempfile.TemporaryDirectory() as temp_dir:
        with open(f'{temp_dir}/std_out', 'wb') as f_output, open(f'{temp_dir}/std_err', 'wb') as f_err:
            f_output.write(mock_std_output.encode('utf-8'))
            f_err.write(mock_std_error.encode('utf-8'))

        with open(f'{temp_dir}/std_out', 'rb') as f_output, open(f'{temp_dir}/std_err', 'rb') as f_err:
            mocker.patch.object(mock_client, 'exec_command', return_value=(None, f_output, f_err))
            results: CommandResults = execute_shell_command(mock_client, {'cmd': command})
    assert results.outputs_prefix == 'RemoteAccess.Command'
    assert results.outputs == [{
        'output': mock_std_output,
        'error': mock_std_error,
        'success': success,
        'command': command
    }]


def test_copy_to_command_valid(mocker):
    """
    Given:
    - Cortex XSOAR arguments

    When:
    - Calling the copy-to command.

    Then:
    - Ensure expected readable output is returned upon successful copy.
    """
    from RemoteAccessv2 import copy_to_command
    from paramiko import SSHClient
    mock_client: SSHClient = SSHClient()
    mocker.patch('RemoteAccessv2.perform_copy_command', return_value='')
    results: CommandResults = copy_to_command(mock_client, {'entry_id': 123})
    assert results.readable_output == '### The file corresponding to entry ID: 123 was copied to remote host.'


def test_copy_to_command_invalid_entry_id(mocker):
    """
    Given:
    - Cortex XSOAR arguments

    When:
    - Calling the copy-to command with invalid entry ID input.

    Then:
    - Ensure DemistoException is thrown with expected error message.
    """
    from RemoteAccessv2 import copy_to_command
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
    - Calling the copy-to command.
    Case a: Calling the command without specified file name.
    Case b: Calling the command with specified file name.

    Then:
    - Ensure expected fileResult object is returned.
    """
    from RemoteAccessv2 import main
    from paramiko import SSHClient
    import RemoteAccessv2
    mock_client: SSHClient = SSHClient()
    mocker_results = mocker.patch.object(RemoteAccessv2, 'fileResult')
    mocker.patch.object(demisto, 'command', return_value='copy-from')
    mocker.patch.object(RemoteAccessv2, 'create_paramiko_ssh_client', return_value=mock_client)
    mocker.patch.object(RemoteAccessv2, 'return_results')
    args = {'file_path': 'mock_path.txt'}
    if file_name:
        args['file_name'] = file_name
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch('RemoteAccessv2.perform_copy_command', return_value='RemoteFileData')
    main()
    assert mocker_results.call_args[0][0] == expected_file_name
    assert mocker_results.call_args[0][1] == 'RemoteFileData'


@pytest.mark.parametrize('args', [({}), ({'additional_password': '1243'})])
def test_invalid_password_for_command(mocker, args):
    """"
    Given:
    - Cortex XSOAR params, having additional_password parameter fulfilled.
    - Cortex XSOAR arguments.

    When:
    - Executing a command.
    Cases:
    Case a: No additional_password was given in the arguments.
    Case a: Incorrect additional_password was given in the arguments.

    Then:
    - Ensure DemistoException is thrown with the expected error message.
    """
    from RemoteAccessv2 import main
    mocker.patch.object(demisto, 'params', return_value={'additional_password': {'password': '1234'}})
    mocker.patch.object(demisto, 'args', return_value=args)
    with pytest.raises(DemistoException, match='Additional password to use the module have been supplied.\n'
                                               'Please supply "additional_password" argument that matches '
                                               'the "Additional Password" parameter value.'):
        main()


def test_failed_authentication(mocker):
    """
    Given:
    - Cortex XSOAR arguments.
    - Cortex XSOAR command for Remote Access integration.

    When:
    - No credentials are given.

    Then:
    - Ensure error is returned.
    """
    from RemoteAccessv2 import main
    import RemoteAccessv2
    mocker.patch.object(RemoteAccessv2, 'return_error')
    mocker.patch.object(demisto, 'error')
    main()
    assert RemoteAccessv2.return_error.called
