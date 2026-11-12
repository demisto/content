import pytest

from CommonServerPython import *


def test_get_external_file_too_many_new_lines(mocker):
    """
    Given:
     - an invalid file content with too many newlines

    When:
     - running edl_get_external_file_command

    Then:
     - Verify that an appropriate error message is shown to the user
     - Verify that ssh_execute was executed the correct amount of times
    """
    import PaloAltoNetworks_PAN_OS_EDL_Management as PANW_EDL
    invalid_file = 'a\nb\na\nn\ni\nb\ni\na\nb\no\nd\ne\nb\ne\n'
    mocker.patch.object(PANW_EDL, 'ssh_execute', return_value=invalid_file)
    err_msg = 'The file contains too many newlines to be valid. ' \
              'Please check the file contents on the external web server manually.'
    with pytest.raises(DemistoException, match=err_msg):
        PANW_EDL.edl_get_external_file_command(args={'file_path': 'lies', 'retries': '4'})

    assert PANW_EDL.ssh_execute.call_count == 4


MALICIOUS_INPUTS = [
    "x' ; touch /tmp/pwned ; echo '",
    "$(touch /tmp/pwned)",
    "`touch /tmp/pwned`",
    "a; rm -rf / #",
    "-f/etc/passwd",
]


def _remote_argv(command: str) -> list:
    """Splits a remote command string the same way a POSIX shell tokenizes it."""
    import shlex
    return shlex.split(command)


@pytest.mark.parametrize('malicious', MALICIOUS_INPUTS)
def test_search_external_file_escapes_arguments(mocker, malicious):
    """
    Given:
     - search_string and file_path values containing shell metacharacters
    When:
     - running edl_search_external_file
    Then:
     - Verify each value reaches the remote grep as a single literal argument after the end-of-options marker
    """
    import PaloAltoNetworks_PAN_OS_EDL_Management as PANW_EDL
    ssh_mock = mocker.patch.object(PANW_EDL, 'ssh_execute', return_value='')

    PANW_EDL.edl_search_external_file(file_path=malicious, search_string=malicious)

    assert _remote_argv(ssh_mock.call_args[0][0]) == ['grep', '--', malicious, malicious]


@pytest.mark.parametrize('malicious', MALICIOUS_INPUTS)
def test_get_external_file_escapes_file_path(mocker, malicious):
    """
    Given:
     - a file_path containing shell metacharacters
    When:
     - running edl_get_external_file
    Then:
     - Verify the file path reaches the remote cat as a single literal argument
    """
    import PaloAltoNetworks_PAN_OS_EDL_Management as PANW_EDL
    ssh_mock = mocker.patch.object(PANW_EDL, 'ssh_execute', return_value='a\nb')

    PANW_EDL.edl_get_external_file(malicious)

    assert _remote_argv(ssh_mock.call_args[0][0]) == ['cat', '--', malicious]


@pytest.mark.parametrize('malicious', MALICIOUS_INPUTS)
def test_delete_external_file_escapes_file_path(mocker, malicious):
    """
    Given:
     - a file_path containing shell metacharacters
    When:
     - running edl_delete_external_file
    Then:
     - Verify the file path reaches the remote rm as a single literal argument
    """
    import PaloAltoNetworks_PAN_OS_EDL_Management as PANW_EDL
    ssh_mock = mocker.patch.object(PANW_EDL, 'ssh_execute', return_value='')

    PANW_EDL.edl_delete_external_file(malicious)

    assert _remote_argv(ssh_mock.call_args[0][0]) == ['rm', '-f', '--', malicious]


@pytest.mark.parametrize('malicious', MALICIOUS_INPUTS)
def test_get_external_file_metadata_escapes_file_path(mocker, malicious):
    """
    Given:
     - a file_path containing shell metacharacters
    When:
     - running edl_get_external_file_metadata_command
    Then:
     - Verify the file path reaches the remote stat and wc commands as a single literal argument
    """
    import PaloAltoNetworks_PAN_OS_EDL_Management as PANW_EDL
    mocker.patch.object(PANW_EDL, 'DOCUMENT_ROOT', '')
    mocker.patch.object(demisto, 'results')
    stat_output = '  File: x\n  Size: 10  Blocks: 8\nChange: 2026-01-01 10:00:00.000 +0000\n'
    ssh_mock = mocker.patch.object(PANW_EDL, 'ssh_execute', side_effect=[stat_output, '3'])

    PANW_EDL.edl_get_external_file_metadata_command({'file_path': malicious})

    assert _remote_argv(ssh_mock.call_args_list[0][0][0]) == ['stat', '--', malicious]
    assert _remote_argv(ssh_mock.call_args_list[1][0][0]) == ['wc', '-l', '<', malicious]


@pytest.mark.parametrize('malicious', MALICIOUS_INPUTS)
def test_scp_execute_escapes_remote_path(mocker, malicious):
    """
    Given:
     - a remote file_path containing shell metacharacters
    When:
     - running scp_execute
    Then:
     - Verify the remote path is shell-quoted and options parsing is terminated before the file arguments
    """
    import subprocess
    import PaloAltoNetworks_PAN_OS_EDL_Management as PANW_EDL
    mocker.patch.object(PANW_EDL, 'USERNAME', 'user')
    mocker.patch.object(PANW_EDL, 'HOSTNAME', 'host')
    mocker.patch.object(PANW_EDL, 'SCP_EXTRA_PARAMS', None)
    run_mock = mocker.patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', ''))

    assert PANW_EDL.scp_execute('-oProxyCommand=evil.txt', malicious)

    argv = run_mock.call_args[0][0]
    assert argv[-3:-1] == ['--', '-oProxyCommand=evil.txt']
    remote_target = argv[-1]
    assert remote_target.startswith('user@host:')
    assert _remote_argv(remote_target[len('user@host:'):]) == [malicious]
