from __future__ import print_function

import ast
import os
import json
import string
import time
import unicodedata
from pprint import pformat

import urllib3
import demisto_client.demisto_api
from subprocess import call, check_call, check_output, CalledProcessError, STDOUT


VALID_FILENAME_CHARS = '-_.() %s%s' % (string.ascii_letters, string.digits)
PROXY_PROCESS_INIT_TIMEOUT = 20
PROXY_PROCESS_INIT_INTERVAL = 1

# Disable insecure warnings
urllib3.disable_warnings()


def clean_filename(playbook_id, whitelist=VALID_FILENAME_CHARS, replace=' ()'):
    filename = playbook_id

    # replace spaces
    for r in replace:
        filename = filename.replace(r, '_')

    # keep only valid ascii chars
    cleaned_filename = unicodedata.normalize('NFKD', filename).encode('ASCII', 'ignore').decode()

    # keep only whitelisted chars
    cleaned_filename = ''.join(c for c in cleaned_filename if c in whitelist)
    return cleaned_filename


def silence_output(cmd_method, *args, **kwargs):
    """Redirect linux command output(s) to /dev/null
    To redirect to /dev/null: pass 'null' string in 'stdout' or 'stderr' keyword args

    Args:
        cmd_method (PyFunctionObject): the "subprocess" (or wrapper) method to run
        *args: additional parameters for cmd_method
        **kwargs: additional parameters for cmd_method

    Returns:
        string. output of cmd_method
    """
    with open(os.devnull, 'w') as fnull:
        for k in ('stdout', 'stderr'):
            if kwargs.get(k) == 'null':
                kwargs[k] = fnull

        return cmd_method(*args, **kwargs)


def get_mock_file_path(playbook_id):
    clean = clean_filename(playbook_id)
    return os.path.join(clean + '/', clean + '.mock')


def get_log_file_path(playbook_id, record=False):
    clean = clean_filename(playbook_id)
    suffix = '_record' if record else '_playback'
    return os.path.join(clean + '/', clean + suffix + '.log')


def get_folder_path(playbook_id):
    return clean_filename(playbook_id) + '/'


class AMIConnection:
    """Wrapper for AMI communication.

    Attributes:
        public_ip (string): The public IP of the AMI instance.
        docker_ip (string): The IP of the AMI on the docker bridge (to direct traffic from docker to the AMI).
    """

    REMOTE_MACHINE_USER = 'ec2-user'
    REMOTE_HOME = f'/home/{REMOTE_MACHINE_USER}/'
    LOCAL_SCRIPTS_DIR = '/home/circleci/project/Tests/scripts/'
    CLONE_MOCKS_SCRIPT = 'clone_mocks.sh'
    UPLOAD_MOCKS_SCRIPT = 'upload_mocks.sh'

    def __init__(self, public_ip):
        self.public_ip = public_ip
        self.docker_ip = self._get_docker_ip()

    def _get_docker_ip(self):
        """Get the IP of the AMI on the docker bridge.
        Used to configure the docker host (AMI machine, in this case) as the proxy server.

        Returns:
            string. The IP of the AMI on the docker bridge.
        """
        out = self.check_output(['/usr/sbin/ip', 'addr', 'show', 'docker0']).decode().split('\n')
        lines_of_words = map(lambda y: y.strip().split(' '), out)  # Split output to lines[words[]]
        address_lines = list(filter(lambda x: x[0] == 'inet', lines_of_words))  # Take only lines with ipv4 addresses
        if len(address_lines) != 1:
            raise Exception("docker bridge interface has {} ipv4 addresses, should only have one."
                            .format(len(address_lines)))
        return address_lines[0][1].split('/')[0]  # Return only the IP Address (without mask)

    def add_ssh_prefix(self, command, ssh_options=""):
        """Add necessary text before a command in order to run it on the AMI instance via SSH.

        Args:
            command (list): Command to run on the AMI machine (according to "subprocess" interface).
            ssh_options (string): optional parameters for ssh connection to AMI.

        Returns:
            string: ssh command that will run the desired command on the AMI.
        """
        if ssh_options and not isinstance(ssh_options, str):
            raise TypeError("options must be string")
        if not isinstance(command, list):
            raise TypeError("command must be list")
        prefix = "ssh {} -o StrictHostKeyChecking=no {}@{}".format(ssh_options,
                                                                   self.REMOTE_MACHINE_USER, self.public_ip).split()
        return prefix + command

    def call(self, command, **kwargs):
        return call(self.add_ssh_prefix(command), **kwargs)

    def check_call(self, command, **kwargs):
        return check_call(self.add_ssh_prefix(command), **kwargs)

    def check_output(self, command, **kwargs):
        return check_output(self.add_ssh_prefix(command), **kwargs)

    def copy_file(self, src, dst=REMOTE_HOME, **kwargs):
        silence_output(check_call, ['scp', '-o', ' StrictHostKeyChecking=no', src,
                                    "{}@{}:{}".format(self.REMOTE_MACHINE_USER, self.public_ip, dst)],
                       stdout='null', **kwargs)
        return os.path.join(dst, os.path.basename(src))

    def run_script(self, script, *args):
        """Copy a script to the AMI and run it.

        Args:
            script (string): Name of the script file in the LOCAL_SCRIPTS_DIR.
            *args: arguments to be passed to the script.
        """
        remote_script_path = self.copy_file(os.path.join(self.LOCAL_SCRIPTS_DIR, script))

        silence_output(self.check_call, ['chmod', '+x', remote_script_path], stdout='null')
        silence_output(self.check_call, [remote_script_path] + list(args), stdout='null')

    def upload_mock_files(self, build_name, build_number):
        self.run_script(self.UPLOAD_MOCKS_SCRIPT, build_name, build_number)

    def clone_mock_data(self):
        self.run_script(self.CLONE_MOCKS_SCRIPT)


class MITMProxy:
    """Manager for MITM Proxy and the mock file structure.

    Attributes:
        logging_manager: Logging module to use
        public_ip (string): The IP of the AMI instance.
        repo_folder (string): path to the local clone of the content-test-data git repo.
        tmp_folder (string): path to a temporary folder for log/mock files before pushing to git.
        current_folder (string): the current folder to use for mock/log files.
        ami (AMIConnection): Wrapper for AMI communication.
        empty_files (list): List of playbooks that have empty mock files (indicating no usage of mock mechanism).
        rerecorded_tests (list): List of playbook ids that failed on mock playback but succeeded on new recording.
    """

    PROXY_PORT = '9997'
    MOCKS_TMP_PATH = '/tmp/Mocks/'
    MOCKS_GIT_PATH = f'{AMIConnection.REMOTE_HOME}content-test-data/'
    TIME_TO_WAIT_FOR_PROXY_SECONDS = 30

    def __init__(self,
                 public_ip,
                 logging_manager,
                 repo_folder=MOCKS_GIT_PATH, tmp_folder=MOCKS_TMP_PATH):
        self.public_ip = public_ip
        self.current_folder = self.repo_folder = repo_folder
        self.tmp_folder = tmp_folder
        self.logging_manager = logging_manager
        self.ami = AMIConnection(self.public_ip)

        self.empty_files = []
        self.failed_tests_count = 0
        self.successful_tests_count = 0
        self.successful_rerecord_count = 0
        self.failed_rerecord_count = 0
        self.failed_rerecord_tests = []
        self.rerecorded_tests = []
        silence_output(self.ami.call, ['mkdir', '-p', tmp_folder], stderr='null')
        script_filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'timestamp_replacer.py')
        self.ami.copy_file(script_filepath)

    def configure_proxy_in_demisto(self, username, password, server, proxy=''):
        client = demisto_client.configure(base_url=server, username=username,
                                          password=password, verify_ssl=False)
        self.logging_manager.debug('Adding proxy server configurations')
        system_conf_response = demisto_client.generic_request_func(
            self=client,
            path='/system/config',
            method='GET'
        )
        system_conf = ast.literal_eval(system_conf_response[0]).get('sysConf', {})
        self.logging_manager.debug(f'Server configurations before proxy server configurations:\n{pformat(system_conf)}')
        http_proxy = https_proxy = proxy
        if proxy:
            http_proxy = 'http://' + proxy
            https_proxy = 'http://' + proxy
        system_conf.update({
            'http_proxy': http_proxy,
            'https_proxy': https_proxy
        })
        data = {
            'data': system_conf,
            'version': -1
        }
        response = demisto_client.generic_request_func(self=client, path='/system/config',
                                                       method='POST', body=data)
        self.logging_manager.debug(f'Server configurations response:\n{pformat(response)}')

        return response

    def get_mock_file_size(self, filepath):
        return self.ami.check_output(['stat', '-c', '%s', filepath]).strip()

    @staticmethod
    def get_script_mode(is_record: bool) -> str:
        """
        Returns the string describing script mode for the SCRIPT_MODE env variable needed for the mitmdump initialization
        Args:
            is_record: A boolean indicating this is record mode or not

        Returns:
            'record' if is_record is True else 'playback'
        """
        return 'record' if is_record else 'playback'

    def has_mock_file(self, playbook_id):
        command = ["[", "-f", os.path.join(self.current_folder, get_mock_file_path(playbook_id)), "]"]
        return self.ami.call(command) == 0

    def has_mock_folder(self, playbook_id):
        command = ["[", "-d", os.path.join(self.current_folder, get_folder_path(playbook_id)), "]"]
        return self.ami.call(command) == 0

    def set_repo_folder(self):
        """Set the repo folder as the current folder (the one used to store mock and log files)."""
        self.current_folder = self.repo_folder

    def set_tmp_folder(self):
        """Set the temp folder as the current folder (the one used to store mock and log files)."""
        self.current_folder = self.tmp_folder

    def move_mock_file_to_repo(self, playbook_id):
        """Move the mock and log files of a (successful) test playbook run from the temp folder to the repo folder

        Args:
            playbook_id (string): ID of the test playbook of which the files should be moved.
        """
        src_filepath = os.path.join(self.tmp_folder, get_mock_file_path(playbook_id))
        src_files = os.path.join(self.tmp_folder, get_folder_path(playbook_id) + '*')
        dst_folder = os.path.join(self.repo_folder, get_folder_path(playbook_id))

        if not self.has_mock_file(playbook_id):
            self.logging_manager.debug('Mock file not created!')
        elif self.get_mock_file_size(src_filepath) == '0':
            self.logging_manager.debug('Mock file is empty, ignoring.')
            self.empty_files.append(playbook_id)
        else:
            # Move to repo folder
            self.logging_manager.debug(f'Moving "{src_files}" files to "{dst_folder}" directory')
            self.ami.call(['mkdir', '--parents', dst_folder])
            self.ami.call(['mv', src_files, dst_folder])

    def clean_mock_file(self, playbook_id, path=None):
        self.logging_manager.debug(f'clean_mock_file was called for test "{playbook_id}"')
        path = path or self.current_folder
        problem_keys_filepath = os.path.join(path, get_folder_path(playbook_id), 'problematic_keys.json')
        self.logging_manager.debug(f'problem_keys_filepath="{problem_keys_filepath}"')
        problem_key_file_exists = ["[", "-f", problem_keys_filepath, "]"]
        if not self.ami.call(problem_key_file_exists) == 0:
            self.logging_manager.debug('Error: The problematic_keys.json file was not written to the file path'
                                       f' "{problem_keys_filepath}" when recording the "{playbook_id}" test playbook')
            return
        problem_keys = json.loads(self.ami.check_output(['cat', problem_keys_filepath]))

        # is there data in problematic_keys.json that needs whitewashing?
        self.logging_manager.debug('checking if there is data to whitewash')
        needs_whitewashing = False
        for val in problem_keys.values():
            if val:
                needs_whitewashing = True
                break

        if problem_keys and needs_whitewashing:
            mock_file_path = os.path.join(path, get_mock_file_path(playbook_id))
            cleaned_mock_filepath = mock_file_path.strip('.mock') + '_cleaned.mock'
            # rewrite mock file with problematic key values replaced
            command = 'mitmdump -ns ~/timestamp_replacer.py '
            log_file = os.path.join(path, get_log_file_path(playbook_id, record=True))
            # Handle proxy log output
            debug_opt = f' | sudo tee -a {log_file}'
            options = f'--set script_mode=clean --set keys_filepath={problem_keys_filepath}'
            if options.strip():
                command += options
            command += ' -r {} -w {}{}'.format(mock_file_path, cleaned_mock_filepath, debug_opt)
            command = "source .bash_profile && {}".format(command)
            self.logging_manager.debug(f'command to clean mockfile:\n\t{command}')
            split_command = command.split()
            self.logging_manager.debug('Let\'s try and clean the mockfile from timestamp data!')
            try:
                check_output(self.ami.add_ssh_prefix(split_command, ssh_options='-t'), stderr=STDOUT)
            except CalledProcessError as e:
                self.logging_manager.debug(
                    'There may have been a problem when filtering timestamp data from the mock file.')
                err_msg = f'command `{command}` exited with return code [{e.returncode}]'
                err_msg = f'{err_msg} and the output of "{e.output}"' if e.output else err_msg
                if e.stderr:
                    err_msg += f'STDERR: {e.stderr}'
                self.logging_manager.debug(err_msg)
            else:
                self.logging_manager.debug('Success!')

            # verify cleaned mock is different than original
            self.logging_manager.debug('verifying cleaned mock file is different than the original mock file')
            diff_cmd = f'diff -sq {cleaned_mock_filepath} {mock_file_path}'
            try:
                diff_cmd_output = self.ami.check_output(diff_cmd.split()).decode().strip()
                self.logging_manager.debug(f'{diff_cmd_output=}')
                if diff_cmd_output.endswith('are identical'):
                    self.logging_manager.debug('cleaned mock file and original mock file are identical')
                else:
                    self.logging_manager.debug('looks like the cleaning process did something!')

            except CalledProcessError:
                self.logging_manager.debug('looks like the cleaning process did something!')

            self.logging_manager.debug('Replace old mock with cleaned one.')
            mv_cmd = f'mv {cleaned_mock_filepath} {mock_file_path}'
            self.ami.call(mv_cmd.split())
        else:
            self.logging_manager.debug('"problematic_keys.json" dictionary values were empty - '
                                       'no data to whitewash from the mock file.')

    def start(self, playbook_id, path=None, record=False):
        """Start the proxy process and direct traffic through it.

        Args:
            playbook_id (string): ID of the test playbook to run.
            path (string): path override for the mock/log files.
            record (bool): Select proxy mode (record/playback)
        """
        if self.is_proxy_listening():
            self.logging_manager.debug('proxy service is already running, stopping it')
            self.ami.call(['sudo', 'systemctl', 'stop', 'mitmdump'])
        self.logging_manager.debug(f'Attempting to start proxy in {self.get_script_mode(record)} mode')
        self.prepare_proxy_start(path, playbook_id, record)
        # Start proxy server
        self._start_proxy_and_wait_until_its_up(is_record=record)

    def _start_proxy_and_wait_until_its_up(self, is_record: bool) -> None:
        """
        Starts mitmdump service and wait for it to listen to port 9997 with timeout of 5 seconds
        Args:
            is_record (bool):  Indicates whether this is a record run or not
        """
        self._start_mitmdump_service()
        was_proxy_up = self.wait_until_proxy_is_listening()
        if was_proxy_up:
            self.logging_manager.debug(f'Proxy service started in {self.get_script_mode(is_record)} mode')
        else:
            self.logging_manager.error(f'Proxy failed to start after {self.TIME_TO_WAIT_FOR_PROXY_SECONDS} seconds')
            self.get_mitmdump_service_status()

    def _start_mitmdump_service(self) -> None:
        """
        Starts mitmdump service on the remote service
        """
        self.ami.call(['sudo', 'systemctl', 'start', 'mitmdump'])

    def get_mitmdump_service_status(self) -> None:
        """
        Safely extract the current mitmdump status and logs it
        """
        try:
            output = self.ami.check_output('systemctl status mitmdump'.split(), stderr=STDOUT)
            self.logging_manager.debug(f'mitmdump service status output:\n{output.decode()}')
        except CalledProcessError as exc:
            self.logging_manager.debug(f'mitmdump service status output:\n{exc.output.decode()}')

    def prepare_proxy_start(self,
                            path: str,
                            playbook_id: str,
                            record: bool) -> bool:
        """
        Writes proxy server run configuration options to the remote host, the details of which include:
        - Creating new tmp directory on remote machine if in record mode and moves the problematic keys file in to it
        - Creating the mitmdump_rc file that includes the script mode, keys file path, mock file path and log file path
          for the mitmdump service and puts it in '/home/ec2-user/mitmdump_rc' in the remote machine.
        - starts the systemd mitmdump service

        Args:
            path: the path to the temp folder in which the record files should be created
            playbook_id: The ID of the playbook that is tested
            record: Indicates whether this is a record run or not
        """
        path = path or self.current_folder
        folder_path = get_folder_path(playbook_id)

        repo_problem_keys_path = os.path.join(self.repo_folder, folder_path, 'problematic_keys.json')
        current_problem_keys_path = os.path.join(path, folder_path, 'problematic_keys.json')
        log_file_path = os.path.join(path, get_log_file_path(playbook_id, record))
        mock_file_path = os.path.join(path, get_mock_file_path(playbook_id))

        file_content = f'export KEYS_FILE_PATH="{current_problem_keys_path if record else repo_problem_keys_path}"\n'
        file_content += f'export SCRIPT_MODE={self.get_script_mode(record)}\n'
        file_content += f'export MOCK_FILE_PATH="{mock_file_path}"\n'
        file_content += f'export LOG_FILE_PATH="{log_file_path}"\n'

        # Create mock files directory
        silence_output(self.ami.call, ['mkdir', os.path.join(path, folder_path)], stderr='null')
        # when recording, copy the `problematic_keys.json` for the test to current temporary directory if it exists
        # that way previously recorded or manually added keys will only be added upon and not wiped with an overwrite
        if record:
            try:
                silence_output(self.ami.call,
                               ['mv', repo_problem_keys_path, current_problem_keys_path],
                               stdout='null')
            except CalledProcessError as e:
                self.logging_manager.debug(f'Failed to move problematic_keys.json with exit code {e.returncode}')

        return self._write_mitmdump_rc_file_to_host(file_content)

    def _write_mitmdump_rc_file_to_host(self,
                                        file_content: str) -> bool:
        """
        Does all needed preparation for starting the proxy service which include:
        - Creating the mitmdump_rc file that includes the script mode, keys file path, mock file path and log file path
          for the mitmdump service and puts it in '/home/ec2-user/mitmdump_rc' in the remote machine.

        Args:
            file_content: The content of the mitmdump_rc file that includes the script mode, keys file path,
            mock file path and log file path

        Returns:
            True if file was successfully copied to the server, else False
        """
        try:
            self.ami.call(['echo', f"'{file_content}'", '>', os.path.join(AMIConnection.REMOTE_HOME, 'mitmdump_rc')])
            return True
        except CalledProcessError:
            self.logging_manager.exception(
                f'Could not copy arg file for mitmdump service to server {self.ami.public_ip},')
        return False

    def wait_until_proxy_is_listening(self):
        """
        Checks if the mitmdump service is listening, and raises an exception if 30 seconds pass without positive answer
        """
        for i in range(self.TIME_TO_WAIT_FOR_PROXY_SECONDS):
            proxy_is_listening = self.is_proxy_listening()
            if proxy_is_listening:
                return True
            time.sleep(1)
        return False

    def is_proxy_listening(self) -> bool:
        """
        Runs 'sudo lsof -iTCP:9997 -sTCP:LISTEN' on the remote machine and returns answer according to the results
        Returns:
            True if the ssh command return exit code 0 and False otherwise
        """
        try:
            self.ami.check_output(['sudo', 'lsof', '-iTCP:9997', '-sTCP:LISTEN'])
            return True
        except CalledProcessError:
            return False

    def stop(self):
        self.logging_manager.debug('Stopping mitmdump service')
        if not self.is_proxy_listening():
            self.logging_manager.debug('proxy service was already down.')
            self.get_mitmdump_service_status()
        else:
            self.ami.call(['sudo', 'systemctl', 'stop', 'mitmdump'])
        self.ami.call(["rm", "-rf", "/tmp/_MEI*"])  # Clean up temp files
