from __future__ import print_function
import os
import json
import signal
import string
import time
import unicodedata
import urllib3
import demisto_client.demisto_api
from subprocess import call, Popen, PIPE, check_call, check_output, CalledProcessError
from demisto_sdk.commands.common.tools import print_color, print_error, print_warning, \
    LOG_COLORS

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
    REMOTE_HOME = '/home/{}/'.format(REMOTE_MACHINE_USER)
    LOCAL_SCRIPTS_DIR = '/home/circleci/project/Tests/scripts/'
    CLONE_MOCKS_SCRIPT = 'clone_mocks.sh'
    UPLOAD_MOCKS_SCRIPT = 'upload_mocks.sh'
    MOCK_KEY_FILE = 'id_rsa_f5256ae5ac4b84fb60541482f1e96cf9'

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
        remote_key_filepath = self.copy_file(os.path.join('/home/circleci/.ssh/', self.MOCK_KEY_FILE))
        self.run_script(self.CLONE_MOCKS_SCRIPT, remote_key_filepath)


class MITMProxy:
    """Manager for MITM Proxy and the mock file structure.

    Attributes:
        demisto_api_key: API key for demisto API.
        public_ip (string): The IP of the AMI instance.
        repo_folder (string): path to the local clone of the content-test-data git repo.
        tmp_folder (string): path to a temporary folder for log/mock files before pushing to git.
        current_folder (string): the current folder to use for mock/log files.
        ami (AMIConnection): Wrapper for AMI communication.
        process (Popen): object representation of the Proxy process (used to track the proxy process status).
        empty_files (list): List of playbooks that have empty mock files (indicating no usage of mock mechanism).
        rerecorded_tests (list): List of playbook ids that failed on mock playback but succeeded on new recording.
        debug (bool): enable debug prints - redirect.
    """

    PROXY_PORT = '9997'
    MOCKS_TMP_PATH = '/tmp/Mocks/'
    MOCKS_GIT_PATH = 'content-test-data/'

    def __init__(self, public_ip,
                 repo_folder=MOCKS_GIT_PATH, tmp_folder=MOCKS_TMP_PATH, debug=False):
        self.public_ip = public_ip
        self.current_folder = self.repo_folder = repo_folder
        self.tmp_folder = tmp_folder
        self.debug = debug

        self.ami = AMIConnection(self.public_ip)

        self.process = None
        self.empty_files = []
        self.rerecorded_tests = []

        silence_output(self.ami.call, ['mkdir', '-p', tmp_folder], stderr='null')

    def configure_proxy_in_demisto(self, demisto_api_key, server, proxy=''):
        client = demisto_client.configure(base_url=server, api_key=demisto_api_key,
                                          verify_ssl=False)
        http_proxy = https_proxy = proxy
        if proxy:
            http_proxy = 'http://' + proxy
            https_proxy = 'http://' + proxy
        data = {
            'data':
                {
                    'http_proxy': http_proxy,
                    'https_proxy': https_proxy
                },
            'version': -1
        }
        response = demisto_client.generic_request_func(self=client, path='/system/config',
                                                       method='POST', body=data)
        # client.api_client.pool.close()
        return response

    def get_mock_file_size(self, filepath):
        return self.ami.check_output(['stat', '-c', '%s', filepath]).strip()

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

    def move_mock_file_to_repo(self, playbook_id, thread_index=0, prints_manager=None):
        """Move the mock and log files of a (successful) test playbook run from the temp folder to the repo folder

        Args:
            playbook_id (string): ID of the test playbook of which the files should be moved.
            thread_index (int): Index of the relevant thread, to make printing readable.
            prints_manager (ParallelPrintsManager): Prints manager to synchronize parallel prints.
        """
        src_filepath = os.path.join(self.tmp_folder, get_mock_file_path(playbook_id))
        src_files = os.path.join(self.tmp_folder, get_folder_path(playbook_id) + '*')
        dst_folder = os.path.join(self.repo_folder, get_folder_path(playbook_id))

        if not self.has_mock_file(playbook_id):
            prints_manager.add_print_job('Mock file not created!', print, thread_index)
        elif self.get_mock_file_size(src_filepath) == '0':
            prints_manager.add_print_job('Mock file is empty, ignoring.', print, thread_index)
            self.empty_files.append(playbook_id)
        else:
            # Move to repo folder
            self.ami.call(['mkdir', '--parents', dst_folder])
            self.ami.call(['mv', src_files, dst_folder])

    def clean_mock_file(self, playbook_id, path=None, thread_index=0, prints_manager=None):
        prints_manager.add_print_job(f'clean_mock_file was called for test "{playbook_id}"', print, thread_index)
        path = path or self.current_folder
        problem_keys_filepath = os.path.join(path, get_folder_path(playbook_id), 'problematic_keys.json')
        prints_manager.add_print_job(f'problem_keys_filepath="{problem_keys_filepath}"', print, thread_index)
        problem_key_file_exists = ["[", "-f", problem_keys_filepath, "]"]
        if not self.ami.call(problem_key_file_exists) == 0:
            err_msg = 'Error: The problematic_keys.json file was not written to the file path' \
                      ' "{}" when recording the "{}" test playbook'.format(problem_keys_filepath, playbook_id)
            prints_manager.add_print_job(err_msg, print_error, thread_index)
            return
        problem_keys = json.loads(self.ami.check_output(['cat', problem_keys_filepath]))
        prints_manager.add_print_job(
            f'Test "{playbook_id}" problem_keys: \n{json.dumps(problem_keys, indent=4)}',
            print,
            thread_index
        )

        # is there data in problematic_keys.json that needs whitewashing?
        prints_manager.add_print_job('checking if there is data to whitewash', print, thread_index)
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
            debug_opt = f' >>{log_file} 2>&1' if not self.debug else ''
            options = f'--set script_mode=clean --set keys_filepath={problem_keys_filepath}'
            if options.strip():
                command += options
            command += ' -r {} -w {}{}'.format(mock_file_path, cleaned_mock_filepath, debug_opt)
            command = "source .bash_profile && {}".format(command)
            prints_manager.add_print_job(f'command to clean mockfile:\n\t{command}', print, thread_index)
            split_command = command.split()
            prints_manager.add_print_job('Let\'s try and clean the mockfile from timestamp data!', print, thread_index)
            try:
                clean_cmd_output = check_output(self.ami.add_ssh_prefix(split_command, ssh_options='-t'))
                prints_manager.add_print_job(
                    f'clean_cmd_output.decode()={clean_cmd_output.decode()}',
                    print,
                    thread_index
                )
            except CalledProcessError as e:
                cleaning_err_msg = 'There may have been a problem when filtering timestamp data from the mock file.'
                prints_manager.add_print_job(cleaning_err_msg, print_error, thread_index)
                err_msg = f'command `{command}` exited with return code [{e.returncode}]'
                err_msg = f'{err_msg} and the output of "{e.output}"' if e.output else err_msg
                prints_manager.add_print_job(err_msg, print_error, thread_index)
            else:
                prints_manager.add_print_job('Success!', print_color, thread_index, LOG_COLORS.GREEN)

            # verify cleaned mock is different than original
            verify_diff_start_msg = 'verifying cleaned mock file is different than the original mock file'
            prints_manager.add_print_job(verify_diff_start_msg, print, thread_index)
            diff_cmd = 'diff -sq {} {}'.format(cleaned_mock_filepath, mock_file_path)
            try:
                diff_cmd_output = self.ami.check_output(diff_cmd.split()).decode().strip()
                prints_manager.add_print_job(f'diff_cmd_output={diff_cmd_output}', print, thread_index)
                if diff_cmd_output.endswith('are identical'):
                    identical_msg = 'cleaned mock file and original mock file are identical... ' \
                                    'uh oh looks like cleaning didn\'t work properly'
                    prints_manager.add_print_job(identical_msg, print_warning, thread_index)
                else:
                    prints_manager.add_print_job(
                        'looks like the cleaning process did something!',
                        print_color,
                        thread_index,
                        LOG_COLORS.GREEN
                    )

            except CalledProcessError as e:
                err_msg = 'command `{}` exited with return code [{}]'.format(diff_cmd, e.returncode)
                err_msg = '{} and the output of "{}"'.format(err_msg, e.output) if e.output else err_msg
                prints_manager.add_print_job(err_msg, print_error, thread_index)

            prints_manager.add_print_job('Replace old mock with cleaned one.', print, thread_index)
            mv_cmd = 'mv {} {}'.format(cleaned_mock_filepath, mock_file_path)
            self.ami.call(mv_cmd.split())
        else:
            empty_msg = '"problematic_keys.json" dictionary values were empty - ' \
                        'no data to whitewash from the mock file.'
            prints_manager.add_print_job(empty_msg, print, thread_index)

    def start(self, playbook_id, path=None, record=False, thread_index=0, prints_manager=None):
        """Start the proxy process and direct traffic through it.

        Args:
            playbook_id (string): ID of the test playbook to run.
            path (string): path override for the mock/log files.
            record (bool): Select proxy mode (record/playback)
            thread_index (int): Index of the relevant thread, to make printing readable.
            prints_manager (ParallelPrintsManager): Prints manager to synchronize parallel prints.
        """
        if self.process:
            raise Exception("Cannot start proxy - already running.")

        path = path or self.current_folder

        # Create mock files directory
        silence_output(self.ami.call, ['mkdir', os.path.join(path, get_folder_path(playbook_id))], stderr='null')

        repo_problem_keys_filepath = os.path.join(
            self.repo_folder, get_folder_path(playbook_id), 'problematic_keys.json'
        )
        prints_manager.add_print_job(f'repo_problem_keys_filepath={repo_problem_keys_filepath}', print, thread_index)
        current_problem_keys_filepath = os.path.join(path, get_folder_path(playbook_id), 'problematic_keys.json')
        prints_manager.add_print_job(
            f'current_problem_keys_filepath={current_problem_keys_filepath}', print, thread_index
        )

        script_filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'timestamp_replacer.py')
        prints_manager.add_print_job(f'script_filepath={script_filepath}', print, thread_index)
        remote_script_path = self.ami.copy_file(script_filepath)
        prints_manager.add_print_job(f'remote_script_path={remote_script_path}', print, thread_index)

        # if recording
        # record with detect_timestamps and then rewrite mock file
        if record:
            actions = '-s {} '.format(remote_script_path)
            actions += '--set script_mode=record '
            actions += '--set detect_timestamps=true --set keys_filepath={} --save-stream-file'.format(
                current_problem_keys_filepath
            )
        else:
            actions = '-s {} '.format(remote_script_path)
            actions += '--set script_mode=playback '
            actions += '--set keys_filepath={} --server-replay-kill-extra --server-replay'.format(
                repo_problem_keys_filepath
            )

        log_file = os.path.join(path, get_log_file_path(playbook_id, record))
        # Handle proxy log output
        debug_opt = " >{} 2>&1".format(log_file) if not self.debug else ''

        # all mitmproxy/mitmdump commands should have the 'source .bash_profile && ' prefix to ensure the PATH
        # is correct when executing the command over ssh
        # Configure proxy server
        command = "source .bash_profile && mitmdump --ssl-insecure --verbose --listen-port {} {} {}{}".format(
            self.PROXY_PORT, actions, os.path.join(path, get_mock_file_path(playbook_id)), debug_opt
        )
        prints_manager.add_print_job(f'mitm command: "{command}"', print, thread_index)
        command = command.split()

        # Start proxy server
        self.process = Popen(self.ami.add_ssh_prefix(command, "-t"), stdout=PIPE, stderr=PIPE)
        self.process.poll()
        if self.process.returncode is not None:
            raise Exception("Proxy process terminated unexpectedly.\nExit code: {}\noutputs:\nSTDOUT\n{}\n\nSTDERR\n{}"
                            .format(self.process.returncode, self.process.stdout.read(), self.process.stderr.read()))
        log_file_exists = False
        seconds_since_init = 0
        # Make sure process is up and running
        while not log_file_exists and seconds_since_init < PROXY_PROCESS_INIT_TIMEOUT:
            # Check if log file exist
            log_file_exists = silence_output(self.ami.call, ['ls', log_file], stdout='null', stderr='null') == 0
            time.sleep(PROXY_PROCESS_INIT_INTERVAL)
            seconds_since_init += PROXY_PROCESS_INIT_INTERVAL
        if not log_file_exists:
            self.stop()
            raise Exception("Proxy process took to long to go up.")
        proxy_up_message = 'Proxy process up and running. Took {} seconds'.format(seconds_since_init)
        prints_manager.add_print_job(proxy_up_message, print, thread_index)

    def stop(self, thread_index=0, prints_manager=None):
        if not self.process:
            raise Exception("Cannot stop proxy - not running.")

        prints_manager.add_print_job('proxy.stop() was called', print, thread_index)
        self.process.send_signal(signal.SIGINT)  # Terminate proxy process
        self.ami.call(["rm", "-rf", "/tmp/_MEI*"])  # Clean up temp files

        # Handle logs
        if self.debug:
            prints_manager.add_print_job('proxy outputs:', print, thread_index)
            prints_manager.add_print_job(f'{self.process.stdout.read()}', print, thread_index)
            prints_manager.add_print_job(f'{self.process.stderr.read()}', print, thread_index)

        self.process = None
