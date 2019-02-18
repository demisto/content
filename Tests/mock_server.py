import os
import signal
import string
import unicodedata
from subprocess import call, Popen, PIPE, check_call, check_output

PROXY_PORT = '9997'
LOCAL_SCRIPTS_DIR = '/home/circleci/project/Tests/scripts/'
CLONE_MOCKS_SCRIPT = 'clone_mocks.sh'
UPLOAD_MOCKS_SCRIPT = 'upload_mocks.sh'
MOCKS_TMP_PATH = '/tmp/Mocks/'
MOCKS_GIT_PATH = 'content-test-data/'
MOCK_KEY_FILE = 'id_rsa_f5256ae5ac4b84fb60541482f1e96cf9'
REMOTE_MACHINE_USER = 'ec2-user'
REMOTE_HOME = '/home/{}/'.format(REMOTE_MACHINE_USER)
VALID_FILENAME_CHARS = '-_.() %s%s' % (string.ascii_letters, string.digits)


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
        output of cmd_method
    """
    with open(os.devnull, 'w') as fnull:
        for k in ('stdout', 'stderr'):
            if kwargs.get(k) == 'null':
                kwargs[k] = fnull

        return cmd_method(*args, **kwargs)


def id_to_mock_file(playbook_id):
    clean = clean_filename(playbook_id)
    return os.path.join(clean + '/', clean + '.mock')


def id_to_log_file(playbook_id, record=False):
    clean = clean_filename(playbook_id)
    suffix = '_record' if record else '_playback'
    return os.path.join(clean + '/', clean + suffix + '.log')


def id_to_folder(playbook_id):
    return clean_filename(playbook_id) + '/'


class AMIConnection:
    """Wrapper for AMI communication.

    Attributes:
        public_ip (string): The public IP of the AMI instance.
        docker_ip (string): The IP of the AMI on the docker bridge (to direct traffic from docker to the AMI).
    """
    def __init__(self, public_ip):
        self.public_ip = public_ip
        self.docker_ip = self.__get_docker_ip()

    def __get_docker_ip(self):
        """Get the IP of the AMI on the docker bridge.
        Used to configure the docker host (AMI machine, in this case) as the proxy server.

        Returns:
            string: The IP of the AMI on the docker bridge.
        """
        out = self.check_output(['/usr/sbin/ip', 'addr', 'show', 'docker0']).split('\n')
        lines_of_words = map(lambda y: y.strip().split(' '), out)  # Split output to lines[words[]]
        address_lines = filter(lambda x: x[0] == 'inet', lines_of_words)  # Take only lines that begin with 'inet'
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
                                                                   REMOTE_MACHINE_USER, self.public_ip).split()
        return prefix + command

    def call(self, command, **kwargs):
        return call(self.add_ssh_prefix(command), **kwargs)

    def check_call(self, command, **kwargs):
        return check_call(self.add_ssh_prefix(command), **kwargs)

    def check_output(self, command, **kwargs):
        return check_output(self.add_ssh_prefix(command), **kwargs)

    def copy_file(self, src, dst=REMOTE_HOME, **kwargs):
        check_call(['scp', '-o', ' StrictHostKeyChecking=no', src,
                    "{}@{}:{}".format(REMOTE_MACHINE_USER, self.public_ip, dst)], **kwargs)
        return os.path.join(dst, os.path.basename(src))

    def run_script(self, script, *args):
        """Copy a script to the AMI and run it.

        Args:
            script (string): Name of the script file in the LOCAL_SCRIPTS_DIR.
            *args: arguments to be passed to the script.
        """
        remote_script_path = self.copy_file(os.path.join(LOCAL_SCRIPTS_DIR, script))
        self.check_call(['chmod', '+x', remote_script_path])
        self.check_call([remote_script_path] + list(args))

    def upload_mock_files(self, build_name, build_number):
        self.run_script(UPLOAD_MOCKS_SCRIPT, build_name, build_number)

    def clone_mock_data(self):
        remote_key_filepath = self.copy_file(os.path.join('/home/circleci/.ssh/', MOCK_KEY_FILE))
        self.run_script(CLONE_MOCKS_SCRIPT, remote_key_filepath)


class MITMProxy:
    """Manager for MITM Proxy and the mock file structure.

    Attributes:
        demisto_client (demisto.DemistoClient): Wrapper for demisto API.
        public_ip (string): The IP of the AMI instance.
        primary_folder (string): path to the local clone of the content-test-data git repo.
        tmp_folder (string): path to a temporary folder for log/mock files before pushing to git.
        active_folder (string): the current folder to use for mock/log files.
        debug (bool): enable debug prints - redirect.
        ami (AMIConnection): Wrapper for AMI communication.
        process (Popen): object representation of the Proxy process (used to track the proxy process status).
        last_playbook_id (string): ID of the currently running / most recently run playbook.
        record (bool): Proxy mode (playback/record).
        empty_files (list): List of playbooks that have empty mock files (indicating no usage of mock mechanism).
    """

    def __init__(self, demisto_client, public_ip,
                 primary_folder=MOCKS_GIT_PATH, tmp_folder=MOCKS_TMP_PATH, debug=False):
        """Initialize.

        Args:
            demisto_client (demisto.DemistoClient): Wrapper for demisto API.
            public_ip (string): The IP of the AMI instance.
            primary_folder (string): path to the local clone of the content-test-data git repo.
            tmp_folder (string): path to a temporary folder for log/mock files before pushing to git.
            debug (bool): enable debug prints - redirect.
        """
        self.demisto_client = demisto_client
        self.public_ip = public_ip
        self.active_folder = self.primary_folder = primary_folder
        self.tmp_folder = tmp_folder
        self.debug = debug

        self.ami = AMIConnection(self.public_ip)

        self.process = None
        self.last_playbook_id = None
        self.record = None
        self.empty_files = []

        silence_output(self.ami.call, ['mkdir', '-p', tmp_folder], stderr='null')

    """Class utility functions"""
    def __configure_proxy_in_demisto(self, proxy=''):
        http_proxy = https_proxy = proxy
        if proxy:
            http_proxy = 'http://' + proxy
            https_proxy = 'https://' + proxy
        data = {
            'data':
                {
                    'http_proxy': http_proxy,
                    'https_proxy': https_proxy
                },
            'version': -1
        }
        return self.demisto_client.req('POST', '/system/config', data)

    """File/Folder management"""
    def has_mock_file(self, playbook_id):
        command = ["[", "-f", os.path.join(self.active_folder, id_to_mock_file(playbook_id)), "]"]
        return self.ami.call(command) == 0

    def has_mock_folder(self, playbook_id):
        command = ["[", "-d", os.path.join(self.active_folder, id_to_folder(playbook_id)), "]"]
        return self.ami.call(command) == 0

    def set_folder_primary(self):
        """Set the primary folder as the active folder (the one used to store mock and log files)."""
        self.active_folder = self.primary_folder

    def set_folder_tmp(self):
        """Set the temp folder as the active folder (the one used to store mock and log files)."""
        self.active_folder = self.tmp_folder

    def move_to_primary(self, playbook_id):
        """Move the mock and log files of a (successful) test playbook run from the temp folder to the primary folder

        Args:
            playbook_id (string): ID of the test playbook of which the files should be moved.
        """
        src_filepath = os.path.join(self.tmp_folder, id_to_mock_file(playbook_id))
        src_files = os.path.join(self.tmp_folder, id_to_folder(playbook_id) + '*')
        dst_folder = os.path.join(self.primary_folder, id_to_folder(playbook_id))

        if not self.has_mock_file(playbook_id):
            print 'Mock file not created!'
        elif self.ami.check_output(['stat', '-c', '%s', src_filepath]).strip() == '0':
            print 'Mock file is empty, ignoring.'
            self.empty_files.append(playbook_id)
        else:
            # Move to primary folder
            self.ami.call(['mkdir', '--parents', dst_folder])
            self.ami.call(['mv', src_files, dst_folder])

    def print_empty_files(self):
        if self.empty_files:
            print "Integrations with empty mock files:\n{}\n".format('\n'.join(self.empty_files))

    def start(self, playbook_id, path=None, record=False):
        """Start the proxy process and direct traffic through it.

        Args:
            playbook_id (string): ID of the test playbook to run.
            path (string): path override for the mock/log files.
            record (bool): Select proxy mode (record/playback)
        """
        if self.process:
            raise Exception("Cannot start proxy - already running.")

        self.last_playbook_id = playbook_id
        self.record = record
        path = path or self.active_folder

        silence_output(self.ami.call, ['mkdir', os.path.join(path, id_to_folder(playbook_id))], stderr='null')

        actions = '--server-replay-kill-extra --server-replay' if not record else '--save-stream-file'
        command = "mitmdump --ssl-insecure --verbose --listen-port {} {}".format(PROXY_PORT, actions).split()
        command.append(os.path.join(path, id_to_mock_file(playbook_id)))

        self.process = Popen(self.ami.add_ssh_prefix(command, "-t"), stdout=PIPE, stderr=PIPE)
        self.__configure_proxy_in_demisto(self.ami.docker_ip + ':' + PROXY_PORT)

    def stop(self):
        if not self.process:
            raise Exception("Cannot stop proxy - not running.")

        self.__configure_proxy_in_demisto('')
        self.process.send_signal(signal.SIGINT)
        self.ami.call(["rm", "-rf", "/tmp/_MEI*"])

        if self.debug:
            print "proxy outputs:"
            print self.process.stdout.read()
            print self.process.stderr.read()
        else:
            local_log_filepath = os.path.join(
                '/tmp', os.path.basename(id_to_log_file(self.last_playbook_id, self.record)))
            remote_log_filepath = os.path.join(self.active_folder, id_to_log_file(self.last_playbook_id, self.record))

            with open(local_log_filepath, 'w+') as log:
                log.write('STDOUT:\n')
                log.write(self.process.stdout.read())
                log.write('\nSTDERR:\n')
                log.write(self.process.stderr.read())

            silence_output(self.ami.copy_file, local_log_filepath, remote_log_filepath, stdout='null')

        self.process = None
