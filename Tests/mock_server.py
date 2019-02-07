import os
import signal
import string
import unicodedata
from subprocess import call, Popen, PIPE, check_call, check_output

LOCAL_SCRIPTS_DIR = '/home/circleci/project/Tests/scripts/'
CLONE_MOCKS_SCRIPT = 'clone_mocks.sh'
UPLOAD_MOCKS_SCRIPT = 'upload_mocks.sh'
MOCKS_TMP_PATH = "/tmp/Mocks/"
MOCKS_GIT_PATH = "content-test-data/"
MOCK_KEY_FILE = 'id_rsa_f5256ae5ac4b84fb60541482f1e96cf9'
REMOTE_MACHINE_USER = "ec2-user"
VALID_FILENAME_CHARS = "-_.() %s%s" % (string.ascii_letters, string.digits)

REMOTE_HOME = "/home/{}/".format(REMOTE_MACHINE_USER)


def clean_filename(playbook_id, whitelist=VALID_FILENAME_CHARS, replace=' '):
    filename = playbook_id

    # replace spaces
    for r in replace:
        filename = filename.replace(r, '_')

    # keep only valid ascii chars
    cleaned_filename = unicodedata.normalize('NFKD', filename).encode('ASCII', 'ignore').decode()

    # keep only whitelisted chars
    cleaned_filename = ''.join(c for c in cleaned_filename if c in whitelist)
    return cleaned_filename + '.mock'


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
    def __init__(self, public_ip):
        self.ip = public_ip

    def add_ssh_prefix(self, command, ssh_options=""):
        if ssh_options and not isinstance(ssh_options, str):
            raise TypeError("options must be string")
        if not isinstance(command, list):
            raise TypeError("command must be list")
        prefix = "ssh {} -o StrictHostKeyChecking=no {}@{}".format(ssh_options,
                                                                   REMOTE_MACHINE_USER, self.ip).split()
        return prefix + command

    def call(self, command, **kwargs):
        return call(self.add_ssh_prefix(command), **kwargs)

    def check_call(self, command):
        return check_call(self.add_ssh_prefix(command))

    def check_output(self, command):
        return check_output(self.add_ssh_prefix(command))

    def copy_file(self, src, dst=REMOTE_HOME):
        check_call(['scp', '-o', ' StrictHostKeyChecking=no', src,
                    "{}@{}:{}".format(REMOTE_MACHINE_USER, self.ip, dst)])
        return os.path.join(dst, os.path.basename(src))

    def run_script(self, script, *args):
        remote_script_path = self.copy_file(os.path.join(LOCAL_SCRIPTS_DIR, script))
        self.check_call(['chmod', '+x', remote_script_path])
        self.check_call([remote_script_path] + list(args))

    def upload_mock_files(self, build_name, build_number):
        self.run_script(UPLOAD_MOCKS_SCRIPT, build_name, build_number)

    def clone_mock_data(self):
        remote_key_filepath = self.copy_file(os.path.join('/home/circleci/.ssh/', MOCK_KEY_FILE))
        self.run_script(CLONE_MOCKS_SCRIPT, remote_key_filepath)

    def get_docker_ip(self):
        out = self.check_output(['/usr/sbin/ip', 'addr', 'show', 'docker0']).split('\n')
        lines_of_words = map(lambda y: y.strip().split(' '), out)
        address_lines = filter(lambda x: x[0] == 'inet', lines_of_words)
        if len(address_lines) != 1:
            raise Exception("docker bridge interface has {} ipv4 addresses, should only have one."
                            .format(len(address_lines)))
        return address_lines[0][1].split('/')[0]


class MITMProxy:
    def __init__(self, demisto_client, public_ip,
                 primary_folder=MOCKS_GIT_PATH, tmp_folder=MOCKS_TMP_PATH, debug=False):
        self.demisto_client = demisto_client
        self.public_ip = public_ip
        self.ami = AMIConnection(self.public_ip)
        self.docker_ip = self.ami.get_docker_ip()
        self.process = None
        self.last_playbook_id = None
        self.record = None
        self.active_folder = self.primary_folder = primary_folder
        self.tmp_folder = tmp_folder
        self.debug = debug
        self.empty_files = []

        with open(os.devnull, 'w') as fnull:
            self.ami.call(['mkdir', '-p', tmp_folder], stderr=fnull)

    def __configure_proxy(self, proxy=""):
        http_proxy = https_proxy = proxy
        if proxy:
            http_proxy = "http://" + proxy
            https_proxy = "https://" + proxy
        data = {"data": {"http_proxy": http_proxy, "https_proxy": https_proxy}, "version": -1}
        return self.demisto_client.req('POST', '/system/config', data)

    def set_folder_primary(self):
        self.active_folder = self.primary_folder

    def set_folder_tmp(self):
        self.active_folder = self.tmp_folder

    def move_to_primary(self, playbook_id):
        src_filepath = os.path.join(self.tmp_folder, id_to_mock_file(playbook_id))
        src_files = os.path.join(self.tmp_folder, id_to_folder(playbook_id) + '*')
        dst_folder = os.path.join(self.primary_folder, id_to_folder(playbook_id))

        if self.ami.check_output(['stat', '-c', '%s', src_filepath]).strip() == 0:
            print 'Mock file is empty, ignoring.'
            self.empty_files.append(playbook_id)
        else:
            self.ami.call(['mkdir', '--parents', dst_folder])
            self.ami.call(['mv', src_files, dst_folder])

    def print_empty_files(self):
        if self.empty_files:
            print "Integrations with empty mock files:\n{}".format('\n'.join(self.empty_files))

    def start(self, playbook_id, path=None, record=False):
        if self.process:
            raise Exception("Cannot start proxy - already running.")

        self.last_playbook_id = playbook_id
        self.record = record

        path = path or self.active_folder
        actions = '--server-replay-kill-extra -S' if not record else '-w'
        command = "mitmdump -k -v -p 9997 {}".format(actions).split()
        command.append(os.path.join(path, id_to_mock_file(playbook_id)))

        self.process = Popen(self.ami.add_ssh_prefix(command, "-t"), stdout=PIPE, stderr=PIPE)
        self.__configure_proxy(self.docker_ip + ':9997')

    def stop(self):
        if not self.process:
            raise Exception("Cannot start proxy - already running.")

        self.__configure_proxy('')
        self.process.send_signal(signal.SIGINT)
        self.ami.call(["rm", "-rf", "/tmp/_MEI*"])

        if self.debug:
            print "proxy outputs:"
            print self.process.stdout.read()
            print self.process.stderr.read()
        else:
            log_filepath = os.path.join(self.primary_folder, id_to_log_file(self.last_playbook_id, self.record))
            with open(log_filepath, 'wb') as log:
                log.write('STDOUT:\n')
                log.write(self.process.stdout.read())
                log.write('\nSTDERR:\n')
                log.write(self.process.stdout.read())

        self.process = None
