import os
import signal
import string
import unicodedata
from subprocess import call, Popen, PIPE

CLONE_MOCKS_SCRIPT = 'clone_mocks.sh'
MOCKS_TMP_PATH = "/tmp/Mocks/"
MOCKS_GIT_PATH = "content-test-data/Mocks/"
MOCK_KEY_FILE = 'id_rsa_f5256ae5ac4b84fb60541482f1e96cf9'
REMOTE_MACHINE_USER = "ec2-user"
VALID_FILENAME_CHARS = "-_.() %s%s" % (string.ascii_letters, string.digits)


def clone_content_test_data(public_ip):
    remote_home = "/home/{}/".format(REMOTE_MACHINE_USER)
    remote_key_filepath = os.path.join(remote_home, MOCK_KEY_FILE)
    call(['scp', '-o', ' StrictHostKeyChecking=no',
          os.path.join('/home/circleci/.ssh/', MOCK_KEY_FILE),
          "{}@{}:{}".format(REMOTE_MACHINE_USER, public_ip, remote_key_filepath)
          ])
    call(['scp', '-o', ' StrictHostKeyChecking=no',
          os.path.join('Tests/scripts/', CLONE_MOCKS_SCRIPT),
          "{}@{}:{}".format(REMOTE_MACHINE_USER, public_ip, remote_home)
          ])

    remote_call(public_ip, ['chmod', '+x', CLONE_MOCKS_SCRIPT])
    remote_call(public_ip, ['./' + CLONE_MOCKS_SCRIPT, remote_key_filepath])


def upload_mock_files(public_ip, build_name, build_number):
    remote_call(public_ip, ['git', 'add', 'Mocks/*.mock'])
    commit_message = "Updated mock files from content build {} - {}".format(build_name, build_number)
    remote_call(public_ip, ['git', 'commit', '-m', commit_message])
    remote_call(public_ip, ['git', 'push'])


def clean_filename(filename, whitelist=VALID_FILENAME_CHARS, replace=' '):
    # replace spaces
    for r in replace:
        filename = filename.replace(r, '_')

    # keep only valid ascii chars
    cleaned_filename = unicodedata.normalize('NFKD', filename).encode('ASCII', 'ignore').decode()

    # keep only whitelisted chars
    cleaned_filename = ''.join(c for c in cleaned_filename if c in whitelist)
    return cleaned_filename


def add_ssh_prefix(public_ip, command, ssh_options=""):
    if ssh_options and not isinstance(ssh_options, str):
        raise TypeError("options must be string")
    if not isinstance(command, list):
        raise TypeError("command must be list")
    full_command = "ssh {} -o StrictHostKeyChecking=no {}@{}".format(ssh_options,
                                                                     REMOTE_MACHINE_USER, public_ip).split()
    full_command.extend(command)
    return full_command


def remote_call(public_ip, command):
    return call(add_ssh_prefix(public_ip, command))


class MITMProxy:
    def __init__(self, demisto_client, public_ip,
                 primary_folder=MOCKS_GIT_PATH, tmp_folder=MOCKS_TMP_PATH, debug=False):
        self.demisto_client = demisto_client
        self.ip = public_ip
        self.process = None
        self.active_folder = self.primary_folder = primary_folder
        self.tmp_folder = tmp_folder
        self.debug = debug

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
        remote_call(self.ip, ['mv', os.path.join(self.tmp_folder, playbook_id + '.mock'), self.primary_folder])

    def start(self, playbook_id, path=None, record=False):
        if self.process:
            raise Exception("Cannot start proxy - already running.")

        path = path or self.active_folder
        action = '--server-replay' if not record else '--save-stream-file'
        command = "mitmdump -p 9997 {}".format(action).split()
        command.append(os.path.join(path, clean_filename(playbook_id) + ".mock"))

        self.process = Popen(add_ssh_prefix(self.ip, command, "-t"), stdout=PIPE, stderr=PIPE)
        self.__configure_proxy('localhost:9997')

    def stop(self):
        if not self.process:
            raise Exception("Cannot start proxy - already running.")

        self.__configure_proxy('')
        self.process.send_signal(signal.SIGINT)
        call(add_ssh_prefix(self.ip, ["rm", "-rf", "/tmp/_MEI*"]))
        if self.debug:
            print "proxy outputs:"
            print self.process.stdout.read()
            print self.process.stderr.read()
        self.process = None
