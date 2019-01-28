import os
import signal
import string
import unicodedata
from subprocess import call, Popen, PIPE

MOCK_KEY_FILE = 'id_rsa_f5256ae5ac4b84fb60541482f1e96cf9'
REMOTE_MACHINE_USER = "ec2-user"
VALID_FILENAME_CHARS = "-_.() %s%s" % (string.ascii_letters, string.digits)


def clone_content_test_data(public_ip):
    remote_home = "/home/{}/".format(REMOTE_MACHINE_USER)
    remote_key_filepath = os.path.join(remote_home, MOCK_KEY_FILE)
    call(['scp',
          os.path.join('/home/circleci/.ssh/', MOCK_KEY_FILE),
          "{}@{}:{}".format(REMOTE_MACHINE_USER, public_ip, remote_key_filepath)
          ])
    remote_call(public_ip, ['ssh-agent', '-s'])
    remote_call(public_ip, ['ssh-add', remote_key_filepath])
    remote_call(public_ip, ['git', 'clone', 'git@github.com:demisto/content-test-data.git'])


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
    def __init__(self, demisto_client, public_ip, mocks_folder, debug=False):
        self.demisto_client = demisto_client
        self.ip = public_ip
        self.process = None
        self.mocks_folder = mocks_folder
        self.debug = debug

    def __configure_proxy(self, proxy=""):
        http_proxy = https_proxy = proxy
        if proxy:
            http_proxy = "http://" + proxy
            https_proxy = "https://" + proxy
        data = {"data": {"http_proxy": http_proxy, "https_proxy": https_proxy}, "version": -1}
        return self.demisto_client.req('POST', '/system/config', data)

    def start(self, playbook_id, record=False):
        if self.process:
            raise Exception("Cannot start proxy - already running.")
        action = '--server-replay' if not record else '--save-stream-file'
        command = "mitmdump -p 9997 {}".format(action).split()
        command.append(os.path.join(self.mocks_folder, clean_filename(playbook_id) + ".mock"))
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
