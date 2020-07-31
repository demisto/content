import demistomock as demisto
import winrm
from CommonServerPython import *


class Client():
    def __init__(self, username, password, auth_type, realm):
        self.username = username
        self.password = password
        self.auth = auth_type
        self.realm = realm if realm else None
        self.hostname = None
        self.runType = None
        self.command = None
        self.script = None
        self.arguments = None
        self.res = None

    def run(self):
        if self.auth == "ntlm":
            winrm_session = winrm.Session(self.hostname, auth=(self.username, self.password), transport=self.auth)
        elif self.auth == "kerberos":
            winrm_session = winrm.Session(self.hostname, auth=(self.username, self.password), transport=self.auth, realm=self.realm)
        if self.runType == 'Process':
            self.res = winrm_session.run_cmd(self.command, self.arguments)
        elif self.runType == 'Script':
            self.res = winrm_session.run_ps(self.script)

    def output(self):
        entry_context = dict()
        if self.runType == 'Process':
            data = {"hostname": self.hostname, "process": self.command, "output": self.res.std_out.decode(
                "utf-8"), "error": self.res.std_err.decode("utf-8"), "status": self.res.status_code}
            entry_context = {'WinRM.Process(val.hostname == obj.hostname && val.process == obj.process)': data}
        elif self.runType == 'Script':
            data = {"hostname": self.hostname, "script": self.command, "output": self.res.std_out.decode(
                "utf-8"), "error": self.res.std_err.decode("utf-8"), "status": self.res.status_code}
            entry_context = {'WinRM.Script(val.hostname && val.hostname == obj.hostname && val.script == obj.script)': data}
        if self.res.status_code == 0:
            this_out = self.res.std_out
        else:
            this_out = self.res.std_err
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': data,
            'ContentsFormat': formats['json'],
            'HumanReadable': this_out.decode("utf-8"),
            'ReadableContentsFormat': formats['text'],
            "EntryContext": entry_context
        })


def test_command(client):
    client.hostname = demisto.params().get('testhost', None)
    if not client.hostname:
        return_error('You must provide a value for Default Host for the test button')
    client.runType = 'Process'
    client.command = 'cd'
    try:
        client.run()
        demisto.results('ok')
    except Exception as err:
        demisto.results(err)


def run_command(client, runType):
    client.hostname = demisto.args().get('hostname')
    client.runType = runType
    if runType == 'Process':
        client.command = demisto.args().get('command')
        client.arguments = demisto.args().get('arguments', None)
    elif runType == 'Script':
        client.script = demisto.args().get('script')
        client.command = demisto.args().get('scriptname', None)
    res = client.run()
    client.output()


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    auth_type = demisto.params().get('authType')
    realm = demisto.params().get('realm')

    try:
        client = Client(username, password, auth_type, realm)

        if demisto.command() == 'test-module':
            test_command(client)

        if demisto.command() == 'winrm-run-process':
            run_command(client, 'Process')

        if demisto.command() == 'winrm-run-powershell':
            run_command(client, 'Script')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__builtin__', 'builtins']:
    main()
