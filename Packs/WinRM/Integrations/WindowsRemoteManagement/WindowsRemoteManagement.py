import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import winrm
from winrm import Session

''' Helper functions '''


class Client:
    def __init__(self, username, password, auth_type, realm, default_host, decode):
        self.username = username
        self.password = password
        self.auth = auth_type
        self.realm = realm if realm else None
        self.hostname = default_host
        self.decode = decode
        self.runType = None
        self.command = None
        self.script = None
        self.arguments = None
        self.res = None

    def run(self):
        s: Session
        if self.auth == "ntlm":
            s = winrm.Session(
                target=self.hostname,
                auth=(self.username, self.password),
                transport=self.auth
            )
        else:  # self.auth == "kerberos":
            demisto.debug(f"{self.auth=}. Should be kerberos")
            s = winrm.Session(
                target=self.hostname,
                auth=(self.username, self.password),
                transport=self.auth,
                realm=self.realm
            )

        if self.runType == 'Process':
            self.res = s.run_cmd(self.command, self.arguments)  # type: ignore[arg-type]

        elif self.runType == 'Script':
            self.res = s.run_ps(self.script)  # type: ignore[arg-type]

    def output(self):
        entry_context = None
        if self.res is None:
            raise ValueError('Failed to get the response from the executed command.')

        if self.runType == 'Process':
            data = {
                "hostname": self.hostname,
                "process": self.command,
                "output": self.res.std_out.decode(self.decode) if self.res.std_out else None,
                "error": self.res.std_err.decode(self.decode) if self.res.std_err else None,
                "status": self.res.status_code
            }
            entry_context = {
                'WinRM.Process(val.hostname == obj.hostname && val.process == obj.process)': data
            }
        elif self.runType == 'Script':
            data = {
                "hostname": self.hostname,
                "script": self.command,
                "output": self.res.std_out.decode(self.decode) if self.res.std_out else None,
                "error": self.res.std_err.decode(self.decode) if self.res.std_err else None,
                "status": self.res.status_code
            }
            entry_context = {
                'WinRM.Script(val.hostname && val.hostname == obj.hostname && val.script == obj.script)': data
            }

        if self.res.status_code == 0:
            this_out = self.res.std_out
        else:
            this_out = self.res.std_err

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': data,
            'ContentsFormat': formats['json'],
            'HumanReadable': this_out.decode(encoding=self.decode),
            'ReadableContentsFormat': formats['text'],
            "EntryContext": entry_context
        })


def test_command(client):
    client.hostname = demisto.params().get('default_host', None)
    if not client.hostname:
        return_error('You must provide a value for Default Host for the test button')
    client.runType = 'Process'
    client.command = 'cd'
    try:
        client.run()
        demisto.results('ok')
    except Exception as err:
        demisto.results(err)


def run_command(client, run_type):
    args = demisto.args()
    client.hostname = args.get('hostname', client.hostname)
    client.decode = args.get('decode', client.decode)
    client.runType = run_type
    if run_type == 'Process':
        client.command = args.get('command')
        client.arguments = args.get('arguments', None)
    elif run_type == 'Script':
        entry_id = args.get('entryID', None)
        if entry_id:
            file_path = demisto.getFilePath(entry_id)
            client.command = file_path['name']
            data = open(file_path['path']).read()
            client.script = data
        else:
            client.script = args.get('script', None)
            client.command = args.get('scriptname', None)
        if not client.script and not client.command:
            return_error("You must provide an entryID or script and script name")
    client.run()
    client.output()


def main():
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    auth_type = params.get('auth_type')
    realm = demisto.params().get('realm')
    default_host = params.get('default_host')
    decode = params.get('decode', 'utf_8')

    try:
        client = Client(username, password, auth_type, realm, default_host, decode)

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
