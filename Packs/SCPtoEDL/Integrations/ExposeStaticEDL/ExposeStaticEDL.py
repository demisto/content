import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from bottle import route, run, response
import paramiko
from paramiko import SSHClient
from scp import SCPClient

ThisEDL = ""
file = demisto.params().get('remote_filename')
path = demisto.params().get('remote_path')
remotehost = demisto.params().get('remote_host')
username = demisto.params().get('credentials').get('identifier')
password = demisto.params().get('credentials').get('password')


@route('/')
def index():
    # expose the local stored file
    edl = open(file, 'r')
    ThisEDL = edl.read()
    edl.close()
    response.content_type = 'text/text; charset=UTF8'
    return str(ThisEDL)


def run_long_running(listen_port):
    run(host='0.0.0.0', port=listen_port, debug=True)


def main() -> None:
    # fetch remote file and store
    ssh = SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(str(remotehost), username=username, password=password)

    scp = SCPClient(ssh.get_transport())
    scp.get(path + file)

    listen_port = demisto.params().get('longRunningPort')
    command = demisto.command()

    try:
        if command == 'long-running-execution':
            run_long_running(listen_port)
        elif command == 'test-module':
            pass
        else:
            return_error('Command not found')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
