import traceback
from typing import Dict, Any

import requests
from paramiko import SSHClient, AutoAddPolicy
# import paramiko
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''

''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    credentials: Dict = params.get('credentials', {})
    user: Optional[str] = credentials.get('identifier')
    password: Optional[str] = credentials.get('password')

    host_name: str = params.get('hostname', '')

    ciphers: List[str] = argToList(params.get('ciphers'))

    interactive_terminal_mode: bool = argToBoolean(params.get('interactive_terminal_mode', False))
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(hostname=host_name, username=user, password=password, port=22)
        if demisto.command() == 'test-module':
            stdin, stdout, stderr = client.exec_command('ls')
            return_results('ok')
            pass
        elif command == 'ssh':
            stdin, stdout, stderr = client.exec_command(args.get('command', ''))

        else:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
