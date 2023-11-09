import demistomock as demisto
from CommonServerPython import *


ACCOUNT_LIST_COMMAND = 'aws-org-account-list'


def get_accounts():
    if ACCOUNT_LIST_COMMAND in demisto.getAllSupportedCommands():  # is dict; check if needed
        demisto.executeCommand(ACCOUNT_LIST_COMMAND, {})
    else:
        raise DemistoException(f'The command {ACCOUNT_LIST_COMMAND!r} must be operational to run this script.')

def main():
    try:
        demisto.internalHttpRequest('PUT', 'uri', {})
    except Exception as e:
        return_error(f'Error in AwsEC2GetAccounts: {e}')


if __name__ in ('__main__', 'builtins', '__builtin__'):
    main()
