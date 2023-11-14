import demistomock as demisto
from CommonServerPython import *


ACCOUNT_LIST_COMMAND = 'aws-org-account-list'


def get_account_ids() -> list[str]:
    try:
        account_list_result = demisto.executeCommand(ACCOUNT_LIST_COMMAND, {})
        return [
            account.get('Id', '')
            for account in dict_safe_get(
                account_list_result,
                [0, 'EntryContext', 'AWS.Organizations.Account(val.Id && val.Id == obj.Id)'],
                default_return_value=[],
                return_type=list,
            )
        ]
    except ValueError as e:
        demisto.debug(str(e))
        raise DemistoException(f'The command {ACCOUNT_LIST_COMMAND!r} must be operational to run this script.')


def main():
    try:
        accounts = get_account_ids()
        demisto.internalHttpRequest('PUT', 'uri', {})
    except Exception as e:
        return_error(f'Error in AwsEC2GetAccounts: {e}')


if __name__ in ('__main__', 'builtins', '__builtin__'):
    main()
