import demistomock as demisto
from CommonServerPython import *


ACCOUNT_LIST_COMMAND = 'aws-org-account-list'


def get_account_ids() -> list[str]:
    try:
        account_list_result = demisto.executeCommand(ACCOUNT_LIST_COMMAND, {})
        return [
            account['Id']
            for account in dict_safe_get(
                account_list_result,
                [0, 'EntryContext', 'AWS.Organizations.Account(val.Id && val.Id == obj.Id)'],
            ) or []
        ]
    except ValueError:
        raise DemistoException(f'The command {ACCOUNT_LIST_COMMAND!r} must be operational to run this script.')
    except KeyError:
        account_list_result = locals().get('account_list_result')  # catch unbound variable error
        raise DemistoException(f'Unexpected output from {ACCOUNT_LIST_COMMAND!r}:\n{account_list_result}')
    except Exception as e:
        raise DemistoException(f'Unexpected error while fetching accounts:\n{e}')


def configure_ec2_instance(account_ids: list[str]):
    accounts_as_str = ','.join(account_ids)
    try:
        demisto.internalHttpRequest('PUT', 'uri', {})
    except Exception as e:
        raise DemistoException(f'Unexpected error while configuring AWS - EC2 instance with accounts {accounts_as_str!r}:\n{e}')


def main():
    try:
        account_ids = get_account_ids()
        configure_ec2_instance(account_ids)
    except Exception as e:
        return_error(f'Error in AwsEC2GetAccounts: {e}')


if __name__ in ('__main__', 'builtins', '__builtin__'):
    main()
