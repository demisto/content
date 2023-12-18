import demistomock as demisto
from CommonServerPython import *


ACCOUNT_LIST_COMMAND = 'aws-org-account-list'


def internal_request(method: str, uri: str, body: dict = {}) -> dict:
    return json.loads(demisto.internalHttpRequest(method, uri, body)['body'])


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


def update_ec2_instance(account_ids: list[str], instance_name: str):
    accounts_as_str = ','.join(account_ids)
    try:
        response = internal_request('POST', '/settings/integration/search')
        demisto.debug(str(response))  # remove
        instance = next(inst for inst in response['instances'] if inst['name'] == instance_name)
        if instance['configvalues']['accounts_to_access'] != accounts_as_str:
            demisto.debug(f'Updating {instance_name!r} with accounts: {accounts_as_str}')
            # instance['version'] += 1
            instance['configvalues']['accounts_to_access'] = accounts_as_str
            response = internal_request('PUT', '/settings/integration', instance)
            return_results(str(response))  # remove
        else:
            demisto.debug(f'Not updating {instance_name!r}. Account list is up to date.')
    except StopIteration:
        raise DemistoException(f'AWS - EC2 instance {instance_name!r} was not found.')
    except Exception as e:
        raise DemistoException(f'Unexpected error while configuring AWS - EC2 instance with accounts {accounts_as_str!r}:\n{e}')


def main():
    try:
        instance_name = str(demisto.getArg('instanceName'))
        account_ids = get_account_ids()
        update_ec2_instance(account_ids, instance_name)
        return_results(f'Successfully updated {instance_name!r} with accounts: {", ".join(account_ids)}')
    except Exception as e:
        return_error(f'Error in AwsEC2GetAccounts: {e}')


if __name__ in ('__main__', 'builtins', '__builtin__'):
    main()
