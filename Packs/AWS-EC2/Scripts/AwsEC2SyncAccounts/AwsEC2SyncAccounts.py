import demistomock as demisto
from CommonServerPython import *


ACCOUNT_LIST_COMMAND = 'aws-org-account-list'
EC2_ACCOUNTS_PARAM = 'accounts_to_access'


def internal_request(method: str, uri: str, body: dict = {}) -> dict:
    """A wrapper for demisto.internalHttpRequest.

    Args:
        method (str): HTTP method such as: GET or POST
        uri (str): Server uri to request. For example: "/contentpacks/marketplace/HelloWorld".
        body (dict, optional): Optional body for a POST request. Defaults to {}.

    Returns:
        dict: The body of request response.
    """
    return json.loads(demisto.internalHttpRequest(method, uri, body)['body'])


def get_account_ids() -> list[str]:
    '''Get the AWS organization accounts using the `aws-org-account-list` command.

    Returns:
            list[str]: A list of AWS account IDs.
    '''
    try:
        account_list_result: list[dict[str, dict]] = demisto.executeCommand(ACCOUNT_LIST_COMMAND, {})  # type: ignore
        return [
            account['Id']
            for account
            in account_list_result[0]['EntryContext']['AWS.Organizations.Account(val.Id && val.Id == obj.Id)']
        ]
    except ValueError as e:
        raise DemistoException(f'The command {ACCOUNT_LIST_COMMAND!r} must be operational to run this script.\nServer error: {e}')
    except KeyError:
        account_list_result = locals().get('account_list_result')  # type: ignore # catch unbound variable error
        raise DemistoException(f'Unexpected output from {ACCOUNT_LIST_COMMAND!r}:\n{account_list_result}')
    except Exception as e:
        raise DemistoException(f'Unexpected error while fetching accounts:\n{e}')


def get_instance(instance_name: str) -> dict:
    '''Get the object of the instance with the name provided.

    Args:
        instance_name (str): The name of the instance to get.

    Returns:
        dict: The instance object.
    '''
    integrations = internal_request('POST', '/settings/integration/search')
    return next(inst for inst in integrations['instances'] if inst['name'] == instance_name)


def set_instance(instance: dict, accounts: str) -> dict:
    '''Set an instance configuration with the accounts.

    Args:
        instance (dict): The instance object to configure.
        accounts (str): The accounts to add to the body.

    Returns:
        dict: The server response from the configuration call.
    '''
    accounts_param: dict = next(param for param in instance['data'] if param['name'] == EC2_ACCOUNTS_PARAM)
    accounts_param.update({
        'hasvalue': True,
        'value': accounts
    })
    return internal_request('PUT', '/settings/integration', instance)


def update_ec2_instance(account_ids: list[str], instance_name: str) -> str:
    '''Update an AWS - EC2 instance with AWS Organization accounts.

    Args:
        account_ids (list[str]): The accounts to configure the instance with.
        instance_name (str): The name of the instance to configure.

    Returns:
        str: A message regarding the outcome of the script run.
    '''
    accounts_as_str = ','.join(account_ids)
    try:
        instance = get_instance(instance_name)
        if instance['configvalues'][EC2_ACCOUNTS_PARAM] == accounts_as_str:
            return f'Account list in {instance_name!r} is up to date.'
        response = set_instance(instance, accounts_as_str)
        if response['configvalues'][EC2_ACCOUNTS_PARAM] != accounts_as_str:
            demisto.debug(f'{response=}')
            raise DemistoException(f'Attempt to update {instance_name!r} with accounts {accounts_as_str} has failed.')
        return f'Successfully updated {instance_name!r} with accounts: {accounts_as_str}'
    except StopIteration:
        raise DemistoException(f'Instance {instance_name!r} was not found or is not an AWS - EC2 instance.')
    except Exception as e:
        raise DemistoException(f'Unexpected error while configuring AWS - EC2 instance with accounts {accounts_as_str!r}:\n{e}')


def main():
    try:
        instance_name = str(demisto.getArg('instanceName'))
        account_ids = get_account_ids()
        result = update_ec2_instance(account_ids, instance_name)
        return_results(result)
    except Exception as e:
        return_error(f'Error in AwsEC2SyncAccounts: {e}')


if __name__ in ('__main__', 'builtins', '__builtin__'):
    main()
