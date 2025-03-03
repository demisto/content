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
    return demisto.executeCommand(
        f'core-api-{method.lower()}',
        {'uri': uri, 'body': json.dumps(body)}
    )[0]['Contents']['response']  # type: ignore


def get_account_ids(ec2_instance_name: str | None, limit: int | None) -> tuple[list[str], str]:
    '''Get the AWS organization accounts using the `aws-org-account-list` command.

    Returns:
        list[str]: A list of AWS account IDs.
    '''
    try:
        command_args = assign_params(limit=limit, using=ec2_instance_name)
        account_list_result: list[dict] = demisto.executeCommand(ACCOUNT_LIST_COMMAND, command_args)  # type: ignore
        accounts = dict_safe_get(
            account_list_result, (0, 'EntryContext', 'AWS.Organizations.Account(val.Id && val.Id == obj.Id)'), []
        )
        return [account['Id'] for account in accounts], str(dict_safe_get(account_list_result, (0, 'HumanReadable'), ''))
    except ValueError as e:
        raise DemistoException(f'The command {ACCOUNT_LIST_COMMAND!r} must be operational to run this script.\nServer error: {e}')
    except StopIteration:
        raise DemistoException(f'AWS - Organizations instance {ec2_instance_name!r} was not found.')
    except (KeyError, TypeError):
        account_list_result = locals().get('account_list_result')  # type: ignore # catch unbound variable error
        raise DemistoException(f'Unexpected output from {ACCOUNT_LIST_COMMAND!r}:\n{account_list_result}')
    except Exception as e:
        raise DemistoException(f'Unexpected error while fetching accounts:\n{e}')


def get_instance(ec2_instance_name: str) -> dict:
    '''Get the object of the instance with the name provided.

    Args:
        instance_name (str): The name of the instance to get.

    Returns:
        dict: The instance object.
    '''
    integrations = internal_request('post', '/settings/integration/search')
    return next(inst for inst in integrations['instances'] if inst['name'] == ec2_instance_name)


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
    return internal_request('put', '/settings/integration', instance)


def remove_excluded_accounts(account_ids: list, accounts_to_exclude: str | None) -> list[str]:
    return (
        list(set(account_ids) - set(argToList(accounts_to_exclude)))
        if accounts_to_exclude
        else account_ids
    )


def update_ec2_instance(account_ids: list[str], ec2_instance_name: str) -> str:
    '''Update an AWS - EC2 instance with AWS Organization accounts.

    Args:
        account_ids (list[str]): The accounts to configure the instance with.
        instance_name (str): The name of the instance to configure.

    Returns:
        str: A message regarding the outcome of the script run.
    '''
    accounts_as_str = ','.join(account_ids)
    try:
        instance = get_instance(ec2_instance_name)
        if instance['configvalues'][EC2_ACCOUNTS_PARAM] == accounts_as_str:
            return f'Account list in ***{ec2_instance_name}*** is up to date.'
        response = set_instance(instance, accounts_as_str)
        if response['configvalues'][EC2_ACCOUNTS_PARAM] != accounts_as_str:
            demisto.debug(f'{response=}')
            raise DemistoException(f'Attempt to update {ec2_instance_name!r} with accounts {accounts_as_str} has failed.')
        return f'Successfully updated ***{ec2_instance_name}*** with accounts:'
    except StopIteration:
        raise DemistoException(f'AWS - EC2 instance {ec2_instance_name!r} was not found or is not an AWS - EC2 instance.')
    except (TypeError, KeyError) as e:
        raise DemistoException(f'Please make sure a "Core REST API" instance is enabled.\nError: {e}')
    except Exception as e:
        raise DemistoException(f'Unexpected error while configuring AWS - EC2 instance with accounts {accounts_as_str!r}:\n{e}')


def main():
    try:
        args: dict = demisto.args()
        account_ids, readable_output = get_account_ids(
            args.get('org_instance_name'), arg_to_number(args.get('max_accounts')))
        account_ids = remove_excluded_accounts(account_ids, args.get('exclude_accounts'))
        result = update_ec2_instance(account_ids, args['ec2_instance_name'])
        return_results(CommandResults(readable_output=f'## {result}  \n---  \n{readable_output}'))
    except Exception as e:
        return_error(f'Error in AwsEC2SyncAccounts: {e}')


if __name__ in ('__main__', 'builtins', '__builtin__'):
    main()
