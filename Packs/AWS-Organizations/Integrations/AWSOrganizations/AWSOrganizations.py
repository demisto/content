from CommonServerPython import *  # noqa: E402
import demistomock as demisto  # noqa: E402
from AWSApiModule import *
from typing import TYPE_CHECKING
from botocore.paginate import Paginator

# The following imports are used only for type hints and autocomplete.
# They are not used at runtime, and are not in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_organizations import *  # noqa
    from mypy_boto3_organizations.type_defs import *  # noqa

''' CONSTANTS '''

SERVICE_NAME = 'organizations'
REGION = 'us-east-1'
MAX_PAGINATION = 20

''' HELPER FUNCTIONS '''


def create_client(args: dict, params: dict) -> 'OrganizationsClient':
    '''Creates the AWS Organizations client and initiates a session.'''

    aws_access_key_id = dict_safe_get(params, ('credentials', 'identifier'))
    aws_secret_access_key = dict_safe_get(params, ('credentials', 'password'))
    aws_default_region = REGION
    aws_role_arn = params.get('role_arn')
    aws_role_session_name = params.get('role_session_name')
    aws_role_session_duration = params.get('role_session_duration')
    aws_role_policy = None

    validate_params(
        aws_default_region,
        aws_role_arn,
        aws_role_session_name,
        aws_access_key_id,
        aws_secret_access_key,
    )

    return AWSClient(
        aws_default_region,
        aws_role_arn,
        aws_role_session_name,
        aws_role_session_duration,
        aws_role_policy,
        aws_access_key_id,
        aws_secret_access_key,
        not params.get('insecure', True),
        params.get('timeout'),
        params.get('retries')
    ).aws_session(
        service=SERVICE_NAME,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )


def paginate(
    paginator: 'Paginator', key_to_pages: str, limit=None, page_size=None, next_token=None, **kwargs
) -> tuple[list, str | None]:
    '''This function exists because AWS doesn't guarantee that the client functions will
    return all results specified in a single call.
    This function also handles the XSOAR pagination conventions such as the limit, page_size and next_token args.
    '''

    max_items = arg_to_number(limit or page_size) or 50
    pagination_max = min(max_items, MAX_PAGINATION)

    iterator = paginator.paginate(
        **kwargs,
        PaginationConfig={
            'MaxItems': pagination_max,
            'PageSize': pagination_max,
            'StartingToken': next_token if not limit else None
        }
    )

    pages: list = []
    next_token = None

    for response in iterator:
        pages.extend(response.get(key_to_pages, []))
        next_token = response.get('NextToken')
        if len(pages) >= max_items:
            break

    del pages[max_items:]
    return pages, next_token


def next_token_output_dict(outputs_prefix: str, next_token: str | None, page_outputs: Any, page_outputs_key: str = 'Id') -> dict:
    """Creates a dict for CommandResults.output with the next token.
    """
    return {
        (f'AWS.Organizations.{outputs_prefix}(val.{page_outputs_key} && val.{page_outputs_key} == obj.{page_outputs_key})'):
            page_outputs,
        'AWS.Organizations(true)': {f'{outputs_prefix}NextToken': next_token},
    }


def dict_values_to_str(d: dict, *keys) -> dict:
    '''Converts values in a dict to strings and returns the dict.
        Used mainly when a client function output contains a datetime.
    '''
    for key in keys:
        if key in d:
            d[key] = str(d[key])
    return d


''' COMMAND FUNCTIONS '''


def test_module(aws_client: 'OrganizationsClient') -> str:
    aws_client.describe_organization()
    return 'ok'


def root_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    roots, next_token = paginate(
        aws_client.get_paginator('list_roots'),
        'Roots',
        limit=args.get('limit'),
        next_token=args.get('next_token'),
        page_size=args.get('page_size'),
    )

    return CommandResults(
        outputs=next_token_output_dict(
            'Root', next_token, roots, 'Id',
        ),
        readable_output=tableToMarkdown(
            'AWS Organization Roots',
            roots, ['Arn', 'Id', 'Name'],
            removeNull=True,
        )
    )


def children_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    children, next_token = paginate(
        aws_client.get_paginator('list_children'),
        'Children',
        limit=args.get('limit'),
        next_token=args.get('next_token'),
        page_size=args.get('page_size'),
        ParentId=args['parent_id'],
        ChildType={  # type: ignore
            'Account': 'ACCOUNT',
            'OrganizationalUnit': 'ORGANIZATIONAL_UNIT',
        }[args['child_type']],
    )

    return CommandResults(
        outputs=next_token_output_dict(
            'Children',
            next_token,
            [
                child | {'ParentId': args['parent_id']}
                for child in children
            ],
            'Id',
        ),
        readable_output=tableToMarkdown(
            f'AWS Account *{args["parent_id"]}* Children',
            children, removeNull=True,
        )
    )


def parent_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    parents, _ = paginate(
        aws_client.get_paginator('list_parents'),
        'Parents',
        limit=1,  # at of the time of this writing, an account can have only one parent
        ChildId=args['child_id']
    )

    return CommandResults(
        outputs_key_field='Id',
        outputs_prefix='AWS.Organizations.Parent',
        outputs=[
            parent | {'ChildId': args['child_id']}
            for parent in parents
        ],
        readable_output=tableToMarkdown(
            f'AWS Account *{args["child_id"]}* Parent',
            parents, removeNull=True,
        )
    )


def organization_unit_get_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    ou = aws_client.describe_organizational_unit(
        OrganizationalUnitId=args['organization_unit_id']
    )

    return CommandResults(
        outputs_key_field='Id',
        outputs_prefix='AWS.Organizations.OrganizationalUnit',
        outputs=ou.get('OrganizationalUnit', {}),
        readable_output=tableToMarkdown(
            'AWS Organization Unit',
            ou.get('OrganizationalUnit', {}),
            removeNull=True,
        )
    )


def account_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    def response_to_readable(accounts) -> str:
        return tableToMarkdown(
            'AWS Organization Accounts',
            accounts,
            [
                'Id', 'Arn', 'Name', 'Email',
                'JoinedMethod', 'JoinedTimestamp', 'Status',
            ],
            removeNull=True
        )

    def account_get() -> CommandResults:

        description = aws_client.describe_account(
            AccountId=args['account_id']
        )

        account = dict_values_to_str(
            description.get('Account', {}),
            'JoinedTimestamp'
        )

        return CommandResults(
            readable_output=response_to_readable(account),
            outputs_key_field='Id',
            outputs_prefix='AWS.Organizations.Account',
            outputs=account,
        )

    def account_list() -> CommandResults:

        accounts, next_token = paginate(
            aws_client.get_paginator('list_accounts'),
            'Accounts',
            limit=args.get('limit'),
            next_token=args.get('next_token'),
            page_size=args.get('page_size'),
        )

        accounts = [
            dict_values_to_str(account, 'JoinedTimestamp')
            for account in accounts
        ]

        return CommandResults(
            outputs=next_token_output_dict(
                'Account', next_token, accounts, 'Id',
            ),
            readable_output=response_to_readable(accounts)
        )

    if args.get('account_id'):
        return account_get()
    else:
        return account_list()


def organization_get_command(aws_client: 'OrganizationsClient') -> CommandResults:

    organization = aws_client.describe_organization()

    return CommandResults(
        outputs=organization.get('Organization', {}),
        outputs_prefix='AWS.Organizations.Organization',
        outputs_key_field='Id',
        readable_output=tableToMarkdown(
            'AWS Organization',
            organization.get('Organization', {}),
            [
                'Id', 'Arn', 'FeatureSet', 'MasterAccountArn',
                'MasterAccountId', 'MasterAccountEmail'
            ],
            removeNull=True
        )
    )


def account_remove_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    aws_client.remove_account_from_organization(
        AccountId=args['account_id']
    )

    return CommandResults(
        readable_output=tableToMarkdown(
            'AWS Account Removed',
            {'AccountId': args['account_id']}
        )
    )


def account_move_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    aws_client.move_account(
        AccountId=args['account_id'],
        SourceParentId=args['source_parent_id'],
        DestinationParentId=args['destination_parent_id'],
    )

    return CommandResults(
        readable_output=tableToMarkdown(
            'AWS Account Moved',
            {'AccountId': args['account_id']}
        )
    )


@polling_function(
    'aws-org-account-create',
    interval=arg_to_number(demisto.getArg('interval_in_seconds')),
    timeout=arg_to_number(demisto.getArg('timeout')),
    poll_message='Creating account:',
    requires_polling_arg=False
)
def account_create_command(args: dict, aws_client: 'OrganizationsClient') -> PollResult:

    def build_tags(keys: str | None, values: str | None) -> list:
        try:
            return [
                {
                    'Key': key,
                    'Value': value
                }
                for key, value in zip(
                    argToList(keys),
                    argToList(values),
                    strict=True
                )
            ]
        except ValueError:
            raise DemistoException('"tag_key" and "tag_value" must have the same length.')

    def initial_call() -> dict:
        account = aws_client.create_account(
            Email=args['email'],
            AccountName=args['account_name'],
            RoleName=args['role_name'],
            IamUserAccessToBilling=args['iam_user_access_to_billing'].upper(),
            Tags=build_tags(
                args.get('tag_key'),
                args.get('tag_value')
            )
        )
        args['request_id'] = account['CreateAccountStatus']['Id']
        return account

    def polling_call() -> dict:
        return aws_client.describe_create_account_status(
            CreateAccountRequestId=args['request_id']
        )

    def create_response(account: dict) -> PollResult:

        result = PollResult(None, continue_to_poll=True)

        match dict_safe_get(account, ['CreateAccountStatus', 'State']):
            case 'SUCCEEDED':
                result.continue_to_poll = False
                result.response = account_list_command(
                    {'account_id': account.get('AccountId')},
                    aws_client
                )
            case 'FAILED':
                pass

        return result

    if not args.get('request_id'):
        account = initial_call()
    else:
        account = polling_call()

    return create_response(account)


@polling_function(
    'aws-org-account-close',
    interval=arg_to_number(demisto.getArg('interval_in_seconds')),
    timeout=arg_to_number(demisto.getArg('timeout')),
    poll_message='Closing account:',
    requires_polling_arg=False
)
def account_close_command(args: dict, aws_client: 'OrganizationsClient') -> PollResult:

    if not args['is_closed']:
        aws_client.close_account(
            AccountId=args['account_id']
        )
        args['is_closed'] = True

    account = aws_client.describe_account(
        AccountId=args['account_id']
    )
    return PollResult(
        response=CommandResults(
            readable_output=tableToMarkdown(
                'Account closed',
                {'AccountId': args['account_id']}
            )
        ),
        continue_to_poll=(dict_safe_get(account, ['Account', 'Status']) != 'SUSPENDED'),
    )


''' MAIN FUNCTION '''


def main():

    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    aws_client = create_client(args, params)

    demisto.debug(f'Command being called is {command}')

    try:
        if command == 'test-module':
            return_results(test_module(aws_client))
        elif command == 'aws-org-root-list':
            return_results(root_list_command(args, aws_client))
        elif command == 'aws-org-children-list':
            return_results(children_list_command(args, aws_client))
        elif command == 'aws-org-parent-list':
            return_results(parent_list_command(args, aws_client))
        elif command == 'aws-org-organization-unit-get':
            return_results(organization_unit_get_command(args, aws_client))
        elif command == 'aws-org-account-list':
            return_results(account_list_command(args, aws_client))
        elif command == 'aws-org-organization-get':
            return_results(organization_get_command(aws_client))
        elif command == 'aws-org-account-remove':
            return_results(account_remove_command(args, aws_client))
        elif command == 'aws-org-account-move':
            return_results(account_move_command(args, aws_client))
        elif command == 'aws-org-account-create':
            return_results(account_create_command(args, aws_client))
        elif command == 'aws-org-account-close':
            return_results(account_close_command(args, aws_client))
        else:
            raise NotImplementedError(f'AWS-Organizations error: command {command!r} is not implemented')

    except Exception as error:
        demisto.debug(f'{error.args=}')
        return_error(f'Failed to execute {command!r}.\n{error}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
