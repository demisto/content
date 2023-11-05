from CommonServerPython import *  # noqa: E402
import demistomock as demisto  # noqa: E402
from AWSApiModule import *
from typing import TYPE_CHECKING

# The following imports are used only for type hints and autocomplete.
# They are not used at runtime, and are not in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_organizations import *
    from botocore.paginate import Paginator

''' CONSTANTS '''

SERVICE_NAME = 'organizations'
REGION = 'us-east-1'
MAX_PAGINATION = 20

''' HELPER FUNCTIONS '''


def create_client_session(args: dict, params: dict) -> 'OrganizationsClient':

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
        'AWS.Organizations(true)': {f'{outputs_prefix}NextToken': next_token},
        (f'AWS.Organizations.{outputs_prefix}(val.{page_outputs_key} && val.{page_outputs_key} == obj.{page_outputs_key})'):
            page_outputs,
    }


''' COMMAND FUNCTIONS '''


def test_module(aws_client: 'OrganizationsClient') -> str:
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
            'AWS Organizations Roots',
            ['Arn', 'Id', 'Name'],
            roots, removeNull=True,
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
        limit=1,
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
            f'AWS Account *{args["child_id"]}* Parents',
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
        outputs=ou['OrganizationalUnit'],
        readable_output=tableToMarkdown(
            'AWS Organizations Unit',
            ou['OrganizationalUnit'],
            removeNull=True,
        )
    )


def account_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    
    def JoinedTimestamp_to_str(account):
        account['JoinedTimestamp'] = str(account['JoinedTimestamp'])

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

        account = description.get('Account', {})
        JoinedTimestamp_to_str(account)

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

        accounts = list(map(JoinedTimestamp_to_str, accounts))

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
        outputs=organization['Organization'],
        outputs_prefix='AWS.Organizations.Organization',
        outputs_key_field='Id',
        readable_output=tableToMarkdown(
            'AWS Organization',
            organization['Organization'],
            [
                'Id', 'Arn', 'FeatureSet', 'MasterAccountArn',
                'MasterAccountId', 'MasterAccountEmail'
            ],
            removeNull=True
        )
    )


''' MAIN FUNCTION '''


def main():

    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    aws_client = create_client_session(args, params)

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
        else:
            raise NotImplementedError(f'AWS-Organizations error: command {command!r} is not implemented')

    except Exception as error:
        demisto.debug(f'{error.args=}')
        return_error(f'Failed to execute {command!r}.\n{error}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
