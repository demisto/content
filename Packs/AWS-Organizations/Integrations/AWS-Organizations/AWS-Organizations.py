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

    iterator = paginator.paginate(
        **kwargs,
        PaginationConfig={
            'MaxItems': min(max_items, 20),  # TODO verify and make into constant.
            'PageSize': min(max_items, 20),
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
    """Creates a CommandResults object with the next token as the output.
    """
    return {
        f'AWS.Organizations(val.{outputs_prefix}NextToken || true)': {f'{outputs_prefix}NextToken': next_token},
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

    for root in roots:
        del root['PolicyTypes']

    return CommandResults(
        outputs=next_token_output_dict(
            'Root', next_token, roots, 'Id',
        ),
        readable_output=tableToMarkdown(
            'AWS Organizations Roots',
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

    def response_to_readable(account) -> str:
        return tableToMarkdown(
            'AWS Organization Accounts',
            accounts,
            [
                'Id', 'Arn', 'Name', 'Email',
                'JoinedMethod', 'JoinedTimestamp', 'Status',
            ],
            removeNull=True,
        )

    if (account_id := args.get('account_id')):
        account = aws_client.describe_account(
            AccountId=account_id
        )['Account']

        JoinedTimestamp_to_str(account)

        return CommandResults(
            outputs_key_field='Id',
            outputs_prefix='AWS.Organizations.Account',
            outputs=account,
            readable_output=response_to_readable(account)
        )

    else:
        accounts, next_token = paginate(
            aws_client.get_paginator('list_accounts'),
            'Accounts',
            limit=args.get('limit'),
            next_token=args.get('next_token'),
            page_size=args.get('page_size'),
        )

        for account in accounts:
            JoinedTimestamp_to_str(account)

        return CommandResults(
            outputs=next_token_output_dict(
                'Account', next_token, accounts, 'Id',
            ),
            readable_output=response_to_readable(accounts)
        )


def organization_get_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def account_remove_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def account_move_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def account_create_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def account_close_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def organization_unit_create_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def organization_unit_delete_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def organization_unit_rename_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def policy_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def target_policy_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def policy_get_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def policy_delete_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def policy_attach_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def policy_target_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def resource_tag_add_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


def resource_tag_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:
    ...


''' MAIN FUNCTION '''


def main():

    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    aws_client = create_client_session(args, params)

    demisto.debug(f'Command being called is {command}')

    try:
        match command:
            case 'test-module':
                return_results(test_module(aws_client))
            case 'aws-org-root-list':
                return_results(root_list_command(args, aws_client))
            case 'aws-org-children-list':
                return_results(children_list_command(args, aws_client))
            case 'aws-org-parent-list':
                return_results(parent_list_command(args, aws_client))
            case 'aws-org-organization-unit-get':
                return_results(organization_unit_get_command(args, aws_client))
            case 'aws-org-account-list':
                return_results(account_list_command(args, aws_client))
            case 'aws-org-organization-get':
                return_results(organization_get_command(args, aws_client))
            case 'aws-org-account-remove':
                return_results(account_remove_command(args, aws_client))
            case 'aws-org-account-move':
                return_results(account_move_command(args, aws_client))
            case 'aws-org-account-create':
                return_results(account_create_command(args, aws_client))
            case 'aws-org-account-close':
                return_results(account_close_command(args, aws_client))
            case 'aws-org-organization-unit-create':
                return_results(organization_unit_create_command(args, aws_client))
            case 'aws-org-organization-unit-delete':
                return_results(organization_unit_delete_command(args, aws_client))
            case 'aws-org-organization-unit-rename':
                return_results(organization_unit_rename_command(args, aws_client))
            case 'aws-org-policy-list':
                return_results(policy_list_command(args, aws_client))
            case 'aws-org-target-policy-list':
                return_results(target_policy_list_command(args, aws_client))
            case 'aws-org-policy-get':
                return_results(policy_get_command(args, aws_client))
            case 'aws-org-policy-delete':
                return_results(policy_delete_command(args, aws_client))
            case 'aws-org-policy-attach':
                return_results(policy_attach_command(args, aws_client))
            case 'aws-org-policy-target-list':
                return_results(policy_target_list_command(args, aws_client))
            case 'aws-org-resource-tag-add':
                return_results(resource_tag_add_command(args, aws_client))
            case 'aws-org-resource-tag-list':
                return_results(resource_tag_list_command(args, aws_client))
            case _:
                raise NotImplementedError(f'AWS-Organizations error: command {command!r} is not implemented')

    except Exception as error:
        demisto.debug(f'{error.args=}')
        return_error(f'Failed to execute {command!r}.\nError:\n{error}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
