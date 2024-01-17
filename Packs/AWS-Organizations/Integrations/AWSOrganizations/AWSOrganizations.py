from typing import TYPE_CHECKING
from collections.abc import Callable
from CommonServerPython import *  # noqa
import demistomock as demisto  # noqa
from AWSApiModule import *  # noqa

# The following imports are used only for type hints and autocomplete.
# They are not used at runtime, and are not in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_organizations.literals import (
        PolicyTypeType,
        CreateAccountFailureReasonType
    )

''' CONSTANTS '''

SERVICE_NAME = 'organizations'
REGION = 'us-east-1'
MAX_PAGINATION = 20
POLICY_TYPE_MAP: dict[str, 'PolicyTypeType'] = {
    'Service Control Policy': 'SERVICE_CONTROL_POLICY',
    'Tag Policy': 'TAG_POLICY',
    'Backup Policy': 'BACKUP_POLICY',
    'AI Services Opt Out Policy': 'AISERVICES_OPT_OUT_POLICY'
}
CREATE_ACCOUNT_FAILURE_MAP: dict['CreateAccountFailureReasonType', str] = {
    "ACCOUNT_LIMIT_EXCEEDED":
        "The account couldn't be created because you reached the limit on the number of accounts in your organization.",
    "CONCURRENT_ACCOUNT_MODIFICATION":
        "You already submitted a request with the same information.",
    "EMAIL_ALREADY_EXISTS":
        "The account could not be created because another Amazon Web Services account with that email address already exists.",
    "FAILED_BUSINESS_VALIDATION":
        "The Amazon Web Services account that owns your organization failed to receive business license validation.",
    "GOVCLOUD_ACCOUNT_ALREADY_EXISTS":
        "The account in the Amazon Web Services GovCloud (US) Region could not be created because this"
        " Region already includes an account with that email address.",
    "INVALID_IDENTITY_FOR_BUSINESS_VALIDATION":
        "The Amazon Web Services account that owns your organization can't complete business license validation"
        "because it doesn't have valid identity data.",
    "INVALID_ADDRESS": "The account could not be created because the address you provided is not valid.",
    "INVALID_EMAIL": "The account could not be created because the email address you provided is not valid.",
    "INVALID_PAYMENT_INSTRUMENT":
        "The Amazon Web Services account that owns your organization does not have a "
        "supported payment method associated with the account.",
    "INTERNAL_FAILURE":
        "The account could not be created because of an internal failure. Try again later."
        " If the problem persists, contact Amazon Web Services Customer Support.",
    "MISSING_BUSINESS_VALIDATION":
        "The Amazon Web Services account that owns your organization has not received Business Validation.",
    "MISSING_PAYMENT_INSTRUMENT": "You must configure the management account with a valid payment method, such as a credit card.",
    "PENDING_BUSINESS_VALIDATION":
        "The Amazon Web Services account that owns your organization is still in the"
        " process of completing business license validation.",
    "UNKNOWN_BUSINESS_VALIDATION":
        "The Amazon Web Services account that owns your organization"
        " has an unknown issue with business license validation.",
}

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
        region=REGION,
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )


def paginate(
    client_func: Callable,
    key_to_pages: str, limit=None, page_size=None,
    next_token=None, **kwargs
) -> tuple[list, str | None]:
    '''This function exists because AWS doesn't guarantee that the client functions will
    return all results specified in a single call.
    This function also handles the XSOAR pagination conventions such as the limit, page_size and next_token args.
    '''

    if not page_size and not next_token:
        next_token = None
        page_size = limit
    page_size = arg_to_number(page_size) or 50
    pages: list = []

    while page_size:
        response: dict = client_func(
            **assign_params(NextToken=next_token),
            MaxResults=min(page_size, MAX_PAGINATION),
            **kwargs,
        )
        page = response.get(key_to_pages, [])
        next_token = response.get('NextToken')
        pages.extend(page)
        page_size -= len(page)
        if next_token is None:
            break

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


def build_tags(tags: str | None) -> list:
    '''Turns the tags provided by the args in the format "key=value" into the format expected by AWS'''
    result = []
    for tag in argToList(tags):
        key, eq, value = tag.partition('=')
        if not eq:
            raise DemistoException('Tags must be provided in the format "key=value".')
        result.append(
            {
                'Key': key,
                'Value': value
            }
        )
    return result


''' COMMAND FUNCTIONS '''


def test_module(aws_client: 'OrganizationsClient') -> str:
    aws_client.describe_organization()
    return 'ok'


def root_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    roots, next_token = paginate(
        aws_client.list_roots,
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
            roots, ['Id', 'Arn', 'Name'],
            removeNull=True,
        )
    )


def children_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    children, next_token = paginate(
        aws_client.list_children,
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
        aws_client.list_parents,
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
        outputs_prefix='AWS.Organizations.OrganizationUnit',
        outputs=ou.get('OrganizationalUnit', {}),
        readable_output=tableToMarkdown(
            'AWS Organization Unit',
            ou.get('OrganizationalUnit', {}),
            ['Id', 'Arn', 'Name'],
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
            aws_client.list_accounts,
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
        readable_output=f'AWS account *{args["account_id"]}* removed successfully.'
    )


def account_move_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    aws_client.move_account(
        AccountId=args['account_id'],
        SourceParentId=args['source_parent_id'],
        DestinationParentId=args['destination_parent_id'],
    )

    return CommandResults(
        readable_output=f'AWS account *{args["account_id"]}* moved successfully.'
    )


@polling_function(
    'aws-org-account-create',
    interval=arg_to_number(demisto.getArg('interval_in_seconds')),
    timeout=arg_to_number(demisto.getArg('timeout')),
    poll_message='Creating account:',
    requires_polling_arg=False
)
def account_create_command(args: dict, aws_client: 'OrganizationsClient') -> PollResult:

    def initial_call() -> dict:
        account = aws_client.create_account(
            Email=args['email'],
            AccountName=args['account_name'],
            RoleName=args['role_name'],
            IamUserAccessToBilling=args['iam_user_access_to_billing'].upper(),
            **assign_params(Tags=build_tags(args.get('tags')))
        )
        args['request_id'] = account['CreateAccountStatus']['Id']
        return account['CreateAccountStatus']

    def polling_call() -> dict:
        account = aws_client.describe_create_account_status(
            CreateAccountRequestId=args['request_id']
        )
        return account['CreateAccountStatus']

    def create_response(account: dict) -> PollResult:

        match account['State']:
            case 'SUCCEEDED':
                return PollResult(
                    response=account_list_command(
                        {'account_id': account['AccountId']},
                        aws_client
                    ),
                    continue_to_poll=False
                )
            case 'FAILED':
                reason = account.get('FailureReason')
                raise DemistoException(f'Failed to create account. Reason: {CREATE_ACCOUNT_FAILURE_MAP.get(reason, reason)}')
            case _:
                return PollResult(
                    response=None,
                    continue_to_poll=True
                )

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

    if not argToBoolean(args['is_closed']):
        aws_client.close_account(
            AccountId=args['account_id']
        )
        args['is_closed'] = True

    account = aws_client.describe_account(
        AccountId=args['account_id']
    )

    return PollResult(
        response=CommandResults(
            readable_output=f'AWS account *{args["account_id"]}* closed successfully.'
        ),
        continue_to_poll=(dict_safe_get(account, ['Account', 'Status']) != 'SUSPENDED'),
    )


def organization_unit_create_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    ou = aws_client.create_organizational_unit(
        ParentId=args['parent_id'],
        Name=args['name'],
        **assign_params(Tags=build_tags(args.get('tags')))
    )

    return CommandResults(
        outputs_prefix='AWS.Organizations.OrganizationUnit',
        outputs_key_field='Id',
        outputs=ou['OrganizationalUnit'],
        readable_output=tableToMarkdown(
            'AWS Organization Unit',
            ou['OrganizationalUnit'],
            ['Id', 'Name', 'Arn'],
            removeNull=True
        )
    )


def organization_unit_delete_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    aws_client.delete_organizational_unit(
        OrganizationalUnitId=args['organizational_unit_id']
    )

    return CommandResults(
        readable_output=f'AWS organizational unit *{args["organizational_unit_id"]}* deleted successfully.'
    )


def organization_unit_rename_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    aws_client.update_organizational_unit(
        OrganizationalUnitId=args['organizational_unit_id'],
        Name=args['name']
    )

    return CommandResults(
        readable_output=f'AWS organization unit *{args["organizational_unit_id"]}* successfully renamed to *{args["name"]}*.'
    )


def policy_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    policies, next_token = paginate(
        aws_client.list_policies,
        'Policies',
        limit=args.get('limit'),
        next_token=args.get('next_token'),
        page_size=args.get('page_size'),
        Filter=POLICY_TYPE_MAP[args['policy_type']]
    )

    return CommandResults(
        outputs=next_token_output_dict(
            'Policy', next_token, policies,
        ),
        readable_output=tableToMarkdown(
            'AWS Organization Policies',
            policies,
            [
                'Id', 'Arn', 'Name',
                'Description', 'Type', 'AwsManaged'
            ],
            removeNull=True,
        )
    )


def target_policy_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    policies, next_token = paginate(
        aws_client.list_policies_for_target,
        'Policies',
        limit=args.get('limit'),
        next_token=args.get('next_token'),
        page_size=args.get('page_size'),
        TargetId=args['target_id'],
        Filter=POLICY_TYPE_MAP[args['policy_type']]
    )

    return CommandResults(
        outputs=next_token_output_dict(
            'TargetPolicy',
            next_token,
            [
                policy | {'TargetId': args['target_id']}
                for policy in policies
            ],
        ),
        readable_output=tableToMarkdown(
            f'AWS Organization *{args["target_id"]}* Policies',
            policies,
            [
                'Id', 'Arn', 'Name',
                'Description', 'Type', 'AwsManaged'
            ],
            removeNull=True,
        )
    )


def policy_get_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    response = aws_client.describe_policy(
        PolicyId=args['policy_id']
    )

    policy = dict_safe_get(response, ['Policy', 'PolicySummary'])

    return CommandResults(
        raw_response=response,
        outputs=policy,
        outputs_key_field='Id',
        outputs_prefix='AWS.Organizations.Policy',
        readable_output=tableToMarkdown(
            'AWS Organization Policies',
            policy,
            [
                'Id', 'Arn', 'Name',
                'Description', 'Type', 'AwsManaged'
            ],
            removeNull=True,
        )
    )


def policy_delete_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    aws_client.delete_policy(
        PolicyId=args['policy_id']
    )

    return CommandResults(
        readable_output=f'AWS Organizations policy *{args["policy_id"]}* successfully deleted.'
    )


def policy_attach_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    aws_client.attach_policy(
        PolicyId=args['policy_id'],
        TargetId=args['target_id']
    )

    return CommandResults(
        readable_output=f'AWS Organizations policy *{args["policy_id"]}* successfully attached.'
    )


def policy_target_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    targets, next_token = paginate(
        aws_client.list_targets_for_policy,
        'Targets',
        limit=args.get('limit'),
        next_token=args.get('next_token'),
        page_size=args.get('page_size'),
        PolicyId=args['policy_id']
    )

    return CommandResults(
        outputs=next_token_output_dict(
            'PolicyTarget',
            next_token,
            [
                target | {'PolicyId': args['policy_id']}
                for target in targets
            ],
            'TargetId'
        ),
        readable_output=tableToMarkdown(
            f'AWS Organization *{args["policy_id"]}* Targets',
            targets,
            ['TargetId', 'Arn', 'Name', 'Type'],
            removeNull=True
        )
    )


def resource_tag_add_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    aws_client.tag_resource(
        ResourceId=args['resource_id'],
        Tags=build_tags(args['tags'])
    )

    return CommandResults(
        readable_output=f'AWS Organizations resource *{args["resource_id"]}* successfully tagged.'
    )


def resource_tag_list_command(args: dict, aws_client: 'OrganizationsClient') -> CommandResults:

    tags = aws_client.list_tags_for_resource(
        ResourceId=args['resource_id'],
        **assign_params(NextToken=args.get('next_token'))
    )

    return CommandResults(
        outputs=next_token_output_dict(
            'Tag',
            tags.get('NextToken'),
            [
                tag | {'ResourceId': args['resource_id']}
                for tag in tags.get('Tags', [])
            ],
            'Key'
        ),
        readable_output=tableToMarkdown(
            f'AWS Organization *{args["resource_id"]}* Tags',
            tags.get('Tags', []), ['Key', 'Value'],
        )
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
        elif command == 'aws-org-organization-unit-create':
            return_results(organization_unit_create_command(args, aws_client))
        elif command == 'aws-org-organization-unit-delete':
            return_results(organization_unit_delete_command(args, aws_client))
        elif command == 'aws-org-organization-unit-rename':
            return_results(organization_unit_rename_command(args, aws_client))
        elif command == 'aws-org-policy-list':
            return_results(policy_list_command(args, aws_client))
        elif command == 'aws-org-target-policy-list':
            return_results(target_policy_list_command(args, aws_client))
        elif command == 'aws-org-policy-get':
            return_results(policy_get_command(args, aws_client))
        elif command == 'aws-org-policy-delete':
            return_results(policy_delete_command(args, aws_client))
        elif command == 'aws-org-policy-attach':
            return_results(policy_attach_command(args, aws_client))
        elif command == 'aws-org-policy-target-list':
            return_results(policy_target_list_command(args, aws_client))
        elif command == 'aws-org-resource-tag-add':
            return_results(resource_tag_add_command(args, aws_client))
        elif command == 'aws-org-resource-tag-list':
            return_results(resource_tag_list_command(args, aws_client))
        else:
            raise NotImplementedError(f'AWS-Organizations error: command {command!r} is not implemented')

    except Exception as error:
        demisto.debug(f'{error.args=}')
        return_error(f'Failed to execute {command!r}.\n{error}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
