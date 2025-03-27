import json
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from AWSApiModule import *  # noqa: E402

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' HELPER FUNCTIONS '''


def validate_args(resources_vpc_config: dict, logging_arg: dict, authentication_mode: bool):
    """
    Check that exactly one argument is passed, and if not raise a value error
    Args:
        resources_vpc_config: An object representing the VPC configuration to use for an Amazon EKS cluster.
        logging_arg: The cluster control plane logging configuration.
        authentication_mode: The desired authentication mode for the cluster.

    Returns:
        A Command Results object
    """
    arr = [resources_vpc_config, logging_arg, authentication_mode]
    arg_num = sum(bool(arg) for arg in arr)  # counts the number of non-empty args.
    if arg_num != 1:
        raise ValueError("Please provide exactly one of the following arguments: resources_vpc_config, logging or "
                         "authentication_mode.")


def config_aws_session(args: dict, aws_client: AWSClient):
    """
    Configures an AWS session for the EKS service,
    Used in all the commands.

    Args:
        args (dict): A dictionary containing the configuration parameters for the session.
                     - 'region' (str): The AWS region.

        aws_client (AWSClient): The AWS client used to configure the session.

    Returns:
        AWS session (boto3 client): The configured AWS session.
    """
    return aws_client.aws_session(
        service='eks',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration')
    )


def build_client(args: dict):
    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_access_key_id = params.get('credentials', {}).get('identifier')
    aws_secret_access_key = params.get('credentials', {}).get('password')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    verify_certificate = not params.get('insecure', False)
    timeout = params.get('timeout')
    retries = params.get('retries') or 5

    demisto.debug(f'Command being called is {demisto.command()}')

    validate_params(aws_default_region, '', '', aws_access_key_id,
                    aws_secret_access_key)

    aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                           None, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout, retries)

    aws_client = config_aws_session(args, aws_client)

    return aws_client


''' COMMAND FUNCTIONS '''


@run_on_all_accounts
def list_clusters_command(args: dict) -> CommandResults:
    """
    Lists the Amazon EKS clusters in the Amazon Web Services account in the specified Amazon Web Services Region.
    Args:
        aws_client (boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
    aws_client = build_client(args)
    limit = arg_to_number(args.get('limit')) or 50
    next_token = args.get('next_token', '')
    list_clusters = []
    flag = True  # Do we want to enter the while loop? -> in the first time, yes. After that only if next_token!=None & limit>0
    while limit > 0 and flag:
        if limit > 100:
            response = aws_client.list_clusters(maxResults=100,
                                                nextToken=next_token)
            limit -= 100
        else:
            response = aws_client.list_clusters(maxResults=limit,
                                                nextToken=next_token)
            limit = 0
        list_clusters.extend(response.get('clusters', []))
        next_token = response.get('nextToken')
        flag = bool(next_token)

    md_table = {
        'Clusters Names': list_clusters,
    }

    outputs = {
        'ClustersNames': list_clusters,
        'NextToken': next_token
    }

    if list_clusters:
        readable_output = tableToMarkdown(
            name='The list of clusters',
            t=md_table,
            removeNull=True,
        )
    else:
        readable_output = "No clusters found."

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AWS.EKS.Cluster',
        outputs=outputs,
        raw_response=outputs,
    )


@run_on_all_accounts
def update_cluster_config_command(args: dict) -> CommandResults:
    """
    Updates an Amazon EKS cluster configuration.
    Args:
        aws_client(boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
    aws_client = build_client(args)
    cluster_name = args.get('cluster_name')
    resources_vpc_config = args.get('resources_vpc_config', '').replace('\'', '"')
    logging_arg = args.get('logging', '').replace('\'', '"')
    resources_vpc_config = json.loads(resources_vpc_config) if resources_vpc_config else {}
    logging_arg = json.loads(logging_arg) if logging_arg else {}
    authentication_mode = argToBoolean(args.get('authentication_mode', False))

    validate_args(resources_vpc_config, logging_arg, authentication_mode)

    access_config = {
        'authenticationMode': 'API_AND_CONFIG_MAP'
    } if authentication_mode else {}

    try:
        if resources_vpc_config:
            response = aws_client.update_cluster_config(
                name=cluster_name,
                resourcesVpcConfig=resources_vpc_config
            )
        elif logging_arg:
            response = aws_client.update_cluster_config(
                name=cluster_name,
                logging=logging_arg,
            )
        else:  # access_config
            response = aws_client.update_cluster_config(
                name=cluster_name,
                accessConfig=access_config
            )

        response_data = response.get('update', {})
        response_data['clusterName'] = cluster_name
        response_data['createdAt'] = datetime_to_string(response_data.get('createdAt'))

        headers = ['clusterName', 'id', 'status', 'type', 'params']
        readable_output = tableToMarkdown(
            name='Updated Cluster Config Information',
            t=response_data,
            removeNull=True,
            headers=headers,
            headerTransform=pascalToSpace
        )
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='AWS.EKS.UpdateCluster',
            outputs=response_data,
            raw_response=response_data,
            outputs_key_field='id'
        )
    except Exception as e:
        if 'No changes needed' in str(e):
            return CommandResults(readable_output='No changes needed for the required update.')
        else:
            raise e


@run_on_all_accounts
def describe_cluster_command(args: dict) -> CommandResults:
    """
    Describes an Amazon EKS cluster.
    Args:
        aws_client(boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
    aws_client = build_client(args)
    cluster_name = args.get('cluster_name')

    response = aws_client.describe_cluster(name=cluster_name)
    response_data = response.get('cluster', {})
    response_data['createdAt'] = datetime_to_string(response_data.get('createdAt'))
    if response_data.get('connectorConfig', {}).get('activationExpiry'):
        response_data.get('connectorConfig', {})['activationExpiry'] = (
            datetime_to_string(response_data.get('connectorConfig', {}).get('activationExpiry')))

    headers = ['name', 'id', 'status', 'arn', 'createdAt', 'version']
    readable_output = tableToMarkdown(
        name='Describe Cluster Information',
        t=response_data,
        removeNull=True,
        headers=headers,
        headerTransform=pascalToSpace
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AWS.EKS.DescribeCluster',
        outputs=response_data,
        raw_response=response_data,
        outputs_key_field='name'
    )


@run_on_all_accounts
def create_access_entry_command(args: dict) -> CommandResults:
    """
    Creates an access entry.
    Args:
        aws_client(boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
    aws_client = build_client(args)
    cluster_name = args.get('cluster_name')
    principal_arn = args.get('principal_arn')
    kubernetes_groups = argToList(args.get('kubernetes_groups'))
    tags = args.get('tags', '').replace('\'', '"')
    tags = json.loads(tags) if tags else {}
    client_request_token = args.get('client_request_token', '')
    username = args.get('username', '')
    type_arg = args.get('type', '').upper()

    try:
        if username:
            response = aws_client.create_access_entry(
                clusterName=cluster_name,
                principalArn=principal_arn,
                kubernetesGroups=kubernetes_groups,
                tags=tags,
                clientRequestToken=client_request_token,
                username=username,
                type=type_arg
            ).get('accessEntry')
        else:
            response = aws_client.create_access_entry(
                clusterName=cluster_name,
                principalArn=principal_arn,
                kubernetesGroups=kubernetes_groups,
                tags=tags,
                clientRequestToken=client_request_token,
                type=type_arg
            ).get('accessEntry')

        response['createdAt'] = datetime_to_string(response.get('createdAt'))
        response['modifiedAt'] = datetime_to_string(response.get('modifiedAt'))

        headers = ['clusterName', 'principalArn', 'username', 'type', 'createdAt']
        readable_output = tableToMarkdown(
            name='The newly created access entry',
            t=response,
            removeNull=True,
            headers=headers,
            headerTransform=pascalToSpace
        )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='AWS.EKS.CreateAccessEntry',
            outputs=response,
            raw_response=response,
            outputs_key_field='ClusterName'
        )
    except Exception as e:
        if 'already in use' in str(e):
            return CommandResults(readable_output='The specified access entry resource is already in use on this cluster.')
        else:
            raise e


@run_on_all_accounts
def associate_access_policy_command(args: dict) -> CommandResults:
    """
    Associates an access policy and its scope to an access entry.
    Args:
        aws_client(boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
    aws_client = build_client(args)
    cluster_name = args.get('cluster_name')
    principal_arn = args.get('principal_arn')
    policy_arn = args.get('policy_arn')
    type_arg = args.get('type')
    namespaces = argToList(args.get('namespaces'))
    if type_arg and type_arg == 'namespace' and not namespaces:
        raise Exception(f'When the {type_arg=}, you must enter a namespace.')

    access_scope = {
        'type': type_arg,
        'namespaces': namespaces
    }

    response = aws_client.associate_access_policy(
        clusterName=cluster_name,
        principalArn=principal_arn,
        policyArn=policy_arn,
        accessScope=access_scope
    )
    response_data = response.get('associatedAccessPolicy', {})
    response_data['clusterName'] = response.get('clusterName')
    response_data['principalArn'] = response.get('principalArn')

    response_data['associatedAt'] = datetime_to_string(response_data.get('associatedAt'))
    response_data['modifiedAt'] = datetime_to_string(response_data.get('modifiedAt'))

    headers = ['clusterName', 'principalArn', 'policyArn', 'associatedAt']
    readable_output = tableToMarkdown(
        name='The access policy was associated to the access entry successfully.',
        t=response_data,
        removeNull=True,
        headers=headers,
        headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AWS.EKS.AssociatedAccessPolicy',
        outputs=response_data,
        raw_response=response_data,
        outputs_key_field='clusterName'
    )


@run_on_all_accounts
def update_access_entry_command(args: dict) -> CommandResults:
    """
    Updates an access entry.
    Args:
        aws_client(boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
    aws_client = build_client(args)
    cluster_name = args.get('cluster_name')
    principal_arn = args.get('principal_arn')
    kubernetes_groups = argToList(args.get('kubernetes_groups'))
    client_request_token = args.get('client_request_token', '')
    username = args.get('username')

    if username:
        response = aws_client.update_access_entry(
            clusterName=cluster_name,
            principalArn=principal_arn,
            kubernetesGroups=kubernetes_groups,
            clientRequestToken=client_request_token,
            username=username
        ).get('accessEntry', {})
    else:
        response = aws_client.update_access_entry(
            clusterName=cluster_name,
            principalArn=principal_arn,
            kubernetesGroups=kubernetes_groups,
            clientRequestToken=client_request_token
        ).get('accessEntry', {})

    response['createdAt'] = datetime_to_string(response.get('createdAt'))
    response['modifiedAt'] = datetime_to_string(response.get('modifiedAt'))

    headers = ['clusterName', 'principalArn', 'username', 'type', 'modifiedAt']
    readable_output = tableToMarkdown(
        name='The updated access entry',
        t=response,
        removeNull=True,
        headers=headers,
        headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AWS.EKS.UpdateAccessEntry',
        outputs=response,
        raw_response=response,
        outputs_key_field='ClusterName'
    )


def test_module() -> str:  # pragma: no cover
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type aws_client(boto3 client): The configured AWS session.
    :param AWSClient: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    aws_client = build_client({})
    message: str = ''
    params = demisto.params()
    role_name: str = params.get('access_role_name', '')

    if role_name:
        if not params.get('accounts_to_access'):
            raise DemistoException("'AWS organization accounts' must not be empty when an access role is provided.")

        def test_account(args: dict) -> CommandResults:
            build_client(args)
            return CommandResults()

        fails = [
            result.readable_output
            for result in run_on_all_accounts(test_account)({})  # type: ignore
            if result.entry_type == EntryType.ERROR
        ]
        if fails:
            demisto.debug('\n\n'.join(fails))
            #  extract the account ID form the readable_output encased in backticks
            fail_ids = ', '.join(res.split('`')[1] for res in fails)
            raise DemistoException(
                f'AssumeRole with role name {role_name!r} failed for the following accounts: {fail_ids}.'
            )

    try:
        aws_client.list_clusters(maxResults=1)
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


''' MAIN FUNCTION '''


def main():  # pragma: no cover

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        args = demisto.args()

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module())

        elif demisto.command() == 'aws-eks-list-clusters':
            return_results(list_clusters_command(args))

        elif demisto.command() == 'aws-eks-update-cluster-config':
            return_results(update_cluster_config_command(args))

        elif demisto.command() == 'aws-eks-describe-cluster':
            return_results(describe_cluster_command(args))

        elif demisto.command() == 'aws-eks-create-access-entry':
            return_results(create_access_entry_command(args))

        elif demisto.command() == 'aws-eks-associate-access-policy':
            return_results(associate_access_policy_command(args))

        elif demisto.command() == 'aws-eks-update-access-entry':
            return_results(update_access_entry_command(args))

        else:
            return_error(f"The command {demisto.command()} isn't implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
