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


def datetime_to_str(data: dict, param_name: str):
    """
    Update a datetime parameter to it's string value.
    Args:
        data: a dictionary with the response data
        param_name: the name of the parameter that should be converted from datetime object to string.
    """
    if param_value := data.get(param_name):
        data[param_name] = param_value.strftime(DATE_FORMAT)


def validate_args(resources_vpc_config: dict, logging_arg: dict, authentication_mode: str):
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
    arg_num = 0
    for arg in arr:
        arg_num = arg_num + 1 if arg else arg_num
    if arg_num != 1:
        raise ValueError("Please provide exactly one of the following arguments: resources_vpc_config, logging or "
                         "authentication_mode.")
    else:
        return 'ok'


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
    return aws_client.aws_session(service='eks', region=args.get('region'))


''' COMMAND FUNCTIONS '''


def list_clusters_command(aws_client, args: dict) -> CommandResults:
    """
    Lists the Amazon EKS clusters in the Amazon Web Services account in the specified Amazon Web Services Region.
    Args:
        aws_client (boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
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
        'ClustersNames': list_clusters,
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


def update_cluster_config_command(aws_client, args: dict) -> CommandResults:
    """
    Updates an Amazon EKS cluster configuration.
    Args:
        aws_client(boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
    cluster_name = args.get('cluster_name')
    resources_vpc_config = args.get('resources_vpc_config', '').replace('\'', '"')
    logging_arg = args.get('logging', '').replace('\'', '"')
    resources_vpc_config = json.loads(resources_vpc_config) if resources_vpc_config else {}
    logging_arg = json.loads(logging_arg) if logging_arg else {}
    authentication_mode = args.get('authentication_mode', '')
    access_config = {
        'authenticationMode': authentication_mode
    } if authentication_mode else {}

    validate_args(resources_vpc_config, logging_arg, authentication_mode)

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
    datetime_to_str(response_data, 'createdAt')

    md_table = {
        'Cluster Name': response_data.get('clusterName'),
        'ID': response_data.get('id'),
        'Status': response_data.get('status'),
        'Type': response_data.get('type'),
        'Params': response_data.get('params'),
    }
    headers = ['Cluster Name', 'ID', 'Status', 'Type', 'Params']
    readable_output = tableToMarkdown(
        name='Updated Cluster Config Information',
        t=md_table,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AWS.EKS.UpdateCluster',
        outputs=response_data,
        raw_response=response_data,
        outputs_key_field='id'
    )


def describe_cluster_command(aws_client, args: dict) -> CommandResults:
    """
    Describes an Amazon EKS cluster.
    Args:
        aws_client(boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
    cluster_name = args.get('cluster_name')

    response = aws_client.describe_cluster(name=cluster_name)
    response_data = response.get('cluster', {})
    datetime_to_str(response_data, 'createdAt')
    datetime_to_str(response_data.get('connectorConfig', {}), 'activationExpiry')
    md_table = {
        'Cluster Name': response_data.get('name'),
        'ID': response_data.get('id'),
        'Status': response_data.get('status'),
        'ARN': response_data.get('arn'),
        'Created At': response_data.get('createdAt'),
        'Version': response_data.get('version'),
    }
    headers = ['Cluster Name', 'ID', 'Status', 'ARN', 'Created At', 'Version']
    readable_output = tableToMarkdown(
        name='Describe Cluster Information',
        t=md_table,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AWS.EKS.DescribeCluster',
        outputs=response_data,
        raw_response=response_data,
        outputs_key_field='name'
    )


def create_access_entry_command(aws_client, args: dict) -> CommandResults:
    """
    Creates an access entry.
    Args:
        aws_client(boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
    cluster_name = args.get('cluster_name')
    principal_arn = args.get('principal_arn')
    kubernetes_groups = argToList(args.get('kubernetes_groups'))
    tags = args.get('tags', '').replace('\'', '"')
    tags = json.loads(tags) if tags else {}
    client_request_token = args.get('client_request_token', '')
    username = args.get('username', '')
    type_arg = args.get('type', '').upper()

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

    datetime_to_str(response, 'createdAt')
    datetime_to_str(response, 'modifiedAt')

    md_table = {
        'Cluster Name': response.get('clusterName'),
        'Principal Arn': response.get('principalArn'),
        'Username': response.get('username'),
        'Type': response.get('type'),
        'Created At': response.get('createdAt')
    }

    headers = ['Cluster Name', 'Principal Arn', 'Username', 'Type', 'Created At']
    readable_output = tableToMarkdown(
        name='The newly created access entry',
        t=md_table,
        removeNull=True,
        headers=headers
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AWS.EKS.CreateAccessEntry',
        outputs=response,
        raw_response=response,
        outputs_key_field='ClusterName'
    )


def associate_access_policy_command(aws_client, args: dict) -> CommandResults:
    """
    Associates an access policy and its scope to an access entry.
    Args:
        aws_client(boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
    cluster_name = args.get('cluster_name')
    principal_arn = args.get('principal_arn')
    policy_arn = args.get('policy_arn')
    type_arg = args.get('type')
    namespaces = argToList(args.get('namespaces'))
    if type and type == 'namespace' and not namespaces:
        raise Exception(f'When the {type=}, you must enter a namespace.')

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

    datetime_to_str(response_data, 'associatedAt')
    datetime_to_str(response_data, 'modifiedAt')

    md_table = {
        'Cluster Name': response_data.get('clusterName'),
        'Principal ARN': response_data.get('principalArn'),
        'Policy ARN': response_data.get('policyArn'),
        'Associated At': response_data.get('associatedAt')
    }
    headers = ['Cluster Name', 'Principal ARN', 'Policy ARN', 'Associated At']
    readable_output = tableToMarkdown(
        name='The access policy was associated to the access entry successfully.',
        t=md_table,
        removeNull=True,
        headers=headers
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AWS.EKS.AssociatedAccessPolicy',
        outputs=response_data,
        raw_response=response_data,
        outputs_key_field='clusterName'
    )


def update_access_entry_command(aws_client, args: dict) -> CommandResults:
    """
    Updates an access entry.
    Args:
        aws_client(boto3 client): The configured AWS session.
        args: command arguments

    Returns:
        A Command Results object
    """
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

    datetime_to_str(response, 'createdAt')
    datetime_to_str(response, 'modifiedAt')

    md_table = {
        'Cluster Name': response.get('clusterName'),
        'Principal Arn': response.get('principalArn'),
        'Username': response.get('username'),
        'Type': response.get('type'),
        'Modified At': response.get('modifiedAt')
    }

    headers = ['Cluster Name', 'Principal Arn', 'Username', 'Type', 'Modified At']
    readable_output = tableToMarkdown(
        name='The updated access entry',
        t=md_table,
        removeNull=True,
        headers=headers
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AWS.EKS.UpdateAccessEntry',
        outputs=response,
        raw_response=response,
        outputs_key_field='ClusterName'
    )


def test_module(aws_client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type aws_client(boto3 client): The configured AWS session.
    :param AWSClient: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
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
    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_access_key_id = params.get('credentials', {}).get('identifier')
    aws_secret_access_key = params.get('credentials', {}).get('password')
    verify_certificate = not demisto.params().get('insecure', False)
    demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        validate_params(aws_default_region, '', '', aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, None, None, None,
                               None, aws_access_key_id, aws_secret_access_key, verify_certificate, None, 5)

        args = demisto.args()

        aws_client = config_aws_session(args, aws_client)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(aws_client))

        elif demisto.command() == 'aws-eks-list-clusters':
            return_results(list_clusters_command(aws_client, args))

        elif demisto.command() == 'aws-eks-update-cluster-config':
            return_results(update_cluster_config_command(aws_client, args))

        elif demisto.command() == 'aws-eks-describe-cluster':
            return_results(describe_cluster_command(aws_client, args))

        elif demisto.command() == 'aws-eks-create-access-entry':
            return_results(create_access_entry_command(aws_client, args))

        elif demisto.command() == 'aws-eks-associate-access-policy':
            return_results(associate_access_policy_command(aws_client, args))

        elif demisto.command() == 'aws-eks-update-access-entry':
            return_results(update_access_entry_command(aws_client, args))

        else:
            return_error(f"The command {demisto.command()} isn't implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
