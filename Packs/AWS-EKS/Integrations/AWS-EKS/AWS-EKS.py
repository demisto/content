import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from AWSApiModule import *  # noqa: E402

import urllib3
from typing import Dict, Any  # noqa: UP035

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''


def list_clusters_command(aws_client: AWSClient, args: dict) -> CommandResults:
    # TODO add docstring, and yml outputs, add pagination and the rest of the command
    client = aws_client.aws_session(service='eks')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    if (page and not page_size) or (not page and page_size):
        raise Exception('Please provide both page and page_size arguments.')
    if page_size:
        response = client.list_clusters(maxResults=page_size)
    else:
        response = client.list_clusters(maxResults=limit)

    return CommandResults()


def update_cluster_config_command(aws_client: AWSClient, args: dict) -> CommandResults:
    """
    Updates an Amazon EKS cluster configuration.
    Args:
        aws_client: AWS client
        args: command arguments

    Returns:
        A Command Results object
    """
    client = aws_client.aws_session(service='eks')
    name = args.get('name')
    resources_vpc_config = args.get('resources_vpc_config', '').replace('\'', '"')
    logging_arg = args.get('logging', '').replace('\'', '"')
    resources_vpc_config = json.loads(resources_vpc_config) if resources_vpc_config else {}
    logging_arg = json.loads(logging_arg) if logging_arg else {}
    demisto.debug(f'{resources_vpc_config=}')
    demisto.debug(f'{logging_arg=}')

    response = client.update_cluster_config(
        name=name,
        resourcesVpcConfig=resources_vpc_config,
        logging=logging_arg
    )
    response_data = response.get('update', {})
    response_data['name'] = name
    md_table = {
        'Cluster Name': response_data.get('name'),
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
        outputs_prefix='AWS.EKS.Cluster.Update',
        outputs=response_data,
        raw_response=response_data,
        outputs_key_field='id'
    )


def test_module(aws_client: AWSClient) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type aws_client: ``AWSClient``
    :param AWSClient: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        client = aws_client.aws_session(service='eks')
        client.list_clusters(maxResults=1)
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


''' MAIN FUNCTION '''


def main():
    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_access_key_id = params.get('credentials', {}).get('identifier')
    aws_secret_access_key = params.get('credentials', {}).get('password')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        validate_params(aws_default_region, '', '', aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, None, None, None,
                               None, aws_access_key_id, aws_secret_access_key, verify_certificate, None, 5)

        args = demisto.args()

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(aws_client))

        elif demisto.command() == 'aws-eks-list-clusters':
            return_results(list_clusters_command(aws_client, args))

        elif demisto.command() == 'aws-eks-update-cluster-config':
            return_results(update_cluster_config_command(aws_client, args))

        else:
            return_error(f"The command {demisto.command()} isn't implemented")


    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
