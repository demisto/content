import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from MicrosoftApiModule import *  # noqa: E402

import urllib3

urllib3.disable_warnings()

API_VERSION = '2023-02-01'
PREFIX_URL = 'https://management.azure.com/subscriptions/'


class AKSClient:
    def __init__(self, app_id: str, subscription_id: str, resource_group_name: str, verify: bool, proxy: bool,
                 tenant_id: str = None,
                 enc_key: str = None, auth_type: str = 'Device Code', redirect_uri: str = None, auth_code: str = None,
                 managed_identities_client_id: str = None,
                 azure_cloud: Optional[AzureCloud] = None,
                 ):
        azure_cloud = azure_cloud or AZURE_WORLDWIDE_CLOUD
        auth_types_dict: dict[str, Any] = {
            'Authorization Code': {
                'grant_type': AUTHORIZATION_CODE,
                'resource': None,
                'scope': urljoin(azure_cloud.endpoints.resource_manager, '.default'),
            },
            'Device Code': {
                'grant_type': DEVICE_CODE,
                'resource': azure_cloud.endpoints.management,
                'scope': urljoin(azure_cloud.endpoints.resource_manager, 'user_impersonation offline_access user.read'),
            },
            'Client Credentials': {
                'grant_type': CLIENT_CREDENTIALS,
                'resource': None,
                'scope': urljoin(azure_cloud.endpoints.resource_manager, '.default'),
            }
        }

        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)

        client_args = assign_params(
            self_deployed=True,
            auth_id=app_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token' if 'Device Code' in
                                                                                                       auth_type else None,
            grant_type=auth_types_dict.get(auth_type, {}).get('grant_type'),
            base_url=urljoin(azure_cloud.endpoints.resource_manager, f'subscriptions/{subscription_id}'),
            verify=verify,
            proxy=proxy,
            resource=auth_types_dict.get(auth_type, {}).get('resource'),
            scope=auth_types_dict.get(auth_type, {}).get('scope'),
            azure_ad_endpoint=azure_cloud.endpoints.active_directory,
            tenant_id=tenant_id,
            enc_key=enc_key,
            redirect_uri=redirect_uri,
            auth_code=auth_code,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.management_azure,
            command_prefix="azure-ks",
            azure_cloud=azure_cloud,
        )
        self.ms_client = MicrosoftClient(**client_args)
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name

    @logger
    def clusters_list_request(self, subscription_id: str) -> Dict:
        return self.ms_client.http_request(
            method='GET',
            full_url=f'{PREFIX_URL}{subscription_id}/providers/\
Microsoft.ContainerService/managedClusters?',
            params={
                'api-version': API_VERSION,
            },
        )

    @logger
    def cluster_get(self, resource_name: str) -> Dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'resourceGroups/{self.resource_group_name}/providers/Microsoft.ContainerService/managedClusters'
                       f'/{resource_name}',
            params={
                'api-version': API_VERSION,
            },
        )

    @logger
    def cluster_addon_update(self,
                             resource_name: str,
                             resource_group_name: str,
                             subscription_id: str,
                             location: str,
                             http_application_routing_enabled: Optional[bool] = None,
                             monitoring_agent_enabled: Optional[bool] = None,
                             monitoring_resource_name: Optional[str] = None,
                             ) -> Dict:
        addon_profiles: Dict[str, Any] = {}
        if http_application_routing_enabled is not None:
            addon_profiles['httpApplicationRouting'] = {'enabled': http_application_routing_enabled}
        if monitoring_agent_enabled is not None:
            if monitoring_resource_name:
                workspace_resource_id = f'/subscriptions/{self.subscription_id}/resourceGroups/' \
                                        f'DefaultResourceGroup-WUS/providers/Microsoft.OperationalInsights/workspaces' \
                                        f'/{monitoring_resource_name}'
            else:
                cluster = self.cluster_get(resource_name)
                workspace_resource_id = cluster.get('properties', {}).get('addonProfiles', {}).get('omsagent', {})\
                    .get('config', {}).get('logAnalyticsWorkspaceResourceID')
            addon_profiles['omsagent'] = {
                'enabled': monitoring_agent_enabled,
                'config': {'logAnalyticsWorkspaceResourceID': workspace_resource_id},
            }
        return self.ms_client.http_request(
            'PUT',
            full_url=f'{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}/providers/\
Microsoft.ContainerService/managedClusters/{resource_name}?',
            params={
                'api-version': API_VERSION,
            },
            json_data={
                'location': location,
                'properties': {
                    'addonProfiles': addon_profiles,
                }
            },
            timeout=30,
        )

    @logger
    def list_subscriptions_request(self):
        return self.ms_client.http_request(
            method='GET',
            full_url='https://management.azure.com/subscriptions?api-version=2020-01-01')

    @logger
    def list_resource_groups_request(self, subscription_id: str | None,
                                     filter_by_tag: str | None, limit: int) -> Dict:
        full_url = f'{PREFIX_URL}{subscription_id}/resourcegroups?'
        return self.ms_client.http_request('GET', full_url=full_url,
                                           params={'$filter': filter_by_tag, '$top': limit,
                                                   'api-version': '2021-04-01'})


def clusters_list(client: AKSClient, params: Dict, args: Dict) -> CommandResults:
    """
    This command is used to list all the AKS clusters in the subscription.
    Args:
        client: AKS client.
        params: The configuration parameters.
        args: the arguments from the user.
    Returns:
        CommandResults: The results of the command execution.
    """
    # subscription_id can be passed as command arguments or as configuration parameters,
    # if both are passed, the command arguments will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    response = client.clusters_list_request(subscription_id)
    clusters = response.get('value', [])
    readable_output = [{
        'Name': cluster.get('name'),
        'Status': cluster.get('properties', {}).get('provisioningState'),
        'Location': cluster.get('location'),
        'Tags': cluster.get('tags'),
        'Kubernetes version': cluster.get('properties', {}).get('kubernetesVersion'),
        'API server address': cluster.get('properties', {}).get('fqdn'),
        'Network type (plugin)': cluster.get('properties', {}).get('networkProfile', {}).get('networkPlugin'),
    } for cluster in clusters]
    return CommandResults(
        outputs_prefix='AzureKS.ManagedCluster',
        outputs_key_field='id',
        outputs=clusters,
        readable_output=tableToMarkdown(
            'AKS Clusters List',
            readable_output,
            ['Name', 'Status', 'Location', 'Tags', 'Kubernetes version', 'API server address', 'Network type (plugin)'],
        ),
        raw_response=response,
    )


def clusters_addon_update(client: AKSClient, params: Dict, args: Dict) -> str:
    """
    This command is used to update the a managed cluster.
    Args:
        client: AKS client.
        params: The configuration parameters.
        args: the arguments from the user.
    """
    update_args = {
        'resource_name': args.get('resource_name'),
        'resource_group_name': get_from_args_or_params(params=params, args=args, key='resource_group_name'),
        'subscription_id': get_from_args_or_params(params=params, args=args, key='subscription_id'),
        'location': args.get('location'),
    }
    if args.get('http_application_routing_enabled'):
        update_args['http_application_routing_enabled'] = argToBoolean(args.get('http_application_routing_enabled'))
    if args.get('monitoring_agent_enabled'):
        update_args['monitoring_agent_enabled'] = argToBoolean(args.get('monitoring_agent_enabled'))
        update_args['monitoring_resource_name'] = args.get('monitoring_resource_name')
    client.cluster_addon_update(**update_args)
    return 'The request to update the managed cluster was sent successfully.'


def ks_subscriptions_list(client: AKSClient) -> CommandResults:
    """
        Gets a list of subscriptions.
    Args:
        client: The AKS client.
    Returns:
        CommandResults: The command results in MD table and context data.
    """
    res = client.list_subscriptions_request()
    subscriptions = res.get('value', [])

    return CommandResults(
        outputs_prefix='AzureKS.Subscription',
        outputs_key_field='id',
        outputs=subscriptions,
        readable_output=tableToMarkdown(
            'Azure Kubernetes Subscriptions list',
            subscriptions,
            ['subscriptionId', 'tenantId', 'displayName', 'state'],
        ),
        raw_response=res
    )


def ks_resource_group_list(client: AKSClient, params: Dict, args: Dict) -> CommandResults:
    """
    List all resource groups in the subscription.
    Args:
        client (AKSClient): AKS client.
        params (Dict[str, Any]): configuration parameters.
        args (Dict[str, Any]): command arguments.
    Returns:
        Command results with raw response, outputs and readable outputs.
    """
    tag = args.get('tag')
    limit = arg_to_number(args.get('limit', 50))
    # subscription_id can be passed as command argument or as configuration parameter,
    # if both are passed as arguments, the command argument will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    filter_by_tag = azure_tag_formatter(tag) if tag else ''

    response = client.list_resource_groups_request(subscription_id=subscription_id,
                                                   filter_by_tag=filter_by_tag, limit=limit)
    data_from_response = response.get('value', [])

    readable_output = tableToMarkdown('Resource Groups List',
                                      data_from_response,
                                      ['name', 'location', 'tags',
                                       'properties.provisioningState'
                                       ],
                                      removeNull=True, headerTransform=string_to_table_header)
    return CommandResults(
        outputs_prefix='AzureKS.ResourceGroup',
        outputs_key_field='id',
        outputs=data_from_response,
        raw_response=response,
        readable_output=readable_output,
    )


def start_auth(client: AKSClient) -> CommandResults:
    result = client.ms_client.start_auth('!azure-ks-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: AKSClient) -> str:
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_connection(client: AKSClient) -> str:
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return '✅ Success!'


@logger
def test_module(client):
    """
    Performs basic GET request to check if the API is reachable and authentication is successful.
    Returns ok if successful.
    """
    params = demisto.params()
    if params.get('auth_type') == 'Device Code':
        raise Exception("When using device code flow configuration, "
                        "Please enable the integration and run `!azure-ks-auth-start` and `!azure-ks-auth-complete` to "
                        "log in. You can validate the connection by running `!azure-ks-auth-test`\n"
                        "For more details press the (?) button.")
    elif params.get('auth_type') == 'Authorization Code':
        raise Exception("When using user auth flow configuration, "
                        "Please enable the integration and run the !azure-ks-auth-test command in order to test it")
    elif params.get('auth_type') == 'Azure Managed Identities':
        test_connection(client=client)
        return 'ok'
    elif params.get('auth_type') == 'Client Credentials':
        client.ms_client.get_access_token()
        return 'ok'
    return None


def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        azure_cloud = get_azure_cloud(params, 'AzureKubernetesServices')
        client = AKSClient(
            tenant_id=params.get('tenant_id'),
            auth_type=params.get('auth_type', 'Device Code'),
            auth_code=params.get('auth_code', {}).get('password'),
            redirect_uri=params.get('redirect_uri'),
            enc_key=params.get('credentials', {}).get('password'),
            app_id=params.get('app_id', ''),
            subscription_id=params.get('subscription_id', ''),
            resource_group_name=params.get('resource_group_name', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            azure_cloud=azure_cloud,
            managed_identities_client_id=get_azure_managed_identities_client_id(params)
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'azure-ks-generate-login-url':
            return_results(generate_login_url(client.ms_client, login_url=azure_cloud.endpoints.active_directory))
        elif command == 'azure-ks-auth-start':
            return_results(start_auth(client))
        elif command == 'azure-ks-auth-complete':
            return_results(complete_auth(client))
        elif command == 'azure-ks-auth-test':
            return_results(test_connection(client))
        elif command == 'azure-ks-auth-reset':
            return_results(reset_auth())
        elif command == 'azure-ks-clusters-list':
            return_results(clusters_list(client=client, params=params, args=args))
        elif command == 'azure-ks-cluster-addon-update':
            return_results(clusters_addon_update(client=client, params=params, args=args))
        elif command == 'azure-ks-subscriptions-list':
            return_results(ks_subscriptions_list(client))
        elif command == 'azure-ks-resource-group-list':
            return_results(ks_resource_group_list(client=client, params=params, args=args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}', e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
