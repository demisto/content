import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3

urllib3.disable_warnings()

API_VERSION = '2021-09-01'


class AKSClient:
    def __init__(self, app_id: str, subscription_id: str, resource_group_name: str, verify: bool, proxy: bool,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com', tenant_id: str = None,
                 enc_key: str = None, auth_type: str = 'Device Code', redirect_uri: str = None, auth_code: str = None,
                 managed_identities_client_id: str = None):
        AUTH_TYPES_DICT: dict[str, Any] = {
            'Authorization Code': {
                'grant_type': AUTHORIZATION_CODE,
                'resource': None,
                'scope': 'https://management.azure.com/.default'
            },
            'Device Code': {
                'grant_type': DEVICE_CODE,
                'resource': 'https://management.core.windows.net',
                'scope': 'https://management.azure.com/user_impersonation offline_access user.read'
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
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            grant_type=AUTH_TYPES_DICT.get(auth_type, {}).get('grant_type'),
            base_url=f'https://management.azure.com/subscriptions/{subscription_id}',
            verify=verify,
            proxy=proxy,
            resource=AUTH_TYPES_DICT.get(auth_type, {}).get('resource'),
            scope=AUTH_TYPES_DICT.get(auth_type, {}).get('scope'),
            azure_ad_endpoint=azure_ad_endpoint,
            tenant_id=tenant_id,
            enc_key=enc_key,
            redirect_uri=redirect_uri,
            auth_code=auth_code,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.management_azure,
        )
        self.ms_client = MicrosoftClient(**client_args)
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name

    @logger
    def clusters_list_request(self) -> Dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix='providers/Microsoft.ContainerService/managedClusters',
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
            url_suffix=f'resourceGroups/{self.resource_group_name}/providers/Microsoft.ContainerService/managedClusters'
                       f'/{resource_name}',
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


def clusters_list(client: AKSClient) -> CommandResults:
    response = client.clusters_list_request()
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


def clusters_addon_update(client: AKSClient, args: Dict) -> str:
    update_args = {
        'resource_name': args.get('resource_name'),
        'location': args.get('location'),
    }
    if args.get('http_application_routing_enabled'):
        update_args['http_application_routing_enabled'] = argToBoolean(args.get('http_application_routing_enabled'))
    if args.get('monitoring_agent_enabled'):
        update_args['monitoring_agent_enabled'] = argToBoolean(args.get('monitoring_agent_enabled'))
        update_args['monitoring_resource_name'] = args.get('monitoring_resource_name')
    client.cluster_addon_update(**update_args)
    return 'The request to update the managed cluster was sent successfully.'


def start_auth(client: AKSClient) -> CommandResults:
    result = client.ms_client.start_auth('!azure-ks-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: AKSClient) -> str:
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_connection(client: AKSClient) -> str:
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return '✅ Success!'


def reset_auth() -> str:
    set_integration_context({})
    return 'Authorization was reset successfully. Run **!azure-ks-auth-start** to start the authentication process.'


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


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
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
            azure_ad_endpoint=params.get('azure_ad_endpoint',
                                         'https://login.microsoftonline.com') or 'https://login.microsoftonline.com',
            managed_identities_client_id=get_azure_managed_identities_client_id(params)
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'azure-ks-generate-login-url':
            return_results(generate_login_url(client.ms_client))
        elif command == 'azure-ks-auth-start':
            return_results(start_auth(client))
        elif command == 'azure-ks-auth-complete':
            return_results(complete_auth(client))
        elif command == 'azure-ks-auth-test':
            return_results(test_connection(client))
        elif command == 'azure-ks-auth-reset':
            return_results(reset_auth())
        elif command == 'azure-ks-clusters-list':
            return_results(clusters_list(client))
        elif command == 'azure-ks-cluster-addon-update':
            return_results(clusters_addon_update(client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}', e)


from MicrosoftApiModule import *  # noqa: E402


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
