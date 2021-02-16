import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3

urllib3.disable_warnings()

API_VERSION = '2019-06-01'


class ASClient:
    def __init__(self, app_id: str, subscription_id: str, resource_group_name: str, verify: bool, proxy: bool):
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)

        self.ms_client = MicrosoftClient(
            self_deployed=True,
            auth_id=app_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            grant_type=DEVICE_CODE,
            base_url=f'https://management.azure.com/subscriptions/{subscription_id}',
            verify=verify,
            proxy=proxy,
            resource='https://management.core.windows.net',
            scope='https://management.azure.com/user_impersonation offline_access user.read',
        )
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name

    @logger
    def storage_account_list_request(self, account_name: str) -> Dict:
        """
            Send the get storage account/s request to the API.
        Args:
            account_name: The storage account name, optional.

        Returns:
            The json response from the API call.
        """
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/resourceGroups/{self.resource_group_name}/providers/Microsoft.Storage/storageAccounts/'
                       f'{account_name}',
            params={
                'api-version': API_VERSION,
            }
        )

    @logger
    def storage_blob_service_properties_get_request(self, account_name: str) -> Dict:
        """
            Send the get blob service properties request to the API.
        Args:
            account_name: The storage account name.

        Returns:
            The json response from the API call.
        """
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/resourceGroups/{self.resource_group_name}/providers/Microsoft.Storage/storageAccounts/'
                       f'{account_name}/blobServices/default',
            params={
                'api-version': API_VERSION,
            }
        )

    @logger
    def storage_account_create_update_request(self, args: Dict) -> Dict:
        """
            Send the user arguments for the create/update account in the request body to the API.
        Args:
            args: The user arguments.

        Returns:
            The json response from the API call.
        """
        json_data_args = {
            'sku': {
                'name': args['sku']
            },
            'kind': args['kind'],
            'location': args['location'],
            'properties': {}
        }

        if 'tags' in args:
            args_tags_list = args['tags'].split(',')
            tags_obj = {f'tag{str(i + 1)}': args_tags_list[i] for i in range(len(args_tags_list))}
            json_data_args['tags'] = tags_obj

        if 'custom_domain_name' in args:
            custom_domain = {'name': args['custom_domain_name']}
            if args['use_sub_domain_name']:
                custom_domain['useSubDomainName'] = args['use_sub_domain_name']
            else:
                custom_domain['useSubDomainName'] = False
            json_data_args['properties']['customDomain'] = custom_domain

        if 'enc_key_source' in args:
            json_data_args['properties']['Encryption'] = {'keySource': args['enc_key_source'], 'keyvaultproperties': {}}

        if 'enc_keyvault_key_name' in args:
            if 'Encryption' not in json_data_args['properties']:
                json_data_args['properties']['Encryption'] = {}
            if 'keyvaultproperties' not in json_data_args['properties']['Encryption']:
                json_data_args['properties']['Encryption']['keyvaultproperties'] = {}
            json_data_args['properties']['Encryption']['keyvaultproperties']['keyname'] = args['enc_keyvault_key_name']

        if 'enc_keyvault_key_version' in args:
            if 'Encryption' not in json_data_args['properties']:
                json_data_args['properties']['Encryption'] = {}
            if 'keyvaultproperties' not in json_data_args['properties']['Encryption']:
                json_data_args['properties']['Encryption']['keyvaultproperties'] = {}
            json_data_args['properties']['Encryption']['keyvaultproperties']['keyversion'] = \
                args['enc_keyvault_key_version']

        if 'enc_keyvault_uri' in args:
            if 'Encryption' not in json_data_args['properties']:
                json_data_args['properties']['Encryption'] = {}
            if 'keyvaultproperties' not in json_data_args['properties']['Encryption']:
                json_data_args['properties']['Encryption']['keyvaultproperties'] = {}
            json_data_args['properties']['Encryption']['keyvaultproperties']['keyvaulturi'] = args['enc_keyvault_uri']

        if 'enc_requireInfrastructureEncryption' in args:
            if 'Encryption' not in json_data_args['properties']:
                json_data_args['properties']['Encryption'] = {}
            json_data_args['properties']['Encryption']['requireInfrastructureEncryption'] = \
                args['enc_requireInfrastructureEncryption']

        if 'network_ruleset_bypass' in args:
            if 'networkAcls' not in json_data_args['properties']:
                json_data_args['properties']['networkAcls'] = {}
            json_data_args['properties']['networkAcls']['bypass'] = args['network_ruleset_bypass']

        if 'network_ruleset_default_action' in args:
            if 'networkAcls' not in json_data_args['properties']:
                json_data_args['properties']['networkAcls'] = {}
            json_data_args['properties']['networkAcls']['defaultAction'] = args['network_ruleset_default_action']

        if 'network_ruleset_ipRules' in args:
            if 'networkAcls' not in json_data_args['properties']:
                json_data_args['properties']['networkAcls'] = {}
            json_data_args['properties']['networkAcls']['ipRules'] = json.loads(args['network_ruleset_ipRules'])

        if 'virtual_network_rules' in args:
            if 'networkAcls' not in json_data_args['properties']:
                json_data_args['properties']['networkAcls'] = {}
            json_data_args['properties']['networkAcls']['virtualNetworkRules'] = \
                json.loads(args['virtual_network_rules'])

        if 'access_tier' in args:
            json_data_args['properties']['accessTier'] = args['access_tier']

        if 'supports_https_traffic_only' in args:
            json_data_args['properties']['supportsHttpsTrafficOnly'] = args['supports_https_traffic_only']

        if 'is_hns_enabled' in args:
            json_data_args['properties']['isHnsEnabled'] = args['is_hns_enabled']

        if 'large_file_shares_state' in args:
            json_data_args['properties']['largeFileSharesState'] = args['large_file_shares_state']

        if 'allow_blob_public_access' in args:
            json_data_args['properties']['allowBlobPublicAccess'] = args['allow_blob_public_access']

        if 'minimum_tls_version' in args:
            json_data_args['properties']['minimumTlsVersion'] = args['minimum_tls_version']

        return self.ms_client.http_request(
            method='PUT',
            url_suffix=f'/resourceGroups/{self.resource_group_name}/providers/Microsoft.Storage/storageAccounts/'
                       f'/{args["account_name"]}',
            params={
                'api-version': API_VERSION,
            },
            json_data=json_data_args
        )

    def storage_blob_service_properties_set_request(self, args: Dict) -> Dict:
        """
            Send the user arguments for the blob service in the request body to the API.
        Args:
            args: The user arguments.

        Returns:
            The json response from the API call.
        """
        properties = {}

        if 'change_feed_enabled' in args:
            properties['changeFeed'] = {'enabled': args['change_feed_enabled']}

        if 'change_feed_retention_days' in args:
            if 'changeFeed' not in properties:
                properties['changeFeed'] = {}
            properties['changeFeed']['retentionInDays'] = args['change_feed_retention_days']

        if 'container_delete_rentention_policy_enabled' in args:
            properties['containerDeleteRetentionPolicy'] = \
                {'enabled': args['container_delete_rentention_policy_enabled']}

        if 'container_delete_rentention_policy_days' in args:
            if 'containerDeleteRetentionPolicy' not in properties:
                properties['containerDeleteRetentionPolicy'] = {}
            properties['containerDeleteRetentionPolicy']['days'] = args['container_delete_rentention_policy_days']

        if 'delete_rentention_policy_enabled' in args:
            properties['deleteRetentionPolicy'] = {'enabled': args['delete_rentention_policy_enabled']}

        if 'delete_rentention_policy_days' in args:
            if 'deleteRetentionPolicy' not in properties:
                properties['deleteRetentionPolicy'] = {}
            properties['deleteRetentionPolicy']['days'] = args['delete_rentention_policy_days']

        if 'versioning' in args:
            properties['isVersioningEnabled'] = args['versioning']

        if 'last_access_time_tracking_policy_enabled' in args:
            if 'lastAccessTimeTrackingPolicy' not in properties:
                properties['lastAccessTimeTrackingPolicy'] = {}
            properties['lastAccessTimeTrackingPolicy']['enable'] = args['last_access_time_tracking_policy_enabled']

        if 'last_access_time_tracking_policy_blob_types' in args:
            if 'lastAccessTimeTrackingPolicy' not in properties:
                properties['lastAccessTimeTrackingPolicy'] = {}
            properties['lastAccessTimeTrackingPolicy']['blobType'] = \
                args['last_access_time_tracking_policy_blob_types'].split(',')

        if 'last_access_time_tracking_policy_days' in args:
            if 'lastAccessTimeTrackingPolicy' not in properties:
                properties['lastAccessTimeTrackingPolicy'] = {}
            properties['lastAccessTimeTrackingPolicy']['trackingGranularityInDays'] = \
                args['last_access_time_tracking_policy_days']

        if 'restore_policy_enabled' in args:
            if 'restorePolicy' not in properties:
                properties['restorePolicy'] = {}
            properties['restorePolicy']['enabled'] = args['restore_policy_enabled']

        if 'restore_policy_min_restore_time' in args:
            if 'restorePolicy' not in properties:
                properties['restorePolicy'] = {}
            properties['restorePolicy']['minRestoreTime'] = args['restore_policy_min_restore_time']

        if 'restore_policy_days' in args:
            if 'restorePolicy' not in properties:
                properties['restorePolicy'] = {}
            properties['restorePolicy']['days'] = args['restore_policy_days']

        return self.ms_client.http_request(
            method='PUT',
            url_suffix=f'/resourceGroups/{self.resource_group_name}/providers/Microsoft.Storage/storageAccounts/'
                       f'{args["account_name"]}/blobServices/default',
            params={
                'api-version': API_VERSION,
            },
            json_data={'properties': properties}
        )


# Storage Account Commands


def storage_account_list(client: ASClient, args: Dict) -> CommandResults:
    """
        Gets a storage account if an account name is specified, and a list of storage accounts if not.
    Args:
        client: The microsoft client.
        args: The users arguments, (like account name).

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    account_name = args.get('account_name', '')
    response = client.storage_account_list_request(account_name)
    accounts = response.get('value', [response])

    readable_output = [{
        'Account Name': account.get('name'),
        'Subscription ID': re.search('subscriptions/(.+?)/resourceGroups', account.get('id')).group(1),
        'Resource Group': re.search('resourceGroups/(.+?)/providers', account.get('id')).group(1),
        'Kind': account.get('kind'),
        'Status Primary': account.get('properties').get('statusOfPrimary'),
        'Status Secondary': account.get('properties').get('statusOfSecondary'),
        'Location': account.get('location'),
    } for account in accounts]

    return CommandResults(
        outputs_prefix='AzureStorage.StorageAccount',
        outputs_key_field='id',
        outputs=accounts,
        readable_output=tableToMarkdown(
            'Azure Storage Account List',
            readable_output,
            ['Account Name', 'Subscription ID', 'Resource Group', 'Kind', 'Status Primary', 'Status Secondary',
             'Location'],
        ),
        raw_response=response
    )


def storage_account_create_update(client: ASClient, args: Dict) -> CommandResults:
    """
        Creates or updates a given storage account.
    Args:
        client: The microsoft client.
        args: The users arguments, (like account name).

    Returns:
        CommandResults: The command results in MD table and context data.
    """

    response = client.storage_account_create_update_request(args)

    readable_output = {
        'Account Name': response.get('name'),
        'Subscription ID': re.search('subscriptions/(.+?)/resourceGroups', response.get('id')).group(1),
        'Resource Group': re.search('resourceGroups/(.+?)/providers', response.get('id')).group(1),
        'Kind': response.get('kind'),
        'Status Primary': response.get('properties').get('statusOfPrimary'),
        'Status Secondary': response.get('properties').get('statusOfSecondary'),
        'Location': response.get('location')
    }

    return CommandResults(
        outputs_prefix='AzureStorage.StorageAccount',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(
            'Azure Storage Account',
            readable_output,
            ['Account Name', 'Subscription ID', 'Resource Group', 'Kind', 'Status Primary', 'Status Secondary',
             'Location'],
        ),
        raw_response=response
    )


# Blob Service Commands


def storage_blob_service_properties_get(client: ASClient, args: Dict) -> CommandResults:
    """
        Gets the blob service properties for the storage account.
    Args:
        client: The microsoft client.
        args: The users arguments, (like account name).

    Returns:
        CommandResults: The command results in MD table and context data.
    """

    account_name = args.get('account_name')
    response = client.storage_blob_service_properties_get_request(account_name)

    readable_output = {
        'Name': response.get('name'),
        'Subscription ID': re.search('subscriptions/(.+?)/resourceGroups', response.get('id')).group(1),
        'Resource Group': re.search('resourceGroups/(.+?)/providers', response.get('id')).group(1),
    }

    return CommandResults(
        outputs_prefix='AzureStorage.BlobServiceProperties',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(
            'Azure Storage Blob Service Properties',
            readable_output,
            ['Name', 'Subscription ID', 'Resource Group'],
        ),
        raw_response=response
    )


def storage_blob_service_properties_set(client: ASClient, args: Dict):
    """
        Sets the blob service properties for the storage account.
    Args:
        client: The microsoft client.
        args: The users arguments, (like account name).

    Returns:
        CommandResults: The command results in MD table and context data.
    """

    response = client.storage_blob_service_properties_set_request(args)

    readable_output = {
        'Name': response.get('name'),
        'Subscription ID': re.search('subscriptions/(.+?)/resourceGroups', response.get('id')).group(1),
        'Resource Group': re.search('resourceGroups/(.+?)/providers', response.get('id')).group(1),
    }

    return CommandResults(
        outputs_prefix='AzureStorage.BlobServiceProperties',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(
            'Azure Storage Blob Service Properties',
            readable_output,
            ['Name', 'Subscription ID', 'Resource Group'],
        ),
        raw_response=response
    )


# Authentication Functions


def start_auth(client: ASClient) -> CommandResults:
    user_code = client.ms_client.device_auth_request()
    return CommandResults(readable_output=f"""### Authorization instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
 and enter the code **{user_code}** to authenticate.
2. Run the **!azure-storage-auth-complete** command in the War Room.""")


def complete_auth(client: ASClient) -> str:
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_connection(client: ASClient) -> str:
    client.ms_client.get_access_token()
    return '✅ Success!'


def reset_auth() -> str:
    set_integration_context({})
    return 'Authorization was reset successfully. Run **!azure-storage-auth-start** to start the authentication \
    process.'


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = ASClient(
            app_id=params.get('app_id', ''),
            subscription_id=params.get('subscription_id', ''),
            resource_group_name=params.get('resource_group_name', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
        )
        if command == 'test-module':
            return_results('The test module is not functional, run the azure-storage-auth-start command instead.')
        elif command == 'azure-storage-auth-start':
            return_results(start_auth(client))
        elif command == 'azure-storage-auth-complete':
            return_results(complete_auth(client))
        elif command == 'azure-storage-auth-test':
            return_results(test_connection(client))
        elif command == 'azure-storage-auth-reset':
            return_results(reset_auth())
        elif command == 'azure-storage-account-list':
            return_results(storage_account_list(client, args))
        elif command == 'azure-storage-account-create-update':
            return_results(storage_account_create_update(client, args))
        elif command == 'azure-storage-blob-service-properties-get':
            return_results(storage_blob_service_properties_get(client, args))
        elif command == 'azure-storage-blob-service-properties-set':
            return_results(storage_blob_service_properties_set(client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        demisto.debug(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}', e)


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
