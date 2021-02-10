import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3

urllib3.disable_warnings()

API_VERSION = '2019-06-01'


class AKSClient:
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
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/resourceGroups/{self.resource_group_name}/providers/Microsoft.Storage/storageAccounts/{account_name}',
            params={
                'api-version': API_VERSION,
            }
        )

    @logger
    def storage_blob_service_properties_get_request(self, account_name: str) -> Dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/resourceGroups/{self.resource_group_name}/providers/Microsoft.Storage/storageAccounts/{account_name}/blobServices/default',
            params={
                'api-version': API_VERSION,
            }
        )

    @logger
    def storage_account_create_update(self,
                                      account_name: str,
                                      sku: str,
                                      kind: str,
                                      location: str,
                                      tags: Optional[str] = None,
                                      custom_domain_name: Optional[str] = None,
                                      use_sub_domain_name: Optional[bool] = None,
                                      enc_key_source: Optional[str] = None,
                                      enc_requireInfrastructureEncryption: Optional[bool] = None,
                                      enc_keyvault_key_name: Optional[str] = None,
                                      enc_keyvault_key_version: Optional[str] = None,
                                      enc_keyvault_uri: Optional[str] = None,
                                      access_tier: Optional[str] = None,
                                      supports_https_traffic_only: Optional[bool] = None,
                                      is_hns_enabled: Optional[bool] = None,
                                      large_file_shares_state: Optional[str] = None,
                                      allow_blob_public_access: Optional[bool] = None,
                                      minimum_tls_version: Optional[str] = None
                                      ) -> Dict:
        json_data_args = {
            'sku': {
                'name': sku
            },
            'kind': kind,
            'location': location,
            'properties': {}
        }
        if tags is not None:
            args_tags_list = tags.split(',')
            tags_obj = {f'tag{str(i+1)}': args_tags_list[i] for i in range(len(args_tags_list))}
            json_data_args['tags'] = tags_obj
        if custom_domain_name is not None:
            custom_domain = {'name': custom_domain_name}
            if use_sub_domain_name is not None:
                custom_domain['useSubDomainName'] = use_sub_domain_name
            else:
                custom_domain['useSubDomainName'] = False
            json_data_args['properties']['customDomain'] = custom_domain
        if enc_key_source is not None:
            json_data_args['properties']['Encryption'] = {'keySource': enc_key_source, 'keyvaultproperties':{}}
        if enc_keyvault_key_name is not None:
            json_data_args['properties']['Encryption']['keyvaultproperties']['keyname'] = enc_keyvault_key_name
        if enc_keyvault_key_version is not None:
            json_data_args['properties']['Encryption']['keyvaultproperties']['keyversion'] = enc_keyvault_key_version
        if enc_keyvault_uri is not None:
            json_data_args['properties']['Encryption']['keyvaultproperties']['keyvaulturi'] = enc_keyvault_uri
        if enc_requireInfrastructureEncryption is not None:
            json_data_args['properties']['Encryption']['requireInfrastructureEncryption'] = enc_requireInfrastructureEncryption
        if access_tier is not None:
            json_data_args['properties']['accessTier'] = access_tier
        if supports_https_traffic_only is not None:
            json_data_args['properties']['supportsHttpsTrafficOnly'] = supports_https_traffic_only
        if is_hns_enabled is not None:
            json_data_args['properties']['isHnsEnabled'] = is_hns_enabled
        if large_file_shares_state is not None:
            json_data_args['properties']['largeFileSharesState'] = large_file_shares_state
        if allow_blob_public_access is not None:
            json_data_args['properties']['allowBlobPublicAccess'] = allow_blob_public_access
        if minimum_tls_version is not None:
            json_data_args['properties']['minimumTlsVersion'] = minimum_tls_version
        print(json_data_args)
        return self.ms_client.http_request(
            method='PUT',
            url_suffix=f'/resourceGroups/{self.resource_group_name}/providers/Microsoft.Storage/storageAccounts/'
                       f'/{account_name}',
            params={
                'api-version': API_VERSION,
            },
            json_data=json_data_args,
            timeout=30,
        )


def storage_account_list(client: AKSClient, args: Dict) -> CommandResults:
    account_name = args.get('account_name', '')
    response = client.storage_account_list_request(account_name)
    accounts = response.get('value', [response])
    readable_output = [{
        'Account Name': account.get('name'),
        'Subscription ID': re.search('subscriptions/(.+?)/resourceGroups', account.get('id')).group(1),
        'Resource Group': re.search('resourceGroups/(.+?)/providers', account.get('id')).group(1),
        'Kind': account.get('kind'),
        'Sku': account.get('sku', {}),
        'Status Primary': account.get('properties', {}).get('statusOfPrimary'),
        'Status Secondary': account.get('properties', {}).get('statusOfSecondary'),
        'Location': account.get('location'),
        'Tags': account.get('tags')
    } for account in accounts]
    return CommandResults(
        outputs_prefix='AzureStorage.StorageAccount',
        outputs_key_field='id',
        outputs=accounts,
        readable_output=tableToMarkdown(
            'Azure Storage Account List',
            readable_output,
            ['Account Name', 'Subscription ID', 'Resource Group', 'Kind', 'Sku', 'Status Primary', 'Status Secondary', 'Location', 'Tags'],
        ),
        raw_response=response
    )


def storage_account_create_update(client: AKSClient, args: Dict) -> str:
    account_args = {
        'account_name': args.get('account_name'),
        'sku': args.get('sku'),
        'kind': args.get('kind'),
        'location': args.get('location')
    }
    if args.get('tags'):
        account_args['tags'] = args.get('tags')
    if args.get('custom_domain_name'):
        account_args['custom_domain_name'] = args.get('custom_domain_name')
        if args.get('use_sub_domain_name'):
            account_args['use_sub_domain_name'] = argToBoolean(args.get('use_sub_domain_name'))
        else:
            account_args['use_sub_domain_name'] = False
    if args.get('enc_key_source'):
        account_args['enc_key_source'] = args.get('enc_key_source')
    if args.get('enc_requireInfrastructureEncryption'):
        account_args['enc_requireInfrastructureEncryption'] = argToBoolean(args.get('enc_requireInfrastructureEncryption'))
    if args.get('enc_keyvault_key_name'):
        account_args['enc_keyvault_key_name'] = args.get('enc_keyvault_key_name')
    if args.get('enc_keyvault_key_version'):
        account_args['enc_keyvault_key_version'] = args.get('enc_keyvault_key_version')
    if args.get('enc_keyvault_uri'):
        account_args['enc_keyvault_uri'] = args.get('enc_keyvault_uri')
    if args.get('access_tier'):
        account_args['access_tier'] = args.get('access_tier')
    if args.get('supports_https_traffic_only'):
        account_args['supports_https_traffic_only'] = argToBoolean(args.get('supports_https_traffic_only'))
    if args.get('is_hns_enabled'):
        account_args['is_hns_enabled'] = argToBoolean(args.get('is_hns_enabled'))
    if args.get('large_file_shares_state'):
        account_args['large_file_shares_state'] = args.get('large_file_shares_state')
    if args.get('allow_blob_public_access'):
        account_args['allow_blob_public_access'] = argToBoolean(args.get('allow_blob_public_access'))
    if args.get('minimum_tls_version'):
        account_args['minimum_tls_version'] = args.get('minimum_tls_version')

    try:
        client.storage_account_create_update(**account_args)
        return 'The request to create/update an storage account was sent successfully.'
    except Exception as e:
        return e


def storage_blob_service_properties_get(client: AKSClient, args: Dict):
    account_name = args.get('account_name')
    response = client.storage_blob_service_properties_get_request(account_name)
    readable_output = {
        'Name': response.get('name'),
        'Subscription ID': re.search('subscriptions/(.+?)/resourceGroups', response.get('id')).group(1),
        'Resource Group': re.search('resourceGroups/(.+?)/providers', response.get('id')).group(1),
        'Sku': response.get('sku', {})
    }
    return CommandResults(
        outputs_prefix='AzureStorage.BlobServiceProperties',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(
            'Azure Storage Account List',
            readable_output,
            ['Name', 'Subscription ID', 'Resource Group', 'Sku'],
        ),
        raw_response=response
    )


def azure_storage_blob_service_properties_set(client: AKSClient, args: Dict):
    return


def start_auth(client: AKSClient) -> CommandResults:
    user_code = client.ms_client.device_auth_request()
    return CommandResults(readable_output=f"""### Authorization instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
 and enter the code **{user_code}** to authenticate.
2. Run the **!azure-ks-auth-complete** command in the War Room.""")


def complete_auth(client: AKSClient) -> str:
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_connection(client: AKSClient) -> str:
    client.ms_client.get_access_token()
    return '✅ Success!'


def reset_auth() -> str:
    set_integration_context({})
    return 'Authorization was reset successfully. Run **!azure-ks-auth-start** to start the authentication process.'


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = AKSClient(
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
        # elif command == 'azure-storage-account-create-update':
        #     return_results(storage_blob_service_properties_set(client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}', e)

from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
