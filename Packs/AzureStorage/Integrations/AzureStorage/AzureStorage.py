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
            tags_obj = {f'tag{str(i+1)}': args_tags_list[i] for i in range(len(args_tags_list))}
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
        'Subscription ID': re.search('subscriptions/(.+?)/resourceGroups', account.get('id', '')).group(1),
        'Resource Group': re.search('resourceGroups/(.+?)/providers', account.get('id', '')).group(1),
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
        'Subscription ID': re.search('subscriptions/(.+?)/resourceGroups', response.get('id', '')).group(1),
        'Resource Group': re.search('resourceGroups/(.+?)/providers', response.get('id', '')).group(1),
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
        'Subscription ID': re.search('subscriptions/(.+?)/resourceGroups', response.get('id', '')).group(1),
        'Resource Group': re.search('resourceGroups/(.+?)/providers', response.get('id', '')).group(1),
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
        'Subscription ID': re.search('subscriptions/(.+?)/resourceGroups', response.get('id', '')).group(1),
        'Resource Group': re.search('resourceGroups/(.+?)/providers', response.get('id', '')).group(1),
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

#################################################
import traceback

import requests
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Tuple, List, Optional


class Scopes:
    graph = 'https://graph.microsoft.com/.default'
    security_center = 'https://api.securitycenter.windows.com/.default'


# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'

# grant types in self-deployed authorization
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line
DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: str = '',
                 token_retrieval_url: str = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 auth_code: str = '',
                 scope: str = 'https://graph.microsoft.com/.default',
                 grant_type: str = CLIENT_CREDENTIALS,
                 redirect_uri: str = 'https://localhost/myapp',
                 resource: Optional[str] = '',
                 multi_resource: bool = False,
                 resources: List[str] = None,
                 verify: bool = True,
                 self_deployed: bool = False,
                 *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url, otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id, otherwise (oproxy) it's the auth id and may also
            contain the token url
            enc_key: If self deployed it's the client secret, otherwise (oproxy) it's the encryption key
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        if not self_deployed:
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # guardrails-disable-line
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.app_name = app_name
            self.auth_id = auth_id
            self.enc_key = enc_key
            self.tenant_id = tenant_id
            self.refresh_token = refresh_token

        else:
            self.token_retrieval_url = token_retrieval_url.format(tenant_id=tenant_id)
            self.client_id = auth_id
            self.client_secret = enc_key
            self.tenant_id = tenant_id
            self.auth_code = auth_code
            self.grant_type = grant_type
            self.resource = resource
            self.scope = scope
            self.redirect_uri = redirect_uri

        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE
        self.verify = verify

        self.multi_resource = multi_resource
        if self.multi_resource:
            self.resources = resources if resources else []
            self.resource_to_access_token: Dict[str, str] = {}

    def http_request(
            self, *args, resp_type='json', headers=None,
            return_empty_response=False, scope: Optional[str] = None,
            resource: str = '', **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently will work only with self-deployed app.
            resource (str): The resource identifier for which the generated token will have access to.
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        token = self.get_access_token(resource=resource, scope=scope)
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if headers:
            default_headers.update(headers)
        response = super()._http_request(   # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))
        is_response_empty_and_successful = (response.status_code == 204)
        if is_response_empty_and_successful and return_empty_response:
            return response

        try:
            if resp_type == 'json':
                return response.json()
            if resp_type == 'text':
                return response.text
            if resp_type == 'content':
                return response.content
            if resp_type == 'xml':
                ET.parse(response.text)
            return response
        except ValueError as exception:
            raise DemistoException('Failed to parse json object from response: {}'.format(response.content), exception)

    def get_access_token(self, resource: str = '', scope: Optional[str] = None) -> str:
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        Args:
            resource (str): The resource identifier for which the generated token will have access to.
            scope (str): A scope to get instead of the default on the API.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        refresh_token = integration_context.get('current_refresh_token', '')
        # Set keywords. Default without the scope prefix.
        access_token_keyword = f'{scope}_access_token' if scope else 'access_token'
        valid_until_keyword = f'{scope}_valid_until' if scope else 'valid_until'

        if self.multi_resource:
            access_token = integration_context.get(resource)
        else:
            access_token = integration_context.get(access_token_keyword)

        valid_until = integration_context.get(valid_until_keyword)

        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        auth_type = self.auth_type
        if auth_type == OPROXY_AUTH_TYPE:
            if self.multi_resource:
                for resource_str in self.resources:
                    access_token, expires_in, refresh_token = self._oproxy_authorize(resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(
                refresh_token, scope, integration_context)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update({
            access_token_keyword: access_token,
            valid_until_keyword: valid_until,
            'current_refresh_token': refresh_token
        })

        # Add resource access token mapping
        if self.multi_resource:
            integration_context.update(self.resource_to_access_token)

        set_integration_context(integration_context)

        if self.multi_resource:
            return self.resource_to_access_token[resource]

        return access_token

    def _oproxy_authorize(self, resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing with oproxy.
        Args:
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        content = self.refresh_token or self.tenant_id
        headers = self._add_info_headers()
        oproxy_response = requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key),
                'scope': scope
            },
            verify=self.verify
        )

        if not oproxy_response.ok:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    oproxy_response.status_code, oproxy_response.reason, oproxy_response.text))
                err_response = oproxy_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                    elif detail:
                        server_msg = detail
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = oproxy_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = oproxy_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Oproxy server did not contain the expected content.'
            )

        return (parsed_response.get('access_token', ''), parsed_response.get('expires_in', 3595),
                parsed_response.get('refresh_token', ''))

    def _get_self_deployed_token(self,
                                 refresh_token: str = '',
                                 scope: Optional[str] = None,
                                 integration_context: Optional[dict] = None
                                 ) -> Tuple[str, int, str]:
        if self.grant_type == AUTHORIZATION_CODE:
            if not self.multi_resource:
                return self._get_self_deployed_token_auth_code(refresh_token, scope=scope)
            else:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_auth_code(refresh_token,
                                                                                                      resource)
                    self.resource_to_access_token[resource] = access_token

                return '', expires_in, refresh_token
        elif self.grant_type == DEVICE_CODE:
            return self._get_token_device_code(refresh_token, scope, integration_context)
        else:
            # by default, grant_type is CLIENT_CREDENTIALS
            return self._get_self_deployed_token_client_credentials(scope=scope)

    def _get_self_deployed_token_client_credentials(self, scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.

        Args:
            scope; A scope to add to the headers. Else will get self.scope.

        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        # Set scope.
        if self.scope or scope:
            data['scope'] = scope if scope else self.scope

        if self.resource:
            data['resource'] = self.resource

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))

        return access_token, expires_in, ''

    def _get_self_deployed_token_auth_code(
            self, refresh_token: str = '', resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            resource=self.resource if not resource else resource,
            redirect_uri=self.redirect_uri
        )

        if scope:
            data['scope'] = scope

        refresh_token = refresh_token or self._get_refresh_token_from_auth_code_param()
        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = AUTHORIZATION_CODE
            data['code'] = self.auth_code

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_token_device_code(
            self, refresh_token: str = '', scope: Optional[str] = None, integration_context: Optional[dict] = None
    ) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.

        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = {
            'client_id': self.client_id,
            'scope': scope
        }

        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = DEVICE_CODE
            if integration_context:
                data['code'] = integration_context.get('device_code')

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_refresh_token_from_auth_code_param(self) -> str:
        refresh_prefix = "refresh_token:"
        if self.auth_code.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
            demisto.debug("Using refresh token set as auth_code")
            return self.auth_code[len(refresh_prefix):]
        return ''

    @staticmethod
    def error_parser(error: requests.Response) -> str:
        """

        Args:
            error (requests.Response): response with error

        Returns:
            str: string of error

        """
        try:
            response = error.json()
            demisto.error(str(response))
            inner_error = response.get('error', {})
            if isinstance(inner_error, dict):
                err_str = f"{inner_error.get('code')}: {inner_error.get('message')}"
            else:
                err_str = inner_error
            if err_str:
                return err_str
            # If no error message
            raise ValueError
        except ValueError:
            return error.text

    @staticmethod
    def epoch_seconds(d: datetime = None) -> int:
        """
        Return the number of seconds for given date. If no date, return current.

        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = MicrosoftClient._get_utcnow()
        return int((d - MicrosoftClient._get_utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utcfromtimestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    @staticmethod
    def get_encrypted(content: str, key: str) -> str:
        """
        Encrypts content with encryption key.
        Args:
            content: Content to encrypt
            key: encryption key from oproxy

from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
