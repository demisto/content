from CommonServerPython import *
from typing import Any
from datetime import datetime
import copy
import urllib3

from MicrosoftApiModule import *  # noqa: E402

APP_NAME = 'azure-key-vault'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
AUTHORIZATION_CODE = 'authorization_code'
VAULT_NAME_CONTEXT_FIELD = 'key_vault_name'

DEFAULT_LIMIT = 50
DEFAULT_OFFSET = 0


class KeyVaultClient:
    """
    Key Vault API Client
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 subscription_id: str, resource_group_name: str,
                 verify: bool, proxy: bool, certificate_thumbprint: Optional[str], private_key: Optional[str],
                 managed_identities_client_id: Optional[str] = None,
                 azure_cloud: Optional[AzureCloud] = None):
        self.azure_cloud = azure_cloud or AZURE_WORLDWIDE_CLOUD
        self.ms_client = MicrosoftClient(
            self_deployed=True,
            auth_id=client_id,
            enc_key=client_secret,
            token_retrieval_url=urljoin(self.azure_cloud.endpoints.active_directory, f'/{tenant_id}/oauth2/token'),
            app_name=APP_NAME,
            base_url=urljoin(self.azure_cloud.endpoints.resource_manager,
                             f'/subscriptions/{subscription_id}/resourceGroups/'
                             f'{resource_group_name}/providers/Microsoft.KeyVault'),
            verify=verify,
            proxy=proxy,
            multi_resource=True,
            resources=[self.get_management_resource(), self.get_vault_resource()],
            resource='',
            scope='',
            tenant_id=tenant_id,
            ok_codes=(200, 201, 202, 204, 400, 401, 403, 404),
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            managed_identities_client_id=managed_identities_client_id,
            command_prefix="azure-key-vault",
            azure_cloud=self.azure_cloud,
        )

    def get_vault_resource(self) -> str:
        return self.azure_cloud.endpoints.keyvault

    def get_management_resource(self) -> str:
        return self.azure_cloud.endpoints.resource_manager

    def http_request(self, method: str, url_suffix: str = None, full_url: str = None,
                     params: dict = None,
                     data: dict = None,
                     resource: Optional[str] = None, ok_codes: list = None):
        """
        Wrapper to MicrosoftClient http_request method.

        """
        resource = resource or self.get_management_resource()
        if not params:
            params = {}
        if 'api-version' not in params and full_url and 'api-version' not in full_url:
            params['api-version'] = '2022-07-01' if resource == self.get_management_resource() else '7.2'
        res = self.ms_client.http_request(method=method,
                                          url_suffix=url_suffix,
                                          full_url=full_url,
                                          json_data=data,
                                          params=params,
                                          resp_type='response',
                                          return_empty_response=True,
                                          resource=resource,
                                          timeout=20,
                                          ok_codes=ok_codes)

        if res.text:
            res_json = res.json()
        else:  # in case an empty response returned in delete key vault command
            res_json = {'status_code': res.status_code}

        return res_json

    """integration commands requests"""

    def create_or_update_key_vault_request(self, subscription_id: str, resource_group_name: str,
                                           vault_name: str, object_id: str, location: str,
                                           sku_name: str,
                                           keys_permissions: list[str], secrets_permissions: list[str],
                                           certificates_permissions: list[str], storage_accounts: list[str],
                                           enabled_for_deployment: bool,
                                           enabled_for_disk_encryption: bool,
                                           enabled_for_template_deployment: bool,
                                           default_action: str, bypass: str, vnet_subnet_id: str,
                                           ignore_missing_vnet_service_endpoint: bool,
                                           ip_rules: list[str]) -> dict[str, Any]:
        """
        Create or update a key vault in the specified subscription..

        Args:
            subscription_id (str): Subscription ID.
            resource_group_name (str): Resource group name.
            vault_name (str): Key Vault name.
            object_id (str): The object ID of a user, service principal or security group
                             in the Azure Active Directory.
            location (str): Key Vault supported Azure location.
            sku_name (str): Sku name.
            keys_permissions (List[str]): Permissions to keys.
            secrets_permissions (List[str]): Permissions to secrets.
            certificates_permissions (List[str]): Permissions to certificates.
            storage_accounts (List[str]): Permissions to storage accounts.
            enabled_for_deployment (bool): permission for Azure VM to retrieve certificates stored as secrets.
            enabled_for_disk_encryption (bool): permission for Azure Disk Encryption to retrieve secrets.
            enabled_for_template_deployment (bool): permission for Azure Resource Manager to retrieve secrets.
            default_action (str): The default action.
            bypass (str): bypass network rules.Network acl property.Default is 'AzureServices'.
            vnet_subnet_id (str): Full resource id of a vnet subnet.
            ignore_missing_vnet_service_endpoint (bool): NRP will ignore the check.
            ip_rules (List[str],optional) : The list of IP address rules.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        # permissions property

        permissions = self.config_vault_permission(
            keys_permissions, secrets_permissions, certificates_permissions, storage_accounts)

        # network property
        network_acl = self.config_vault_network_acls(default_action, bypass, vnet_subnet_id,
                                                     ignore_missing_vnet_service_endpoint, ip_rules)
        # private end point connection property

        properties = self.config_vault_properties(object_id, self.ms_client.tenant_id, enabled_for_deployment,
                                                  enabled_for_disk_encryption,
                                                  enabled_for_template_deployment, sku_name, permissions, network_acl)

        data = {"location": location, "properties": properties}

        full_url = urljoin(self.azure_cloud.endpoints.resource_manager, f'subscriptions/{subscription_id}/resourceGroups/'
                           f'{resource_group_name}/providers/Microsoft.KeyVault/vaults/{vault_name}')

        return self.http_request('PUT', full_url=full_url, data=data, ok_codes=[200, 201])

    def delete_key_vault_request(self, subscription_id: str, resource_group_name: str,
                                 vault_name: str) -> dict[str, Any]:
        """
        Delete Key Vault by name.

        Args:
            subscription_id (str): Subscription ID.
            resource_group_name (str): Resource group name.
            vault_name (str): Key Vault name.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        full_url = urljoin(self.azure_cloud.endpoints.resource_manager, f'subscriptions/{subscription_id}/resourceGroups/'
                           f'{resource_group_name}/providers/Microsoft.KeyVault/vaults/{vault_name}')

        return self.http_request('DELETE', full_url=full_url, ok_codes=[200, 204])

    def get_key_vault_request(self, subscription_id: str, resource_group_name: str,
                              vault_name: str) -> dict[str, Any]:
        """
        Retrieve Key Vault by name.

        Args:
            subscription_id (str): Subscription ID.
            resource_group_name (str): Resource group name.
            vault_name (str): Key Vault name.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        full_url = urljoin(self.azure_cloud.endpoints.resource_manager, f'subscriptions/{subscription_id}/resourceGroups/'
                           f'{resource_group_name}/providers/Microsoft.KeyVault/vaults/{vault_name}')
        return self.http_request('GET', full_url=full_url, ok_codes=[200])

    def list_key_vaults_request(self, subscription_id: str = None,
                                limit: int = DEFAULT_LIMIT, offset: int = DEFAULT_OFFSET) -> list[dict]:
        """
        List Key Vaults by limit and offset arguments from the specified resource group and subscription.

        Args:
            subscription_id (str): Subscription ID.
            limit(int): limit the number of key vaults to return.Default is 50.
            offset(int): First index to retrieve from. Default is 0.
        Returns:
            Dict[str, Any]: API response from Azure.
        """
        ful_url = urljoin(self.azure_cloud.endpoints.resource_manager,
                          f'subscriptions/{subscription_id}/providers/Microsoft.KeyVault/'
                          f'vaults?$top={limit}')
        response = self.http_request(
            'GET', full_url=ful_url, ok_codes=[200])
        return self.get_entities_independent_of_pages(response, limit, offset)

    def update_access_policy_request(self, subscription_id: str, resource_group_name: str,
                                     vault_name: str, operation_kind: str, object_id: str,
                                     keys: list[str], secrets: list[str], certificates: list[str],
                                     storage: list[str]) -> dict[str, Any]:
        """
        Update access policy of an existing Key Vault.

        Args:
            subscription_id (str): Subscription ID.
            resource_group_name (str): Resource group name.
            vault_name (str): Key Vault name.
            operation_kind (str): The operation to make on the access policy.
            object_id (str): The object ID of a user, service principal or security group in the Azure Active Directory.
            keys (List[str]): Permissions to keys.
            secrets (List[str]): Permissions to secrets.
            certificates (List[str]): Permissions to certificates.
            storage (List[str]): Permissions to storage accounts.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        permissions = self.config_vault_permission(
            keys, secrets, certificates, storage)
        data = {"properties": {"accessPolicies": [
            {"objectId": object_id, "permissions": permissions, "tenantId": self.ms_client.tenant_id}]}}
        full_url = urljoin(self.azure_cloud.endpoints.resource_manager, f'subscriptions/{subscription_id}/resourceGroups/'
                           f'{resource_group_name}/providers/Microsoft.KeyVault/vaults/'
                           f'{vault_name}/accessPolicies/{operation_kind}')

        return self.http_request('PUT', full_url=full_url, data=data, ok_codes=[200, 201])

    def get_key_request(self, vault_name: str, key_name: str, key_version: str) -> dict[str, Any]:
        """
        Get the public part of a stored key.

        Args:
            vault_name (str): Key Vault name.
            key_name (str): Key name.
            key_version (str): Key version.

        Returns:
            Dict[str, Any]: API response from Azure.
        """

        url = f'https://{vault_name}{self.azure_cloud.suffixes.keyvault_dns}/keys/{key_name}'
        if key_version:
            url = url + f'/{key_version}'
        response = self.http_request(
            'GET', full_url=url, resource=self.get_vault_resource())

        return response

    def list_keys_request(self, vault_name: str, limit: int, offset: int) -> list[dict]:
        """ List keys in the specified Key Vault.

        Args:
            vault_name(str): Key Vault name.
            limit (str): Limit on the number of certificates to return. Default value is 50.
            offset(int): First index to retrieve from. Default value is 0.

        Returns:
            Dict[str, Any]: API response from Azure.

        """
        url = f'https://{vault_name}{self.azure_cloud.suffixes.keyvault_dns}/keys'
        response = self.http_request(
            'GET', full_url=url, resource=self.get_vault_resource(), ok_codes=[200])

        return self.get_entities_independent_of_pages(response, limit, offset, self.get_vault_resource())

    def delete_key_request(self, vault_name: str, key_name: str) -> dict[str, Any]:
        """
        Delete a key of any type from storage in Azure Key vault.

        Args:
            vault_name (str): key vault's name.
            key_name (str): The name of the key to delete.

        Returns:
            Dict[str, Any]: response json
        """
        url = f'https://{vault_name}{self.azure_cloud.suffixes.keyvault_dns}/keys/{key_name}'
        response = self.http_request(
            'DELETE', full_url=url, resource=self.get_vault_resource())

        return response

    def get_secret_request(self, vault_name: str, secret_name: str, secret_version: str) -> dict[str, Any]:
        """
        Retrieve secret by name from the specified key vault.

        Args:
            vault_name (str): Key vault's name.
            secret_name (str): The name of the secret to retrieve.
            secret_version (str) : The version of the secret.
        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = f'https://{vault_name}{self.azure_cloud.suffixes.keyvault_dns}/secrets/{secret_name}'
        if secret_version:
            url = url + f'/{secret_version}'
        response = self.http_request(
            'GET', full_url=url, resource=self.get_vault_resource())

        return response

    def list_secrets_request(self, vault_name: str, limit: int, offset: int) -> list[dict]:
        """
        List secrets by limit and offset from the specified Key Vault.

        Args:
            vault_name (str): Key Vault name.
            limit(int): Maximum number of secrets to retrieve.Default is 50.
            offset(int): First index to retrieve from. Default value is 0.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = f'https://{vault_name}{self.azure_cloud.suffixes.keyvault_dns}/secrets'
        response = self.http_request(
            'GET', full_url=url, resource=self.get_vault_resource())

        return self.get_entities_independent_of_pages(response, limit, offset, self.get_vault_resource())

    def delete_secret_request(self, vault_name: str, secret_name: str) -> dict[str, Any]:
        """
        Delete a secret by name from the specified Key Vault.

        Args:
            vault_name (str): Key vault's name.
            secret_name (str): The name of the secret to delete.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = f'https://{vault_name}{self.azure_cloud.suffixes.keyvault_dns}/secrets/{secret_name}'
        response = self.http_request(
            'DELETE', full_url=url, resource=self.get_vault_resource())
        return response

    def get_certificate_request(self, vault_name: str,
                                certificate_name: str,
                                certificate_version: str) -> dict[str, Any]:
        """
        Retrieve certificate from the specified Key Vault.

        Args:
            vault_name (str): key vault's name.
            certificate_name (str): the name of the certificate to retrieve.
            certificate_version(str): The version of the certificate
        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = f'https://{vault_name}{self.azure_cloud.suffixes.keyvault_dns}/certificates/{certificate_name}'
        if certificate_version:
            url = url + f'/{certificate_version}'
        response = self.http_request(
            'GET', full_url=url,
            resource=self.get_vault_resource())

        return response

    def list_certificates_request(self, vault_name: str, limit: int, offset: int) -> list[dict]:
        """
        List certificates from the specified Key Vault.

        Args:
            vault_name (str): Key Vault name of the certificate.
            limit(int):maximum number of certificates to retrieve. Default is 50.
            offset (int): First index to retrieve from. Default value is 0.

        Returns:
            Dict[str, Any]: response json
        """
        url = f'https://{vault_name}{self.azure_cloud.suffixes.keyvault_dns}/certificates'

        response = self.http_request(
            'GET', full_url=url, resource=self.get_vault_resource())

        return self.get_entities_independent_of_pages(response, limit, offset, self.get_vault_resource())

    def get_certificate_policy_request(self, vault_name: str, certificate_name: str) -> dict[str, Any]:
        """
        Retrieve policy of the specified certificate.

        Args:
            vault_name (str): Key Vault name.
            certificate_name (str): the name of the certificate to retrieve its policy.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = f'https://{vault_name}{self.azure_cloud.suffixes.keyvault_dns}/certificates/{certificate_name}/policy'
        response = self.http_request(
            'GET', full_url=url, resource=self.get_vault_resource())

        return response

    def list_subscriptions_request(self):
        """
        List all subscriptions.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        url = urljoin(self.azure_cloud.endpoints.resource_manager, 'subscriptions?')
        response = self.http_request('GET', full_url=url, resource=self.get_management_resource(),
                                     params={'api-version': '2020-01-01'})
        return self.get_entities_independent_of_pages(first_page=response, limit=DEFAULT_LIMIT, offset=DEFAULT_OFFSET,
                                                      resource=self.get_management_resource())

    def list_resource_groups_request(self, subscription_id: str, tag: str, limit: int) -> list[dict]:
        """
        List all resource groups.

        Args:
            subscription_id (str): Subscription ID.
            tag str: Tag to filter by.
            limit (int): Maximum number of resource groups to retrieve. Default is 50.

        Returns:
            List[dict]: API response from Azure.
        """
        full_url = urljoin(self.azure_cloud.endpoints.resource_manager, f'subscriptions/{subscription_id}/resourcegroups?')
        filter_by_tag = azure_tag_formatter(tag) if tag else None

        response = self.http_request('GET', full_url=full_url, resource=self.get_management_resource(),
                                     params={'$filter': filter_by_tag, '$top': limit,
                                             'api-version': '2021-04-01'}, ok_codes=[200])
        return self.get_entities_independent_of_pages(first_page=response, limit=limit, offset=DEFAULT_OFFSET,
                                                      resource=self.get_management_resource())

    ''' INTEGRATION HELPER METHODS  '''

    def config_vault_permission(self, keys: list[str], secrets: list[str], certificates: list[str],
                                storage: list[str]) -> dict[str, Any]:
        """
        Returns the permissions field of an access policy property of a Key Vault.

        Args:
            keys (List[str]): Permissions to keys.
            secrets (List[str]): Permissions to secrets.
            certificates (List[str]): Permissions to certificates.
            storage (List[str]): Permissions to storage accounts.

        Returns:
            Dict[str,Any]: permissions.
        """
        permissions = {}
        if keys:
            permissions['keys'] = keys
        if secrets:
            permissions['secrets'] = secrets
        if certificates:
            permissions['certificates'] = certificates
        if storage:
            permissions['storage'] = storage
        return permissions

    def config_vault_network_acls(self, default_action: str, bypass: str, vnet_sub_id: str,
                                  ignore_missing_vnet_service_endpoint: bool,
                                  ip_rules: list[str]) -> dict[str, Any]:
        """
        Configure the network acl property of a Key Vault.

        Args:
            default_action (str): Default action.
            bypass (str): Tells what traffic can bypass network rules.
            vnet_sub_id (str): Full resource id of a vnet subnet.
            ignore_missing_vnet_service_endpoint (bool): Specify whether NRP will ignore the check.
            ip_rules (List[str]):The list of IP address rules.

        Returns:
            Dict[str,Any]: Network acls property.
        """
        network_acls: dict[str, Any] = {}
        if default_action:
            network_acls['defaultAction'] = default_action
        if bypass:
            network_acls['bypass'] = bypass
        if vnet_sub_id:
            network_acls['virtualNetworkRules'] = [{'id': vnet_sub_id,
                                                    'ignoreMissingVnetServiceEndpoint':
                                                        ignore_missing_vnet_service_endpoint}]

        if ip_rules:
            network_acls["ipRules"] = []
            for ip in ip_rules:
                network_acls["ipRules"].append({'value': ip})

        return network_acls

    def config_vault_properties(self, object_id: str, tenant_id: str, enabled_for_deployment: bool,
                                enabled_for_disk_encryption: bool,
                                enabled_for_template_deployment: bool, sku_name: str,
                                permissions: dict[str, Any], network_acls: dict[str, Any]):
        """
        Configure the properties of a vault on create or update command.

        Args:
            object_id (str): The object ID of a user, service principal or security group in the Azure Active Directory.
            tenant_id (str):An identity that have access to the key vault.
            enabled_for_deployment (bool): permission for Azure VM to retrieve certificates stored as secrets.
            enabled_for_disk_encryption (bool): permission for Azure Disk Encryption to retrieve secrets.
            enabled_for_template_deployment (bool): permission for Azure Resource Manager to retrieve secrets.
            sku_name (str):Sku name.
            permissions (Dict[str,Any]): Key Vault access policy property.
            network_acls (Dict[str,Any]): Key Vault network acls property.

        Returns:
            Dict[str,Any]: Key Vault properties.
        """
        properties = {"accessPolicies": [
            {"objectId": object_id, "permissions": permissions,
             "tenantId": tenant_id}],
            "enabledForDeployment": enabled_for_deployment,
            "enabledForDiskEncryption": enabled_for_disk_encryption,
            "enabledForTemplateDeployment": enabled_for_template_deployment,
            "sku": {"family": "A", "name": sku_name}, "tenantId": tenant_id}

        if network_acls:
            properties["networkAcls"] = network_acls

        return properties

    def get_entities_independent_of_pages(self, first_page: dict[str, Any], limit: int, offset: int,
                                          resource: Optional[str] = None) -> list[dict]:
        """
        List the entities according to the offset and limit arguments,
        following the first API call to the endpoint.
        The main purpose here is to list the entities regardless the
        restriction of the first API call - which returns only 25 entities at most.
        Used only for list commands.

        Args:
            first_page (Dict[str, Any]): The first list of entities which returned by the first API call.
            limit (int): limit on the number of entities to retrieve to the user.
            offset (int): first index to return from.
            resource (str | None): Azure resource. Default's to management resource.

        Returns:
            List[dict]: List of Key Vaults/Keys/Secrets/Certificates.
        """
        resource = resource or self.get_management_resource()
        entities = first_page.get('value', [])
        next_page_url = first_page.get('nextLink')
        # more entities to get
        while next_page_url and len(entities) < offset + limit:
            response = self.http_request(
                'GET', full_url=next_page_url, resource=resource)

            entities = entities + response.get('value', [])
            next_page_url = response.get('nextLink')
        if offset > len(entities):
            return []
        return entities[offset:limit + offset]

    def get_secret_credentials(self, key_vault_name: str, secret_name: str):
        try:
            response = self.get_secret_request(key_vault_name, secret_name, '')
            secret_value = response['value']
            return {
                "user": secret_name,
                "password": secret_value,
                "name": f'{key_vault_name}/{secret_name}'
            }
        except Exception:  # in case the secret does not exist in the vault
            return None


''' INTEGRATIONS COMMANDS'''


def create_or_update_key_vault_command(client: KeyVaultClient, args: dict[str, Any],
                                       params: dict[str, Any]) -> CommandResults:
    """
    Create or update Key Vault in the specified subscription.

    Args:
        client (KeyVaultClient):Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
        params (Dict[str, Any]): Configuration parameters from XSOAR.

    Returns:
       CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    vault_name = args['vault_name']
    object_id = args['object_id']

    location = args.get('location', 'westus')
    sku_name = args.get('sku_name', 'standard')

    # access policy arguments
    keys_permissions = argToList(args.get('keys', ['get', 'list', 'update', 'create', 'import',
                                                   'delete', 'recover', 'backup', 'restore']))

    secrets_permissions = argToList(args.get('secrets', ['get', 'list', 'set', 'delete', 'recover',
                                                         'backup', 'restore']))
    certificates_permissions = argToList(
        args.get('certificates', ['get', 'list', 'update', 'create', 'import', 'delete', 'recover',
                                  'backup', 'restore',
                                  'managecontacts', 'manageissuers', 'getissuers', 'listissuers',
                                  'setissuers', 'deleteissuers']))

    storage_accounts_permissions = argToList(
        args.get('storage', ['get', 'list', 'delete', 'set',
                             'update', 'regeneratekey',
                             'getsas', 'listsas']))

    enabled_for_deployment = argToBoolean(
        args.get('enabled_for_deployment', True))
    enabled_for_disk_encryption = argToBoolean(
        args.get('enabled_for_disk_encryption', True))
    enabled_for_template_deployment = argToBoolean(args.get(
        'enabled_for_template_deployment', True))

    # network acl arguments
    default_action = args.get('default_action', '')
    bypass = args.get('bypass', '')
    vnet_subnet_id = args.get('vnet_subnet_id', '')
    ignore_missing_vnet_service_endpoint = argToBoolean(
        args.get('ignore_missing_vnet_service_endpoint', True))
    ip_rules = argToList(args.get('ip_rules'))
    # subscription_id and resource_group_name arguments can be passed as command arguments or as configuration parameters,
    # if both are passed as arguments, the command arguments will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    resource_group_name = get_from_args_or_params(params=params, args=args, key='resource_group_name')

    response = client.create_or_update_key_vault_request(subscription_id, resource_group_name,
                                                         vault_name, object_id, location, sku_name, keys_permissions,
                                                         secrets_permissions, certificates_permissions,
                                                         storage_accounts_permissions, enabled_for_deployment,
                                                         enabled_for_disk_encryption, enabled_for_template_deployment,
                                                         default_action, bypass, vnet_subnet_id,
                                                         ignore_missing_vnet_service_endpoint, ip_rules)

    readable_output = tableToMarkdown(f'{vault_name} Information',
                                      response,
                                      ['id', 'name', 'type', 'location'], removeNull=True,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='AzureKeyVault.KeyVault',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )


def delete_key_vault_command(client: KeyVaultClient, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    """
    Delete Key Vault by name.

    Args:
        client (KeyVaultClient):Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
        params (Dict[str, Any]): Configuration parameters from XSOAR.
    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """

    vault_name = args['vault_name']
    # subscription_id and resource_group_name arguments can be passed as command arguments or as configuration parameters,
    # if both are passed as arguments, the command arguments will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    resource_group_name = get_from_args_or_params(params=params,
                                                  args=args, key='resource_group_name')

    response = client.delete_key_vault_request(subscription_id=subscription_id,
                                               resource_group_name=resource_group_name,
                                               vault_name=vault_name)
    message = ""
    if response.get('status_code') == 200:
        message = f'Deleted Key Vault {vault_name} successfully.'
    elif response.get('status_code') == 204:
        message = f'Key Vault {vault_name} does not exists.'

    return CommandResults(
        readable_output=message
    )


def get_key_vault_command(client: KeyVaultClient, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    """
    Retrieve Key Vault by name.

    Args:
        client (KeyVaultClient):Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
        params (Dict[str, Any]): Configuration parameters from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    vault_name = args['vault_name']
    # subscription_id and resource_group_name arguments can be passed as command arguments or as configuration parameters,
    # if both are passed as arguments, the command arguments will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    resource_group_name = get_from_args_or_params(params=params, args=args, key='resource_group_name')
    response = client.get_key_vault_request(subscription_id=subscription_id,
                                            resource_group_name=resource_group_name,
                                            vault_name=vault_name)

    readable_output = tableToMarkdown(f'{vault_name} Information',
                                      response,
                                      ['id', 'name', 'type', 'location'], removeNull=True,
                                      headerTransform=string_to_table_header)
    return CommandResults(
        outputs_prefix='AzureKeyVault.KeyVault',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )


def list_key_vaults_command(client: KeyVaultClient, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    """ List Key Vaults associated with the subscription and within the specified resource group.

    Args:
        client (KeyVaultClient):Azure Key Vault API client
        args (Dict[str, Any]): Command arguments from XSOAR.
        params (Dict[str, Any]): Configuration parameters from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    offset = arg_to_number(args.get('offset')) or DEFAULT_OFFSET
    # subscription_id can be passed as a command argument or as a configuration parameter.
    # If both are passed, the command argument is used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    response = client.list_key_vaults_request(subscription_id=subscription_id,
                                              limit=limit, offset=offset)

    readable_output = tableToMarkdown(
        'Key Vaults List',
        response,
        ['id', 'name', 'type', 'location'], removeNull=True,
        headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.KeyVault',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True)

    return command_results


def update_access_policy_command(client: KeyVaultClient, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    """
    Updates access policy of a key vault in the specified subscription.

    Args:
        client (KeyVaultClient):Azure Key Vault API client
        args (Dict[str, Any]): Command arguments from XSOAR.
        params (Dict[str, Any]): Configuration parameters from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    vault_name = args['vault_name']
    operation_kind = args['operation_kind']
    object_id = args['object_id']
    keys = argToList(args.get('keys'))
    secrets = argToList(args.get('secrets'))
    certificates = argToList(args.get('certificates'))
    storage_accounts = argToList(args.get('storage', []))
    # subscription_id and resource_group_name arguments can be passed as command arguments or as configuration parameters,
    # if both are passed as arguments, the command arguments will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    resource_group_name = get_from_args_or_params(params=params, args=args, key='resource_group_name')

    response = client.update_access_policy_request(subscription_id, resource_group_name,
                                                   vault_name, operation_kind, object_id, keys,
                                                   secrets, certificates, storage_accounts)

    readable_output = tableToMarkdown(f'{vault_name} Updated Access Policy',
                                      response,
                                      ['id', 'name', 'type', 'location'], removeNull=True,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='AzureKeyVault.VaultAccessPolicy',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )


def get_key_command(client: KeyVaultClient, args: dict[str, Any]) -> CommandResults:
    """ Get the public part of a stored key.

    Args:
        client (KeyVaultClient): Azure Key Vault API client
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args['vault_name']
    key_name = args['key_name']
    key_version = args.get('key_version', '')

    response = client.get_key_request(vault_name, key_name, key_version)
    cloned_response = copy.deepcopy(response)
    outputs = copy.deepcopy(response)
    outputs['attributes'] = convert_time_attributes_to_iso(outputs['attributes'])
    outputs['key_vault_name'] = vault_name

    readable_key_info = convert_key_info_to_readable(cloned_response['key'])
    readable_attrib = convert_attributes_to_readable(cloned_response['attributes'])

    readable_output = tableToMarkdown(f'{key_name} Information',
                                      {**readable_key_info, **readable_attrib},
                                      ['key_id', 'enabled', 'json_web_key_type', 'key_operations', 'create_time',
                                       'update_time',
                                       'expiry_time'],
                                      removeNull=True,
                                      headerTransform=string_to_table_header)

    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Key',
        outputs_key_field='kid',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def list_keys_command(client: KeyVaultClient, args: dict[str, Any]) -> CommandResults:
    """
    List keys in the specified vault, in XSOAR's format, according to limit and offset arguments.

    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args['vault_name']
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    offset = arg_to_number(args.get('offset')) or DEFAULT_OFFSET
    response = client.list_keys_request(vault_name, limit, offset)
    outputs = copy.deepcopy(response)
    readable_response = []

    for key in outputs:
        readable_response.append({
            'key_id': key.get('kid'),
            'managed': key.get('managed'),
            **convert_attributes_to_readable(key.get('attributes', {}).copy()),
        })
        key[VAULT_NAME_CONTEXT_FIELD] = vault_name
        key['attributes'] = convert_time_attributes_to_iso(key['attributes'])

    readable_output = tableToMarkdown(
        f'{vault_name} Keys List',
        readable_response,
        ['key_id', 'enabled', 'create_time', 'update_time', 'expiry_time'],
        removeNull=True,
        headerTransform=string_to_table_header)

    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Key',
        outputs_key_field='kid',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def delete_key_command(client: KeyVaultClient, args: dict[str, Any]) -> CommandResults:
    """
    Delete a key of any type from storage in Azure Key vault.

    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args['vault_name']
    key_name = args['key_name']
    response = client.delete_key_request(vault_name, key_name)

    outputs = copy.deepcopy(response)
    outputs['deletedDate'] = convert_timestamp_to_readable_date(
        outputs['deletedDate'])
    outputs['scheduledPurgeDate'] = convert_timestamp_to_readable_date(
        outputs['scheduledPurgeDate'])

    readable_response = copy.deepcopy(outputs)
    readable_response['keyId'] = readable_response['key']['kid']

    outputs['attributes'] = convert_time_attributes_to_iso(outputs['attributes'])
    outputs[VAULT_NAME_CONTEXT_FIELD] = vault_name

    readable_output = tableToMarkdown(f'Delete {key_name}',
                                      readable_response,
                                      ['keyId', 'recoveryId', 'deletedDate',
                                       'scheduledPurgeDate'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Key',
        outputs_key_field='recoveryId',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def get_secret_command(client: KeyVaultClient, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve secret from the specified Key Vault

    Args:
        client (KeyVaultClient):  Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args['vault_name']
    secret_name = args['secret_name']
    secret_version = args.get('secret_version', '')
    response = client.get_secret_request(
        vault_name, secret_name, secret_version)
    outputs = copy.deepcopy(response)
    outputs['attributes'] = convert_time_attributes_to_iso(outputs['attributes'])
    readable_response = {'secret_id': response.get('id'), 'managed': response.get('managed'),
                         'key_id': response.get('kid'),
                         **convert_attributes_to_readable(response.get('attributes', {}).copy())}
    outputs[VAULT_NAME_CONTEXT_FIELD] = vault_name

    readable_output = tableToMarkdown(f'{secret_name} Information',
                                      readable_response,
                                      ['secret_id', 'enabled', 'create_time', 'update_time', 'expiry_time'],
                                      removeNull=True,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Secret',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def list_secrets_command(client: KeyVaultClient, args: dict[str, Any]) -> CommandResults:
    """
    List secrets in the specified key vault.

    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args['vault_name']
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    offset = arg_to_number(args.get('offset')) or DEFAULT_OFFSET
    response = client.list_secrets_request(vault_name, limit, offset)
    outputs = copy.deepcopy(response)
    readable_response = []

    for secret in outputs:
        readable_response.append({
            'secret_id': secret.get('id'), 'managed': secret.get('managed'),
            **convert_attributes_to_readable(secret.get('attributes', {}).copy())
        })
        secret[VAULT_NAME_CONTEXT_FIELD] = vault_name
        secret['attributes'] = convert_time_attributes_to_iso(secret['attributes'])

    readable_output = tableToMarkdown(
        f'{vault_name} Secrets List',
        readable_response,
        ['secret_id', 'enabled', 'create_time', 'update_time', 'expiry_time'], removeNull=True,
        headerTransform=string_to_table_header)

    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Secret',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def delete_secret_command(client: KeyVaultClient, args: dict[str, Any]) -> CommandResults:
    """
    Delete secret from the specified Key Vault.

    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args['vault_name']
    secret_name = args['secret_name']

    response = client.delete_secret_request(vault_name, secret_name)

    outputs = copy.deepcopy(response)
    outputs['deletedDate'] = convert_timestamp_to_readable_date(
        outputs['deletedDate'])
    outputs['scheduledPurgeDate'] = convert_timestamp_to_readable_date(
        outputs['scheduledPurgeDate'])

    readable_response = copy.deepcopy(outputs)
    outputs['attributes'] = convert_time_attributes_to_iso(outputs['attributes'])
    outputs[VAULT_NAME_CONTEXT_FIELD] = vault_name

    readable_response['secretId'] = readable_response.pop('id')
    readable_output = tableToMarkdown(f'Delete {secret_name}',
                                      readable_response,
                                      ['secretId', 'recoveryId', 'deletedDate',
                                       'scheduledPurgeDate'], removeNull=True,
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Secret',
        outputs_key_field='recoveryId',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def get_certificate_command(client: KeyVaultClient, args: dict[str, Any]) -> CommandResults:
    """
    Get information about a certificate.

    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args.get('vault_name', '')
    certificate_name = args.get('certificate_name', '')
    certificate_version = args.get('certificate_version', '')
    response = client.get_certificate_request(
        vault_name, certificate_name, certificate_version)

    outputs = copy.deepcopy(response)
    outputs['attributes'] = convert_time_attributes_to_iso(outputs['attributes'])
    outputs['policy']['attributes'] = convert_time_attributes_to_iso(outputs['policy']['attributes'])

    readable_response = {'certificate_id': response.get(
        'id'), **convert_attributes_to_readable(response.get('attributes', {}).copy())}
    outputs[VAULT_NAME_CONTEXT_FIELD] = vault_name

    readable_output = tableToMarkdown(f'{certificate_name} Information',
                                      readable_response,
                                      ['certificate_id', 'enabled', 'create_time', 'update_time', 'expiry_time'],
                                      removeNull=True,
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Certificate',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def list_certificates_command(client: KeyVaultClient, args: dict[str, Any]) -> CommandResults:
    """
    List certificates in the specified Key Vault.

    Args:
        client (KeyVaultClient): Azure Key Vault API client.
        args (Dict[str, Any]): Command arguments from XSOAR.


    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args['vault_name']
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    offset = arg_to_number(args.get('offset')) or DEFAULT_OFFSET

    response = client.list_certificates_request(vault_name, limit, offset)
    outputs = copy.deepcopy(response)

    readable_response = []
    for certificate in outputs:
        readable_response.append({
            'certificate_id': certificate.get('id'),
            **convert_attributes_to_readable(certificate.get('attributes', {}).copy())
        })
        certificate[VAULT_NAME_CONTEXT_FIELD] = vault_name
        certificate['attributes'] = convert_time_attributes_to_iso(certificate['attributes'])

    readable_output = tableToMarkdown(
        f'{vault_name} Certificates List',
        readable_response,
        ['certificate_id', 'enabled', 'create_time', 'update_time', 'expiry_time'],
        removeNull=True,
        headerTransform=string_to_table_header)

    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.Certificate',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True
    )

    return command_results


def get_certificate_policy_command(client: KeyVaultClient, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve policy of the specified certificate.

    Args:
        client (KeyVaultClient):  Azure Key Vault API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    vault_name = args['vault_name']
    certificate_name = args['certificate_name']
    response = client.get_certificate_policy_request(
        vault_name, certificate_name)
    outputs = copy.deepcopy(response)
    outputs['attributes'] = convert_time_attributes_to_iso(outputs['attributes'])
    outputs['CertificateName'] = certificate_name

    readable_output = tableToMarkdown(f'{certificate_name} Policy Information',
                                      outputs,
                                      ['id', 'key_props', 'secret_props',
                                       'x509_props', 'issuer', 'attributes'],
                                      removeNull=True, headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='AzureKeyVault.CertificatePolicy',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output
    )

    return command_results


def list_subscriptions_command(client: KeyVaultClient) -> CommandResults:
    """
    List all subscriptions in the tenant.

    Args:
        client (KeyVaultClient):  Azure Key Vault API client.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    response = client.list_subscriptions_request()

    readable_output = tableToMarkdown('Subscriptions List',
                                      response,
                                      ['subscriptionId', 'tenantId',
                                       'state', 'displayName'
                                       ],
                                      removeNull=True, headerTransform=string_to_table_header)
    return CommandResults(
        outputs_prefix='AzureKeyVault.Subscription',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
    )


def list_resource_groups_command(client: KeyVaultClient, args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
    """
    List all resource groups in the subscription.

    Args:
        client (KeyVaultClient):  Azure Key Vault API client.
        args (Dict[str, Any]): command arguments.
        params (Dict[str, Any]): configuration parameters.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    tag = args.get('tag', '')
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    # subscription_id can be passed as a command argument or as a configuration parameter.
    # If both are passed, the command argument is used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')

    response = client.list_resource_groups_request(subscription_id=subscription_id, tag=tag, limit=limit)

    readable_output = tableToMarkdown('Resource Groups List',
                                      response,
                                      ['name', 'location', 'tags',
                                       'properties.provisioningState'
                                       ],
                                      removeNull=True, headerTransform=string_to_table_header)
    return CommandResults(
        outputs_prefix='AzureKeyVault.ResourceGroup',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
    )


def test_module(client: KeyVaultClient, params: dict[str, Any]) -> None:
    """
     Test instance parameters validity.
     Displays an appropriate message in case of invalid parameters.

     Args:
         client (KeyVaultClient):  Azure Key Vault API client.
         params (Dict[str, Any]): configuration parameters.

     Returns:
         None
     """
    try:
        subscription_id = params.get('subscription_id')
        client.ms_client.get_access_token(resource=client.get_management_resource())
        client.ms_client.get_access_token(resource=client.get_vault_resource())
        client.list_key_vaults_request(subscription_id=subscription_id, limit=1, offset=0)
        return_results('ok')

    except Exception:
        raise


def fetch_credentials(client: KeyVaultClient,
                      key_vaults_to_fetch_from: list[str],
                      secrets_to_fetch: list[str], credentials_name: str) -> None:
    """
     Fetch credentials from secrets which reside in the specified Key Vaults list.
     This command supports two scenarios:
     1. Fetch a specific set of credentials: assuming that the credentials name is written
        in the format of: KEY_VAULT_NAME/SECRET_NAME
     2. Fetch credentials based on instance parameters: key_vaults list and secret list.
     Args:
         client (KeyVaultClient):  Azure Key Vault API client.
         key_vaults_to_fetch_from (List[str]): List of Key Vaults to fetch secrets from.
         secrets_to_fetch (List[str]): List of secrets to fetch.
         credentials_name (str): Name of a specific set of credentials to fetch.

     Returns:
         None
     """
    credentials = []

    if credentials_name:
        credentials_name_arr = credentials_name.split("/")
        key_vault = credentials_name_arr[0]
        secret = credentials_name_arr[1]
        credentials = [client.get_secret_credentials(key_vault, secret)]

    else:
        if len(key_vaults_to_fetch_from) == 0:
            return_results('No key vaults to fetch secrets from were specified.')
        if len(secrets_to_fetch) == 0:
            return_results('No secrets were specified.')
        for key_vault in key_vaults_to_fetch_from:
            for secret in secrets_to_fetch:
                secret_cred = client.get_secret_credentials(key_vault, secret)
                credentials += [secret_cred] if secret_cred else []

    demisto.credentials(credentials)


def convert_attributes_to_readable(attributes: dict[str, Any]) -> dict[str, Any]:
    """
    Convert attributes fields to be readable for the user.

    Args:
        attributes (Dict[str, Any]): Object attributes field.

    Returns:
        Dict[str, Any] : Readable attributes.

    """
    attributes_fields_mapper = {'nbf': 'should_not_be_retrieved_Before',
                                'exp': 'expiry_time',
                                'created': 'create_time',
                                'updated': 'update_time',
                                'recoveryLevel': 'recovery_level'
                                }

    for key, value in attributes_fields_mapper.items():
        if key in attributes:
            if key != 'recoveryLevel':
                attributes[value] = convert_timestamp_to_readable_date(attributes.pop(key))
            else:
                attributes[value] = attributes.pop(key)
    return attributes


def convert_key_info_to_readable(key_info: dict[str, Any]) -> dict[str, Any]:
    """
    Convert key fields to be readable for the user.

    Args:
        key_info (Dict[str, Any]): key field of Key object.

    Returns:
        Dict[str, Any] : Readable key information.

    """
    key_fields = {'kid': 'key_id',
                  'kty': 'json_web_key_type',
                  'key_ops': 'key_operations',
                  'n': 'RSA_modulus',
                  'e': 'RSA_public_components',
                  }
    for key, value in key_fields.items():
        if key in key_info:
            key_info[value] = key_info.pop(key)

    return key_info


def convert_time_attributes_to_iso(attributes: dict[str, Any]) -> dict[str, Any]:
    """
    Convert attributes fields to be readable for the user.

    Args:
        attributes (Dict[str, Any]): Object attributes field.

    Returns:
        Dict[str, Any] : attributes property with time fields in ISO 8601 format.

    """
    time_attributes_fields = {'nbf',
                              'exp',
                              'created',
                              'updated',
                              }

    for field in attributes:
        if field in time_attributes_fields:
            attributes[field] = convert_timestamp_to_readable_date(attributes[field])

    return attributes


def convert_timestamp_to_readable_date(timestamp: int) -> str:
    """
    Convert timestamp number to readable date.
    Args:
        timestamp (Dict[str, Any]): timestamp as integer.

    Returns:
        str : Date in ISO 8601 format.
    """
    return datetime.utcfromtimestamp(timestamp).isoformat()


def main() -> None:     # pragma: no cover
    params: dict[str, Any] = demisto.params() or {}
    args: dict[str, Any] = demisto.args() or {}
    key_vaults_to_fetch_from = argToList(params.get('key_vaults', []))
    secrets_to_fetch = argToList(params.get('secrets', []))
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    identifier = args.get('identifier', '')
    azure_cloud = get_azure_cloud(params, "AzureKeyVault")
    managed_identities_client_id = get_azure_managed_identities_client_id(params)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client_secret = params.get('credentials', {}).get('password', '')
        certificate_thumbprint = params.get('credentials_certificate_thumbprint', {}).get(
            'password') or params.get('certificate_thumbprint')
        private_key = params.get('private_key')
        if not managed_identities_client_id and not client_secret and not (certificate_thumbprint and private_key):
            raise DemistoException('Client Secret or Certificate Thumbprint and Private Key must be provided. For further information see https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')  # noqa: E501

        urllib3.disable_warnings()
        client: KeyVaultClient = KeyVaultClient(tenant_id=params.get('tenant_id', None),
                                                client_id=params.get(
                                                    'client_id', None),
                                                client_secret=client_secret,
                                                subscription_id=params.get(
                                                    'subscription_id', None),
                                                resource_group_name=params.get(
                                                    'resource_group_name', None),
                                                verify=verify_certificate,
                                                proxy=proxy,
                                                certificate_thumbprint=certificate_thumbprint,
                                                private_key=private_key,
                                                managed_identities_client_id=managed_identities_client_id,
                                                azure_cloud=azure_cloud,
                                                )

        commands_with_args = {
            'azure-key-vault-key-get': get_key_command,
            'azure-key-vault-key-list': list_keys_command,
            'azure-key-vault-key-delete': delete_key_command,
            'azure-key-vault-secret-get': get_secret_command,
            'azure-key-vault-secret-list': list_secrets_command,
            'azure-key-vault-secret-delete': delete_secret_command,
            'azure-key-vault-certificate-get': get_certificate_command,
            'azure-key-vault-certificate-list': list_certificates_command,
            'azure-key-vault-certificate-policy-get': get_certificate_policy_command,
        }
        commands_without_args = {'azure-key-vault-subscriptions-list': list_subscriptions_command}

        commands_with_params = {'test-module': test_module}

        commands_with_args_and_params = {
            'azure-key-vault-create-update': create_or_update_key_vault_command,
            'azure-key-vault-delete': delete_key_vault_command,
            'azure-key-vault-get': get_key_vault_command,
            'azure-key-vault-list': list_key_vaults_command,
            'azure-key-vault-access-policy-update': update_access_policy_command,
            'azure-key-vault-resource-group-list': list_resource_groups_command
        }

        if command in commands_without_args:
            return_results(commands_without_args[command](client))
        elif command in commands_with_args:
            return_results(commands_with_args[command](client, args))
        elif command in commands_with_params:
            return_results(commands_with_params[command](client, params))
        elif command in commands_with_args_and_params:
            return_results(commands_with_args_and_params[command](client, args, params))
        elif demisto.command() == 'fetch-credentials':
            fetch_credentials(client, key_vaults_to_fetch_from, secrets_to_fetch, identifier)
        elif demisto.command() == 'azure-key-vault-auth-reset':
            return_results(reset_auth())
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as error:
        str_error = str(error)
        custom_message = f'Failed to execute {command} command.\nError: \n'
        if 'InvalidSubscriptionId' in str_error:
            custom_message += 'Invalid or missing subscription ID. Please verify your subscription ID.'
        elif 'SubscriptionNotFound' in str_error:
            custom_message += 'The given subscription ID could not be found.'
        elif 'perform action' in str_error:
            custom_message += "The client does not have Key Vault permissions to \
the given resource group name or the resource group name does not exist."

        return_error(custom_message + "\n" + str_error if hasattr(error, 'message') else custom_message)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
