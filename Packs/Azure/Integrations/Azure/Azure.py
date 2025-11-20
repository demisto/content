import demistomock as demisto
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *  # noqa
from MicrosoftApiModule import *  # noqa: E402
from COOCApiModule import *
from requests.exceptions import ConnectionError, Timeout
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse
from datetime import UTC


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DEFAULT_LIMIT = "50"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
API_VERSION = "2022-09-01"
NEW_API_VERSION_PARAMS = {"api-version": "2024-05-01"}
GRANT_BY_CONNECTION = {
    "Device Code": DEVICE_CODE,
    "Authorization Code": AUTHORIZATION_CODE,
    "Client Credentials": CLIENT_CREDENTIALS,
}
SCOPE_BY_CONNECTION = {
    "Device Code": "https://management.azure.com/user_impersonation offline_access user.read",
    "Authorization Code": "https://management.azure.com/.default",
    "Client Credentials": "https://management.azure.com/.default",
}
SCOPE_AZURE = "https://management.azure.com/.default"

PERMISSIONS_TO_COMMANDS = {
    "Microsoft.Network/networkSecurityGroups/read": ["azure-nsg-security-groups-list"],
    "Microsoft.Network/networkSecurityGroups/securityRules/read": [
        "azure-nsg-security-rule-update",
        "azure-nsg-security-rule-create",
        "azure-nsg-security-rule-update-quick-action",
    ],
    "Microsoft.Network/networkSecurityGroups/securityRules/write": [
        "azure-nsg-security-rule-update",
        "azure-nsg-security-rule-create",
        "azure-nsg-security-rule-update-quick-action",
    ],
    "Microsoft.Network/networkSecurityGroups/securityRules/delete": [
        "azure-nsg-security-rule-delete",
        "azure-nsg-security-rule-delete-quick-action",
    ],
    "Microsoft.Storage/storageAccounts/read": [
        "azure-storage-account-update",
        "azure-storage-allow-access-quick-action",
        "azure-storage-disable-cross-tenant-replication-quick-action",
        "azure-storage-disable-public-access-quick-action",
        "azure-network-disable-storage-account-access-quick-action",
        "azure-set-storage-account-https-only-quick-action",
    ],
    "Microsoft.Storage/storageAccounts/write": [
        "azure-storage-account-update",
        "azure-storage-allow-access-quick-action",
        "azure-storage-disable-cross-tenant-replication-quick-action",
        "azure-storage-disable-public-access-quick-action",
        "azure-network-disable-storage-account-access-quick-action",
        "azure-set-storage-account-https-only-quick-action",
    ],
    "Microsoft.Network/networkInterfaces/read": ["azure-nsg-network-interfaces-list", "azure-vm-network-interface-details-get"],
    "Microsoft.Network/publicIPAddresses/read": ["azure-nsg-public-ip-addresses-list", "azure-vm-public-ip-details-get"],
    "Microsoft.Storage/storageAccounts/blobServices/containers/write": ["azure-storage-blob-containers-update"],
    "Microsoft.Storage/storageAccounts/blobServices/read": [
        "azure-storage-blob-service-properties-set",
        "azure-storage-blob-service-properties-get",
        "azure-storage-blob-enable-soft-delete-quick-action",
    ],
    "Microsoft.Storage/storageAccounts/blobServices/write": [
        "azure-storage-blob-service-properties-set",
        "azure-storage-blob-service-properties-get",
        "azure-storage-blob-enable-soft-delete-quick-action",
    ],
    "Microsoft.Authorization/policyAssignments/read": [
        "azure-policy-assignment-create",
        "azure-policy-assignment-create-quick-action",
    ],
    "Microsoft.Authorization/policyAssignments/write": [
        "azure-policy-assignment-create",
        "azure-policy-assignment-create-quick-action",
    ],
    "Microsoft.DBforPostgreSQL/servers/read": [
        "azure-postgres-server-update",
        "azure-postgres-server-update-ssl-enforcement-quick-action",
    ],
    "Microsoft.DBforPostgreSQL/servers/write": [
        "azure-postgres-server-update",
        "azure-postgres-server-update-ssl-enforcement-quick-action",
    ],
    "Microsoft.DBforPostgreSQL/servers/configurations/read": [
        "azure-postgres-config-set",
        "azure-postgres-config-set-disconnection-logging-quick-action"
        "azure-postgres-config-set-checkpoint-logging-quick-action",
        "azure-postgres-config-set-connection-throttling-quick-action",
        "azure-postgres-config-set-session-connection-logging-quick-action",
        "azure-postgres-config-set-log-retention-period-quick-action",
        "azure-postgres-config-set-statement-logging-quick-action",
    ],
    "Microsoft.DBforPostgreSQL/servers/configurations/write": [
        "azure-postgres-config-set",
        "azure-postgres-config-set-disconnection-logging-quick-action"
        "azure-postgres-config-set-checkpoint-logging-quick-action",
        "azure-postgres-config-set-connection-throttling-quick-action",
        "azure-postgres-config-set-session-connection-logging-quick-action",
        "azure-postgres-config-set-log-retention-period-quick-action",
        "azure-postgres-config-set-statement-logging-quick-action",
    ],
    "Microsoft.Web/sites/config/read": [
        "azure-webapp-config-set",
        "azure-webapp-auth-update",
        "azure-webapp-set-http2-quick-action",
        "azure-set-function-app-http-version2-0-quick-action",
        "azure-webapp-disable-remote-debugging-quick-action",
        "azure-webapp-auth-update-quick-action",
        "azure-webapp-set-min-tls-version-quick-action",
        "azure-function-app-set-min-tls-version-quick-action",
    ],
    "Microsoft.Web/sites/config/write": [
        "azure-webapp-config-set",
        "azure-webapp-auth-update",
        "azure-webapp-set-http2-quick-action",
        "azure-set-function-app-http-version2-0-quick-action",
        "azure-webapp-disable-remote-debugging-quick-action",
        "azure-webapp-auth-update-quick-action",
        "azure-webapp-set-min-tls-version-quick-action",
        "azure-function-app-set-min-tls-version-quick-action",
    ],
    "Microsoft.Web/sites/read": [
        "azure-webapp-update",
        "azure-webapp-assign-managed-identity-quick-action",
        "azure-webapp-update-assign-managed-identity-quick-action",
    ],
    "Microsoft.Web/sites/write": [
        "azure-webapp-update",
        "azure-webapp-assign-managed-identity-quick-action",
        "azure-webapp-update-assign-managed-identity-quick-action",
    ],
    "Microsoft.DBforMySQL/flexibleServers/configurations/read": [
        "azure-mysql-flexible-server-param-set",
        "azure-mysql-set-secure-transport-quick-action",
    ],
    "Microsoft.DBforMySQL/flexibleServers/configurations/write": [
        "azure-mysql-flexible-server-param-set",
        "azure-mysql-set-secure-transport-quick-action",
    ],
    "Microsoft.Insights/logprofiles/read": [
        "azure-monitor-log-profile-update",
        "azure-monitor-log-retention-period-quick-action",
    ],
    "Microsoft.Insights/logprofiles/write": [
        "azure-monitor-log-profile-update",
        "azure-monitor-log-retention-period-quick-action",
    ],
    "Microsoft.Compute/disks/read": [
        "azure-disk-update",
        "azure-disable-public-private-access-vm-disk-quick-action",
        "azure-disk-set-data-access-aad-quick-action",
    ],
    "Microsoft.Compute/disks/write": [
        "azure-disk-update",
        "azure-disable-public-private-access-vm-disk-quick-action",
        "azure-disk-set-data-access-aad-quick-action",
    ],
    "Microsoft.Compute/virtualMachines/read": ["azure-vm-instance-details-get"],
    "Microsoft.Compute/virtualMachines/start/action": ["azure-vm-instance-start"],
    "Microsoft.Compute/virtualMachines/poweroff/action": ["azure-vm-instance-power-off"],
    "Microsoft.ContainerRegistry/registries/read": [
        "azure-acr-update",
        "azure-acr-disable-public-private-access-quick-action",
        "azure-acr-disable-authentication-as-arm-quick-action",
        "azure-acr-disable-anonymous-pull-quick-action",
    ],
    "Microsoft.ContainerRegistry/registries/write": [
        "azure-acr-update",
        "azure-acr-disable-public-private-access-quick-action",
        "azure-acr-disable-authentication-as-arm-quick-action",
        "azure-acr-disable-anonymous-pull-quick-action",
    ],
    "Microsoft.KeyVault/vaults/read": ["azure-key-vault-update"],
    "Microsoft.KeyVault/vaults/write": ["azure-key-vault-update"],
    "Microsoft.Sql/servers/databases/securityAlertPolicies/read": ["azure-sql-db-threat-policy-update"],
    "Microsoft.Sql/servers/databases/securityAlertPolicies/write": ["azure-sql-db-threat-policy-update"],
    "Microsoft.DocumentDB/databaseAccounts/read": ["azure-cosmos-db-update"],
    "Microsoft.DocumentDB/databaseAccounts/write": ["azure-cosmos-db-update"],
    "Microsoft.Sql/servers/databases/transparentDataEncryption/read": ["azure-sql-db-transparent-data-encryption-set"],
    "Microsoft.Sql/servers/databases/transparentDataEncryption/write": ["azure-sql-db-transparent-data-encryption-set"],
    "Microsoft.Resources/subscriptions/resourceGroups/read": ["azure-nsg-resource-group-list"],
    "Microsoft.Consumption/usageDetails/read": ["azure-billing-usage-list"],
    "Microsoft.Consumption/budgets/read": ["azure-billing-budgets-list"],
    "Microsoft.CostManagement/forecast/read": ["azure-billing-forecast-list"],
}

API_FUNCTION_TO_PERMISSIONS = {
    "acr_update": ["Microsoft.ContainerRegistry/registries/read", "Microsoft.ContainerRegistry/registries/write"],
    "cosmos_db_update": ["Microsoft.DocumentDB/databaseAccounts/read", "Microsoft.DocumentDB/databaseAccounts/write"],
    "disk-update": ["Microsoft.Compute/disks/read", "Microsoft.Compute/disks/write"],
    "update_key_vault_request": ["Microsoft.KeyVault/vaults/read", "Microsoft.KeyVault/vaults/write"],
    "monitor_log_profile_update": ["Microsoft.Insights/logprofiles/read", "Microsoft.Insights/logprofiles/write"],
    "flexible_server_param_set": [
        "Microsoft.DBforMySQL/flexibleServers/configurations/read",
        "Microsoft.DBforMySQL/flexibleServers/configurations/write",
    ],
    "list_networks_interfaces_request": ["Microsoft.Network/networkInterfaces/read"],
    "list_public_ip_addresses_request": ["Microsoft.Network/publicIPAddresses/read"],
    "list_resource_groups_request": ["Microsoft.Resources/subscriptions/resourceGroups/read"],
    "list_network_security_groups": ["Microsoft.Network/networkSecurityGroups/read"],
    "create_or_update_rule": [
        "Microsoft.Network/networkSecurityGroups/securityRules/read",
        "Microsoft.Network/networkSecurityGroups/securityRules/write",
    ],
    "delete_rule": ["Microsoft.Network/networkSecurityGroups/securityRules/delete"],
    "create_policy_assignment": [
        "Microsoft.Authorization/policyAssignments/read",
        "Microsoft.Authorization/policyAssignments/write",
    ],
    "set_postgres_config": [
        "Microsoft.DBforPostgreSQL/servers/configurations/read",
        "Microsoft.DBforPostgreSQL/servers/configurations/write",
    ],
    "postgres_server_update": ["Microsoft.DBforPostgreSQL/servers/read", "Microsoft.DBforPostgreSQL/servers/write"],
    "sql_db_threat_policy_update": [
        "Microsoft.Sql/servers/databases/securityAlertPolicies/read",
        "Microsoft.Sql/servers/databases/securityAlertPolicies/write",
    ],
    "sql_db_tde_set": [
        "Microsoft.Sql/servers/databases/transparentDataEncryption/read",
        "Microsoft.Sql/servers/databases/transparentDataEncryption/write",
    ],
    "storage_account_update_request": ["Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/write"],
    "storage_blob_service_properties_set_request": [
        "Microsoft.Storage/storageAccounts/blobServices/read",
        "Microsoft.Storage/storageAccounts/blobServices/write",
    ],
    "update_webapp_auth": ["Microsoft.Web/sites/config/read", "Microsoft.Web/sites/config/write"],
    "set_webapp_config": ["Microsoft.Web/sites/config/read", "Microsoft.Web/sites/config/write"],
    "webapp_update": ["Microsoft.Web/sites/read", "Microsoft.Web/sites/write"],
    "start_vm_request": ["Microsoft.Compute/virtualMachines/start/action"],
    "poweroff_vm_request": ["Microsoft.Compute/virtualMachines/poweroff/action"],
    "get_vm_request": ["Microsoft.Compute/virtualMachines/read"],
    "get_network_interface_request": ["Microsoft.Network/networkInterfaces/read"],
    "get_public_ip_details_request": ["Microsoft.Network/publicIPAddresses/read"],
    "get_all_public_ip_details_request": ["Microsoft.Network/publicIPAddresses/read"],
}

REQUIRED_ROLE_PERMISSIONS = [
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/networkSecurityGroups/securityRules/read",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/delete",
    "Microsoft.Network/networkInterfaces/read",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Storage/storageAccounts/write",
    "Microsoft.Storage/storageAccounts/blobServices/read",
    "Microsoft.Storage/storageAccounts/blobServices/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/write",
    "Microsoft.Authorization/policyAssignments/read",
    "Microsoft.Authorization/policyAssignments/write",
    "Microsoft.DBforPostgreSQL/servers/read",
    "Microsoft.DBforPostgreSQL/servers/write",
    "Microsoft.DBforPostgreSQL/servers/configurations/read",
    "Microsoft.DBforPostgreSQL/servers/configurations/write",
    "Microsoft.Web/sites/config/read",
    "Microsoft.Web/sites/config/write",
    "Microsoft.Web/sites/read",
    "Microsoft.Web/sites/write",
    "Microsoft.DBforMySQL/flexibleServers/configurations/read",
    "Microsoft.DBforMySQL/flexibleServers/configurations/write",
    "Microsoft.Insights/logprofiles/read",
    "Microsoft.Insights/logprofiles/write",
    "Microsoft.Compute/disks/read",
    "Microsoft.Compute/disks/write",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/poweroff/action",
    "Microsoft.ContainerRegistry/registries/read",
    "Microsoft.ContainerRegistry/registries/write",
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.KeyVault/vaults/write",
    "Microsoft.Sql/servers/databases/securityAlertPolicies/read",
    "Microsoft.Sql/servers/databases/securityAlertPolicies/write",
    "Microsoft.DocumentDB/databaseAccounts/read",
    "Microsoft.DocumentDB/databaseAccounts/write",
    "Microsoft.Sql/servers/databases/transparentDataEncryption/read",
    "Microsoft.Sql/servers/databases/transparentDataEncryption/write",
    "Microsoft.Resources/subscriptions/read",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Consumption/usageDetails/read",
    "Microsoft.Consumption/budgets/read",
    "Microsoft.CostManagement/forecast/read",
]
REQUIRED_API_PERMISSIONS = ["GroupMember.ReadWrite.All", "RoleManagement.ReadWrite.Directory"]

PREFIX_URL_AZURE = "https://management.azure.com/subscriptions/"
PREFIX_URL_MS_GRAPH = "https://graph.microsoft.com/v1.0"
POLICY_ASSIGNMENT_API_VERSION = "2024-05-01"
POSTGRES_API_VERSION = "2017-12-01"
WEBAPP_API_VERSION = "2024-04-01"
FLEXIBLE_API_VERSION = "2023-12-30"
MONITOR_API_VERSION = "2016-03-01"
DISKS_API_VERSION = "2024-03-02"
ACR_API_VERSION = "2023-07-01"
KEY_VAULT_API_VERSION = "2022-07-01"
SQL_DB_API_VERSION = "2021-11-01"
COSMOS_DB_API_VERSION = "2024-11-15"
PERMISSIONS_VERSION = "2022-04-01"
VM_API_VERSION = "2023-03-01"

""" CLIENT CLASS """


class AzureClient:
    def __init__(
        self,
        app_id: str = "",
        subscription_id: str = "",
        resource_group_name: str = "",
        verify: bool = False,
        proxy: bool = False,
        tenant_id: str | None = None,
        enc_key: str | None = None,
        scope: str | None = None,
        headers: dict | None = None,
    ):
        if not headers:
            ms_client_args = assign_params(
                self_deployed=True,
                auth_id=app_id,
                token_retrieval_url=None,
                grant_type=GRANT_BY_CONNECTION.get("Client Credentials"),
                base_url=f"{PREFIX_URL_AZURE}",
                verify=verify,
                proxy=proxy,
                resource=None,
                scope=scope,
                tenant_id=tenant_id,
                enc_key=enc_key,
                ok_codes=(200, 201, 202, 204),
            )
            self.ms_client = MicrosoftClient(**ms_client_args)
        else:
            base_client_args = assign_params(
                base_url=f"{PREFIX_URL_AZURE}", verify=os.environ.get("EGRESSPROXY_CA_PATH"), proxy=proxy, headers=headers
            )
            self.base_client = BaseClient(**base_client_args)

        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        self.headers = headers

    def http_request(
        self,
        method: str,
        url_suffix: str | None = None,
        full_url: str | None = None,
        params: dict | None = None,
        resp_type: str = "json",
        json_data: dict | None = None,
    ) -> requests.Response | dict[str, Any]:
        params = params or {}
        if not params.get("api-version"):
            params["api-version"] = API_VERSION

        proxies = {"http": os.environ.get("CRTX_HTTP_PROXY"), "https": os.environ.get("CRTX_HTTP_PROXY")}

        if self.headers:
            self.headers |= {"x-caller-id": get_proxydome_token()}
            return self.base_client._http_request(  # type: ignore[misc]
                method=method,
                url_suffix=url_suffix,
                full_url=full_url,
                json_data=json_data,
                params=params,
                resp_type=resp_type,
                headers=self.headers,
                ok_codes=(200, 201, 202, 204, 206),
                proxies=proxies,
            )

        return self.ms_client.http_request(
            method=method, url_suffix=url_suffix, full_url=full_url, json_data=json_data, params=params, resp_type=resp_type
        )

    def handle_azure_error(
        self,
        e: Exception,
        resource_name: str,
        resource_type: str,
        api_function_name: str,
        subscription_id: str = None,
        resource_group_name: str = None,
    ) -> None:
        """
        Standardized error handling for Azure API calls

        Args:
            e: The exception that was raised
            resource_name: Name of the resource that caused the error
            resource_type: Type of the resource (e.g., 'Security Rule', 'Storage Account')
            api_function_name: The api function name, used when need to know the permissions.
            subscription_id: Azure subscription ID (optional, for better error messages)
            resource_group_name: Resource group name (optional, for better error messages)

        Raises:
            ValueError: For 404 (not found) errors
            DemistoException: For permission errors and other API errors
        """
        error_msg = str(e).lower()
        demisto.debug(f"Azure API error for {resource_type} '{resource_name}': {type(e).__name__}")

        if "404" in error_msg or "not found" in error_msg:
            error_details = f'{resource_type} "{resource_name}"'
            if subscription_id and resource_group_name:
                error_details += f' under subscription ID "{subscription_id}" and resource group "{resource_group_name}"'
            elif subscription_id:
                error_details += f' under subscription ID "{subscription_id}"'
            raise ValueError(f"{error_details} was not found. {str(e)}")

        elif ("403" in error_msg or "forbidden" in error_msg) or ("401" in error_msg or "unauthorized" in error_msg):
            demisto.debug("Permission error, trying to find the missing permission.")
            found_permission = []
            # If we have api_function_name, use the reverse mapping for O(1) lookup
            if api_function_name in API_FUNCTION_TO_PERMISSIONS:
                found_permission = get_permissions_from_api_function_name(api_function_name, error_msg)

            if not found_permission:
                found_permission = get_permissions_from_required_role_permissions_list(error_msg)

            error_entries = [{"account_id": subscription_id, "message": error_msg, "name": perm} for perm in found_permission]

            demisto.debug(f"Calling return_multiple_permissions_error function with {error_entries=}")
            return_multiple_permissions_error(error_entries)

        elif "400" in error_msg or "bad request" in error_msg:
            if "intercepted by proxydome" in error_msg:
                raise DemistoException(f'Request for {resource_type} "{resource_name}" was intercepted by proxydome.')

            raise DemistoException(f'Invalid request for {resource_type} "{resource_name}". {str(e)}')

        else:
            # Re-raise the original exception for any other errors
            raise DemistoException(f'Failed to access {resource_type} "{resource_name}": {str(e)}')

    def create_or_update_rule(
        self, security_group: str, rule_name: str, properties: dict, subscription_id: str, resource_group_name: str
    ):
        """
        Create or update a security rule in an Azure Network Security Group.
        Args:
            security_group: Name of the network security group
            rule_name: Name of the security rule to retrieve
            subscription_id: Azure subscription ID
            resource_group_name: Resource group name
            properties: Properties of the security rule

        Returns:
            The response from the Azure API after creating the security rule

        Raises:
            ValueError: If the rule is not found
            DemistoException: If there are permission or other API errors
        """
        try:
            return self.http_request(
                "PUT",
                full_url=(
                    f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
                    f"/providers/Microsoft.Network/networkSecurityGroups/{security_group}/securityRules/{rule_name}?"
                ),
                json_data={"properties": properties},
            )
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{security_group}/{rule_name}",
                resource_type="Security Rule",
                api_function_name="create_or_update_rule",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def get_rule(self, security_group: str, rule_name: str, subscription_id: str, resource_group_name: str):
        """
        Get a network security group rule.

        Args:
            security_group: Name of the network security group
            rule_name: Name of the security rule to retrieve
            subscription_id: Azure subscription ID
            resource_group_name: Resource group name

        Returns:
            Dictionary containing the security rule information

        Raises:
            ValueError: If the rule is not found
            DemistoException: If there are permission or other API errors
        """
        try:
            demisto.debug("Retrieving security rule details.")
            return self.http_request(
                "GET",
                full_url=f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Network/networkSecurityGroups/{security_group}/securityRules/{rule_name}",
            )
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{security_group}/{rule_name}",
                resource_type="Security Rule",
                api_function_name="get_rule",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def storage_account_update_request(self, subscription_id: str, resource_group_name: str, args: dict):
        """
            Send the user arguments for the create/update account in the request body to the API.
        Args:
            subscription_id: The subscription id.
            resource_group_name: The resource group name.
            args: The user arguments.

        Returns:
            The json response from the API call.
        """
        account_name = args.get("account_name", "")
        json_data_args: dict = {
            "sku": {"name": args.get("sku")},
            "kind": args.get("kind"),
            "location": args.get("location"),
            "properties": {},
        }
        if "tags" in args:
            args_tags_list = args["tags"].split(",")
            tags_obj = {f"tag{i + 1!s}": args_tags_list[i] for i in range(len(args_tags_list))}
            json_data_args["tags"] = tags_obj

        json_data_args.update(
            {
                "properties": {
                    "customDomain": {
                        "name": args.get("custom_domain_name"),
                        "useSubDomainName": args.get("use_sub_domain_name") == "true" if "use_sub_domain_name" in args else None,
                    },
                    "encryption": {
                        "keySource": args.get("enc_key_source"),
                        "keyvaultproperties": {
                            "keyname": args.get("enc_keyvault_key_name"),
                            "keyversion": args.get("enc_keyvault_key_version"),
                            "keyvaulturi": args.get("enc_keyvault_uri"),
                        },
                        "requireInfrastructureEncryption": args.get("enc_requireInfrastructureEncryption"),
                    },
                    "networkAcls": {
                        "bypass": args.get("network_ruleset_bypass"),
                        "defaultAction": args.get("network_ruleset_default_action"),
                        "ipRules": json.loads(args["network_ruleset_ipRules"]) if "network_ruleset_ipRules" in args else None,
                        "virtualNetworkRules": json.loads(args["virtual_network_rules"])
                        if "virtual_network_rules" in args
                        else None,
                    },
                    "accessTier": args.get("access_tier"),
                    "supportsHttpsTrafficOnly": args.get("supports_https_traffic_only"),
                    "isHnsEnabled": args.get("is_hns_enabled"),
                    "largeFileSharesState": args.get("large_file_shares_state"),
                    "allowCrossTenantReplication": args.get("allow_cross_tenant_replication"),
                    "allowBlobPublicAccess": args.get("allow_blob_public_access"),
                    "minimumTlsVersion": args.get("minimum_tls_version"),
                }
            }
        )

        json_data_args = remove_empty_elements(json_data_args)
        demisto.debug(f'Updating storage account "{account_name}".')
        try:
            response = self.http_request(
                method="PATCH",
                full_url=(
                    f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
                    f"/providers/Microsoft.Storage/storageAccounts/{account_name}"
                ),
                params={
                    "api-version": API_VERSION,
                },
                json_data=json_data_args,
                resp_type="response",
            )
            return response
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=account_name,
                resource_type="Storage Account",
                api_function_name="storage_account_update_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def storage_blob_service_properties_set_request(
        self,
        subscription_id: str,
        resource_group_name: str,
        account_name: str,
        delete_rentention_policy_enabled: str | None,
        delete_rentention_policy_days: str | None,
    ):
        """
        Set properties of Blob service of a given Azure Storage account.

        Args:
            subscription_id (str): Azure subscription ID containing the storage account.
            resource_group_name (str): Name of the resource group that contains the storage account.
            account_name (str): Name of the Azure Storage account.
            delete_rentention_policy_enabled (str): Whether delete retention is enabled ('true' or 'false').
            delete_rentention_policy_days (str): Number of days to retain deleted blobs.

        Returns:
            dict: The full JSON response from the Azure REST API after applying the update.

        Raises:
            ValueError: If the storage account is not found or required parameters are missing
            DemistoException: If there are permission or other API errors
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Storage/storageAccounts/{account_name}/blobServices/default"
        )
        data = {
            "properties": {
                "deleteRetentionPolicy": {"enabled": delete_rentention_policy_enabled, "days": delete_rentention_policy_days}
            }
        }
        params = {"api-version": API_VERSION}
        data = remove_empty_elements(data)
        try:
            return self.http_request(method="PUT", full_url=full_url, params=params, json_data=data)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{account_name}/blobServices",
                resource_type="Storage Blob Service",
                api_function_name="storage_blob_service_properties_set_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def storage_blob_service_properties_get_request(self, account_name: str, resource_group_name: str, subscription_id: str):
        """
            Send the get blob service properties request to the API.
        Args:
            account_name: The storage account name.
            resource_group_name: The resource group name.
            subscription_id: The subscription id.

        Returns:
            The json response from the API call.
        Docs:
            https://learn.microsoft.com/en-us/rest/api/storagerp/blob-services/get-service-properties?view=rest-storagerp-2024-01-01&utm_source=chatgpt.com&tabs=HTTP
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Storage/storageAccounts/{account_name}/blobServices/default"
        )
        try:
            return self.http_request(method="GET", full_url=full_url)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{account_name}/blobServices",
                resource_type="Storage Blob Service",
                api_function_name="storage_blob_service_properties_get_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def storage_blob_containers_create_update_request(
        self, subscription_id: str, resource_group_name: str, args: Dict, method: str
    ):
        """
        Create or update a blob container in an Azure Storage account.

        This function constructs the request body from user-provided arguments
        and sends an HTTP request to the Azure REST API to create or update
        a blob container under the specified storage account.

        Args:
            subscription_id (str): The Azure subscription ID.
            resource_group_name (str): The name of the resource group containing the storage account.
            args (Dict): User-provided arguments, which can include:
                - container_name (str): Name of the blob container.
                - account_name (str): Name of the storage account.
                - default_encryption_scope (str, optional): Default encryption scope for the container.
                - deny_encryption_scope_override (bool, optional): Whether to deny overriding the encryption scope.
                - public_access (str, optional): Public access level for the container (e.g., "None", "Blob", "Container").
            method (str): HTTP method to use for the request (e.g., "PUT" or "PATCH").

        Returns:
            dict: The JSON response from the Azure API.
        """
        container_name = args.get("container_name", "")
        account_name = args.get("account_name", "")
        try:
            properties = {}

            if "default_encryption_scope" in args:
                properties["defaultEncryptionScope"] = args.get("default_encryption_scope")

            if "deny_encryption_scope_override" in args:
                properties["denyEncryptionScopeOverride"] = argToBoolean(args.get("deny_encryption_scope_override"))

            if "public_access" in args:
                properties["publicAccess"] = args.get("public_access")

            full_url = (
                f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}/providers/"
                f"Microsoft.Storage/storageAccounts/{account_name}/blobServices/default/containers/{container_name}"
            )

            return self.http_request(
                method=method,
                full_url=full_url,
                json_data={"properties": properties},
            )
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{account_name}/{container_name}",
                resource_type="Storage Blob Service",
                api_function_name="storage_blob_containers_create_update_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def create_policy_assignment(
        self, name: str, policy_definition_id: str, display_name: str, parameters: str, description: str, scope: str
    ):
        """
        Create a policy assignment in Azure.
        Args:
            name (str): Name of the policy assignment.
            policy_definition_id (str):  ID of the policy definition to assign.
            display_name (str): Display name for the policy assignment.
            parameters (str): Parameters for the policy assignment.
            description (str): Description of the policy assignment.
            scope (str): Scope of the policy assignment (e.g., subscription or resource group).
        Returns:
            dict: The full response from the Azure policy assignment creation API.
        """
        # subscription_id is required as argument for token creation.
        full_url = f"https://management.azure.com{scope}/providers/Microsoft.Authorization/policyAssignments/{name}"
        params = {"api-version": POLICY_ASSIGNMENT_API_VERSION}
        data = {
            "properties": {
                "policyDefinitionId": "/providers/Microsoft.Authorization/policySetDefinitions/" + policy_definition_id,
                "displayName": display_name,
                "parameters": parameters,
                "description": description,
            }
        }
        try:
            return self.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{name}",
                resource_type="Policy Assignment",
                api_function_name="create_policy_assignment",
                subscription_id=self.subscription_id,
                resource_group_name=self.resource_group_name,
            )

    def set_postgres_config(
        self, server_name: str, subscription_id: str, resource_group_name: str, configuration_name: str, source: str, value: str
    ):
        """
        Updates the configuration of a specific PostgreSQL server parameter.
        Args:
            server_name (str): Name of the PostgreSQL server.
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the server.
            configuration_name (str): Name of the configuration parameter to update.
            source (str): The source of the configuration value.
            value (str): The new value to set for the configuration parameter.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If required parameters are missing or PostgreSQL server not found
            DemistoException: If there are permission or other API errors
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.DBforPostgreSQL/servers/{server_name}/configurations/{configuration_name}"
        )
        params = {"api-version": POSTGRES_API_VERSION}
        data = {"properties": {"source": source, "value": value}}
        data = remove_empty_elements(data)
        demisto.debug(f'Updating configuration of PostgreSQL server "{server_name}".')
        try:
            return self.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{server_name}/{configuration_name}",
                resource_type="PostgreSQL Configuration",
                api_function_name="set_postgres_config",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def set_webapp_config(
        self,
        name: str,
        subscription_id: str,
        resource_group_name: str,
        http20_enabled: str,
        remote_debugging_enabled: str,
        min_tls_version: str,
    ):
        """
        Updates the web app configuration settings.

        Args:
            name (str): Name of the web app.
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the web app.
            http20_enabled (str): Whether HTTP/2.0 is enabled for the web app.
            remote_debugging_enabled (str): Whether remote debugging is enabled.
            min_tls_version (str): Minimum TLS version required.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If required parameters are missing or webapp not found
            DemistoException: If there are permission or other API errors
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Web/sites/{name}/config/web"
        )
        params = {"api-version": WEBAPP_API_VERSION}
        data = {
            "properties": {
                "http20Enabled": http20_enabled,
                "remoteDebuggingEnabled": remote_debugging_enabled,
                "minTlsVersion": min_tls_version,
            }
        }
        data = remove_empty_elements(data)
        demisto.debug(f"Setting WebApp configuration for {name}.")
        try:
            return self.http_request(method="PATCH", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=name,
                resource_type="Web App",
                subscription_id=subscription_id,
                api_function_name="set_webapp_config",
                resource_group_name=resource_group_name,
            )

    def get_webapp_auth(self, name: str, subscription_id: str, resource_group_name: str):
        """
        Gets the authentication settings of a web app.

        Args:
            name (str): Name of the web app.
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the web app.

        Returns:
            dict: The authentication settings of the web app.

        Raises:
            ValueError: If required parameters are missing or webapp not found
            DemistoException: If there are permission or other API errors
        """
        try:
            full_url = (
                f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
                f"/providers/Microsoft.Web/sites/{name}/config/authsettings/list"
            )
            params = {"api-version": WEBAPP_API_VERSION}
            return self.http_request(method="GET", full_url=full_url, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=name,
                resource_type="Web App",
                api_function_name="get_webapp_auth",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def update_webapp_auth(self, name: str, subscription_id: str, resource_group_name: str, enabled: str):
        """
        Updates the authentication settings of a web app.

        Args:
            name (str): Name of the web app.
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the web app.
            current (dict): Current authentication settings dictionary to be updated.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If required parameters are missing or webapp not found
            DemistoException: If there are permission or other API errors
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Web/sites/{name}/config/authsettings"
        )
        params = {"api-version": WEBAPP_API_VERSION}
        data = {"properties": {"enabled": enabled}}
        demisto.debug(f"Updating WebApp auth of {name}.")
        try:
            return self.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=name,
                resource_type="Web App",
                api_function_name="update_webapp_auth",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def flexible_server_param_set(
        self, server_name: str, configuration_name: str, subscription_id: str, resource_group_name: str, source: str, value: str
    ):
        """
        Updates a parameter of a MySQL flexible server.

        Args:
            server_name (str): Name of the MySQL flexible server.
            configuration_name (str): Name of the configuration parameter to update.
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the server.
            source (str): The source of the configuration value.
            value (str): The new value to set for the configuration parameter.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If the MySQL flexible server or configuration parameter is not found
            DemistoException: If there are permission or other API errors
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.DBforMySQL/flexibleServers/{server_name}/configurations/{configuration_name}"
        )
        params = {"api-version": FLEXIBLE_API_VERSION}
        data = {"properties": {"source": source, "value": value}}
        try:
            return self.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{server_name}/{configuration_name}",
                resource_type="MySQL Flexible Server Configuration",
                api_function_name="flexible_server_param_set",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def get_monitor_log_profile(self, subscription_id: str, log_profile_name: str):
        """
        Gets a monitor log profile.

        Args:
            subscription_id (str): Azure subscription ID.
            log_profile_name (str): Name of the log profile.

        Returns:
            dict: The log profile configuration from Azure API.

        Raises:
            ValueError: If the log profile is not found
            DemistoException: If there are permission or other API errors
        """
        try:
            full_url = f"{PREFIX_URL_AZURE}{subscription_id}/providers/Microsoft.Insights/logprofiles/{log_profile_name}"
            params = {"api-version": MONITOR_API_VERSION}
            demisto.debug(f'Getting log profile "{log_profile_name}".')
            return self.http_request(method="GET", full_url=full_url, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=log_profile_name,
                resource_type="Monitor Log Profile",
                api_function_name="get_monitor_log_profile",
                subscription_id=subscription_id,
                resource_group_name=None,
            )

    def monitor_log_profile_update(self, subscription_id: str, log_profile_name: str, current_log_profile: dict):
        """
        Updates a monitor log profile.

        Args:
            subscription_id (str): Azure subscription ID.
            log_profile_name (str): Name of the log profile.
            current_log_profile (dict): The current log profile to update.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If the log profile is not found
            DemistoException: If there are permission or other API errors
        """
        full_url = f"{PREFIX_URL_AZURE}{subscription_id}/providers/Microsoft.Insights/logprofiles/{log_profile_name}"
        params = {"api-version": MONITOR_API_VERSION}
        data = current_log_profile
        data = remove_empty_elements(data)
        try:
            demisto.debug(f'Updating log profile "{log_profile_name}".')
            return self.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=log_profile_name,
                resource_type="Monitor Log Profile",
                api_function_name="monitor_log_profile_update",
                subscription_id=subscription_id,
                resource_group_name=None,
            )

    def disk_update(
        self,
        subscription_id: str,
        resource_group_name: str,
        disk_name: str,
        public_network_access: str | None,
        network_access_policy: str | None,
        data_access_auth_mode: str | None,
    ):
        """
        Updates a disk.

        Args:
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the disk.
            disk_name (str): Name of the disk.
            public_network_access (str): The public network access state.
            network_access_policy (str): The network access policy.
            data_access_auth_mode (str): The data access authentication mode.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If the disk is not found
            DemistoException: If there are permission or other API errors
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Compute/disks/{disk_name}"
        )
        params = {"api-version": DISKS_API_VERSION}
        data = {
            "properties": {
                "publicNetworkAccess": public_network_access,
                "networkAccessPolicy": network_access_policy,
                "dataAccessAuthMode": data_access_auth_mode,
            }
        }
        data = remove_empty_elements(data)
        try:
            demisto.debug(f'Updating disk "{disk_name}."')
            return self.http_request(method="PATCH", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=disk_name,
                resource_type="Disk",
                api_function_name="disk_update",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def webapp_update(
        self,
        subscription_id: str,
        resource_group_name: str,
        name: str,
        identity_type: str | None,
        https_only: str | None,
        client_cert_enabled: str | None,
    ):
        """
        Updates a web app.

        Args:
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the web app.
            name (str): Name of the web app.
            identity_type (str): Type of identity to assign to the web app.
            https_only (str): Whether the web app requires HTTPS only.
            client_cert_enabled (str): Whether client certificates are enabled.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If the web app is not found
            DemistoException: If there are permission or other API errors
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Web/sites/{name}"
        )
        params = {"api-version": WEBAPP_API_VERSION}
        data = {
            "identity": {
                "type": identity_type,
            },
            "properties": {
                "clientCertEnabled": client_cert_enabled,
                "httpsOnly": https_only,
            },
        }
        data = remove_empty_elements(data)
        demisto.debug(f'Updating WebApp "{name}".')
        try:
            return self.http_request(method="PATCH", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=name,
                resource_type="Web App",
                api_function_name="webapp_update",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def acr_update(
        self,
        subscription_id: str,
        resource_group_name: str,
        registry_name: str,
        allow_exports: str | None,
        public_network_access: str | None,
        anonymous_pull_enabled: str | None,
        authentication_as_arm_policy: str | None,
    ):
        """
        Updates an Azure Container Registry.

        Args:
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the registry.
            registry_name (str): Name of the container registry.
            allow_exports (str): Whether exports are allowed.
            public_network_access (str): The public network access state.
            anonymous_pull_enabled (str): Whether anonymous pulls are enabled.
            authentication_as_arm_policy (str): The authentication as ARM policy status.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If the container registry is not found
            DemistoException: If there are permission or other API errors
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.ContainerRegistry/registries/{registry_name}"
        )
        params = {"api-version": ACR_API_VERSION}
        data = {
            "properties": {
                "publicNetworkAccess": public_network_access,
                "anonymousPullEnabled": anonymous_pull_enabled,
                "policies": {
                    "azureADAuthenticationAsArmPolicy": {"status": authentication_as_arm_policy},
                    "exportPolicy": {"status": allow_exports},
                },
            },
        }
        data = remove_empty_elements(data)
        demisto.debug(f'Updating ACR "{registry_name}".')
        try:
            return self.http_request(method="PATCH", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=registry_name,
                resource_type="Container Registry",
                api_function_name="acr_update",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def postgres_server_update(self, subscription_id: str, resource_group_name: str, server_name: str, ssl_enforcement: str):
        """
        Updates a PostgreSQL server.

        Args:
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the server.
            server_name (str): Name of the PostgreSQL server.
            ssl_enforcement (str): The SSL enforcement status.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If the PostgreSQL server is not found
            DemistoException: If there are permission or other API errors
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.DBforPostgreSQL/servers/{server_name}"
        )
        params = {"api-version": POSTGRES_API_VERSION}
        data = {
            "properties": {"sslEnforcement": ssl_enforcement},
        }
        data = remove_empty_elements(data)
        try:
            demisto.debug(f'Updating postgres server "{server_name}".')
            return self.http_request(method="PATCH", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=server_name,
                resource_type="PostgreSQL Server",
                api_function_name="postgres_server_update",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def update_key_vault_request(
        self,
        subscription_id: str,
        resource_group_name: str,
        vault_name: str,
        enable_soft_delete: str,
        enable_purge_protection: str,
    ):
        """
        Updates a Key Vault.

        Args:
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the key vault.
            vault_name (str): Name of the key vault.
            enable_soft_delete (str): Whether soft delete is enabled.
            enable_purge_protection (str): Whether purge protection is enabled.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If the key vault is not found
            DemistoException: If there are permission or other API errors
        """
        data = {"properties": {"enableSoftDelete": enable_soft_delete, "enablePurgeProtection": enable_purge_protection}}
        params = {"api-version": KEY_VAULT_API_VERSION}
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.KeyVault/vaults/{vault_name}"
        )
        try:
            demisto.debug(f'Updating key vault "{vault_name}".')
            return self.http_request("PATCH", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=vault_name,
                resource_type="Key Vault",
                api_function_name="update_key_vault_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def sql_db_threat_policy_get(self, server_name: str, db_name: str, subscription_id: str, resource_group_name: str):
        """
        Gets the threat policy of a SQL database.

        Args:
            server_name (str): Name of the SQL server.
            db_name (str): Name of the database.
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the database.

        Returns:
            dict: The threat policy of the SQL database.

        Raises:
            ValueError: If the SQL database or server is not found
            DemistoException: If there are permission or other API errors
        """
        params = {"api-version": SQL_DB_API_VERSION}
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Sql/servers/{server_name}/databases/{db_name}/securityAlertPolicies/default"
        )
        try:
            demisto.debug("Getting SQL DB threat policy.")
            return self.http_request("GET", full_url=full_url, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{server_name}/{db_name}",
                resource_type="SQL Database Threat Policy",
                api_function_name="sql_db_threat_policy_get",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def sql_db_threat_policy_update(
        self, server_name: str, db_name: str, subscription_id: str, current: dict, resource_group_name: str
    ):
        """
        Updates the threat policy of a SQL database.

        Args:
            server_name (str): Name of the SQL server.
            db_name (str): Name of the database.
            subscription_id (str): Azure subscription ID.
            current (dict): The current threat policy configuration to update.
            resource_group_name (str): Name of the resource group containing the database.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If the SQL database or server is not found
            DemistoException: If there are permission or other API errors
        """
        data = current
        params = {"api-version": SQL_DB_API_VERSION}
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Sql/servers/{server_name}/databases/{db_name}/securityAlertPolicies/default"
        )
        try:
            demisto.debug("Updating SQL DB threat policy.")
            return self.http_request("PUT", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{server_name}/{db_name}",
                resource_type="SQL Database Threat Policy",
                api_function_name="sql_db_threat_policy_update",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def sql_db_tde_set(self, server_name: str, db_name: str, subscription_id: str, state: str, resource_group_name: str):
        """
        Sets the transparent data encryption state of a SQL database.

        Args:
            server_name (str): Name of the SQL server.
            db_name (str): Name of the database.
            subscription_id (str): Azure subscription ID.
            state (str): The TDE state to set.
            resource_group_name (str): Name of the resource group containing the database.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If the SQL database or server is not found
            DemistoException: If there are permission or other API errors
        """
        data = {"properties": {"state": state}}
        params = {"api-version": SQL_DB_API_VERSION}
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Sql/servers/{server_name}/databases/{db_name}/transparentDataEncryption/current"
        )
        demisto.debug("Setting SQL DB Transparent Data Encryption state.")
        try:
            return self.http_request("PUT", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{server_name}/{db_name}",
                resource_type="SQL Database Transparent Data Encryption",
                api_function_name="sql_db_tde_set",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def cosmos_db_update(
        self,
        subscription_id: str,
        resource_group_name: str,
        account_name: str,
        disable_key_based_metadata_write_access: str | None,
    ):
        """
        Updates a Cosmos DB account.

        Args:
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the account.
            account_name (str): Name of the Cosmos DB account.
            disable_key_based_metadata_write_access (str): Whether to disable key-based metadata write access.

        Returns:
            dict: The response from the Azure REST API after applying the update.

        Raises:
            ValueError: If the Cosmos DB account is not found
            DemistoException: If there are permission or other API errors
        """
        data = {"properties": {"disableKeyBasedMetadataWriteAccess": disable_key_based_metadata_write_access}}
        data = remove_empty_elements(data)
        params = {"api-version": COSMOS_DB_API_VERSION}
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.DocumentDB/databaseAccounts/{account_name}"
        )
        demisto.debug("Updating Cosmos DB.")
        try:
            return self.http_request("PATCH", full_url=full_url, json_data=data, params=params)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=account_name,
                resource_type="Cosmos DB Account",
                api_function_name="cosmos_db_update",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def remove_member_from_role(self, role_object_id: str, user_id: str):
        """Currently not supported in the integration - token scope issues.
        Removing a member from a specific role.

        Args:
            role_object_id: A role to remove the user from.
            user_id: The user to remove from the role.

        Return:
            True if succeeded.

        Raises:
            Error on failed removal (as long with requests errors).

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-delete-member?view=graph-rest-1.0&tabs=http
        """
        full_url = f"{PREFIX_URL_MS_GRAPH}/directoryRoles/{role_object_id}/members/{user_id}/$ref"
        self.http_request("DELETE", full_url=full_url)

    def remove_member_from_group(self, group_id: str, user_id: str):
        """Currently not supported in the integration - token scope issues.
        Remove a single member to a group by sending a DELETE request.
        Args:
            group_id: the group id to add the member to.
            user_id: the user id to remove.
        """
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        #  Using resp_type="text" to avoid parsing error in the calling method.
        self.http_request(
            method="DELETE", full_url=f"{PREFIX_URL_MS_GRAPH}/groups/{group_id}/members/{user_id}/$ref", resp_type="text"
        )

    def list_network_security_groups(self, subscription_id: str, resource_group_name: str):
        """
        List all network security groups in a specific resource group.

        Args:
            subscription_id: The Azure subscription ID.
            resource_group_name: The resource group containing the network security groups.

        Return:
            A dictionary containing the list of network security groups.

        Docs:
            https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-security-groups/list?view=rest-virtualnetwork-2024-05-01
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Network/networkSecurityGroups"
        )
        try:
            return self.http_request(method="GET", full_url=full_url)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=resource_group_name,
                resource_type="Security Group",
                api_function_name="list_network_security_groups",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def delete_rule(self, security_group_name: str, security_rule_name: str, subscription_id: str, resource_group_name: str):
        """
        Delete a specific security rule from a network security group.

        Args:
            security_group_name: The name of the network security group.
            security_rule_name: The name of the security rule to delete.
            subscription_id: The Azure subscription ID.
            resource_group_name: The resource group containing the network security group.

        Return:
            The HTTP response object from the delete operation.

        Docs:
            https://learn.microsoft.com/en-us/rest/api/virtualnetwork/security-rules/delete?view=rest-virtualnetwork-2024-05-01
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Network/networkSecurityGroups/{security_group_name}"
            f"/securityRules/{security_rule_name}"
        )
        try:
            response = self.http_request(method="DELETE", full_url=full_url, resp_type="response")
            if response.status_code in (200, 202, 204):  # type: ignore[union-attr]
                return response
            else:
                demisto.debug("Failed to delete security rule.")
                response.raise_for_status()  # type: ignore[union-attr]
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{security_group_name}/{security_rule_name}",
                resource_type="Security Group",
                api_function_name="delete_rule",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def list_resource_groups_request(self, subscription_id: str, filter_by_tag: str, limit: str):
        """
        List resource groups in a subscription, optionally filtered by tag and limited in number.

        Args:
            subscription_id: The Azure subscription ID.
            filter_by_tag: An OData filter expression to filter resource groups by tag.
            limit: Maximum number of resource groups to return.

        Return:
            A dictionary containing the list of resource groups.

        Docs:
            https://learn.microsoft.com/en-us/rest/api/resources/resource-groups/list?view=rest-resources-2021-04-01
        """
        full_url = f"{PREFIX_URL_AZURE}{subscription_id}/resourcegroups"
        try:
            return self.http_request(method="GET", full_url=full_url, params={"$filter": filter_by_tag, "$top": limit})
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=subscription_id,
                resource_type="Resource Group",
                api_function_name="list_resource_groups_request",
                subscription_id=subscription_id,
                resource_group_name=None,
            )

    def list_networks_interfaces_request(self, subscription_id: str, resource_group_name: str):
        """
        List all network interfaces in a specific resource group.

        Args:
            subscription_id: The Azure subscription ID.
            resource_group_name: The resource group containing the network interfaces.

        Return:
            A dictionary containing the list of network interfaces.

        Docs:
            https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-interfaces/list?view=rest-virtualnetwork-2024-05-01
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}/"
            f"providers/Microsoft.Network/networkInterfaces"
        )
        try:
            return self.http_request(method="GET", full_url=full_url, params=NEW_API_VERSION_PARAMS)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=resource_group_name,
                resource_type="Network Interface",
                api_function_name="list_networks_interfaces_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def list_public_ip_addresses_request(self, subscription_id: str, resource_group_name: str):
        """
        List all public IP addresses in a specific resource group.

        Args:
            subscription_id: The Azure subscription ID.
            resource_group_name: The resource group containing the public IP addresses.

        Return:
            A dictionary containing the list of public IP addresses.

        Docs:
            https://learn.microsoft.com/en-us/rest/api/virtualnetwork/public-ip-addresses/list?view=rest-virtualnetwork-2024-05-01
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}/"
            f"providers/Microsoft.Network/publicIPAddresses"
        )
        try:
            return self.http_request(method="GET", full_url=full_url)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=resource_group_name,
                resource_type="Public IP Addresses",
                api_function_name="list_public_ip_addresses_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def start_vm_request(self, subscription_id: str, resource_group_name: str, vm_name: str):
        """
        Starts the specified virtual machine in a given resource group.

        Args:
            subscription_id (str): The ID of the Azure subscription.
            resource_group_name (str): The name of the resource group containing the virtual machine.
            vm_name (str): The name of the virtual machine to start.

        Returns:
            The HTTP response object of the start request.

        Docs:
            https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/start?view=rest-azure-2024-04-01
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Compute/"
            f"virtualMachines/{vm_name}/start"
        )
        try:
            response = self.http_request(
                method="POST", full_url=full_url, params={"api-version": VM_API_VERSION}, resp_type="response"
            )
            if response.status_code in (200, 202, 204):  # type: ignore[union-attr]
                return response
            else:
                demisto.debug(f"Failed to start vm {vm_name}.")
                response.raise_for_status()  # type: ignore[union-attr]
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{resource_group_name}/{vm_name}",
                resource_type="Virtual Machines",
                api_function_name="start_vm_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def poweroff_vm_request(self, subscription_id: str, resource_group_name: str, vm_name: str, skip_shutdown: bool):
        """
        Powers off the specified virtual machine in a given resource group.

        Args:
            subscription_id (str): The ID of the Azure subscription.
            resource_group_name (str): The name of the resource group containing the virtual machine.
            vm_name (str): The name of the virtual machine to power off.
            skip_shutdown (str): Whether to skip the OS shutdown before powering off.
                                Expected values are "true" or "false".

        Returns:
            The HTTP response object of the power-off request.

        Docs:
            https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/power-off?view=rest-azure-2024-04-01
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Compute/"
            f"virtualMachines/{vm_name}/powerOff"
        )
        parameters = {"skipShutdown": skip_shutdown} | {"api-version": VM_API_VERSION}
        try:
            response = self.http_request(method="POST", full_url=full_url, params=parameters, resp_type="response")
            if response.status_code in (200, 202, 204):  # type: ignore[union-attr]
                return response
            else:
                demisto.debug(f"Failed to power off vm {vm_name}.")
                response.raise_for_status()  # type: ignore[union-attr]
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{resource_group_name}/{vm_name}",
                resource_type="Virtual Machines",
                api_function_name="poweroff_vm_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def get_vm_request(self, subscription_id: str, resource_group_name: str, vm_name: str, expand: str = "instanceView"):
        """
        Gets the specified virtual machine in a given resource group.

        Args:
            subscription_id (str): The ID of the Azure subscription.
            resource_group_name (str): The name of the resource group containing the virtual machine.
            vm_name (str): The name of the virtual machine.
            expand (str, optional): Additional properties to include in the response. Defaults to "instanceView".

        Returns:
            The detailed virtual machine object, including optional expanded properties.

        Docs:
            https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/get?view=rest-azure-2024-04-01
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Compute/"
            f"virtualMachines/{vm_name}"
        )
        parameters = {"$expand": expand, "api-version": VM_API_VERSION}
        try:
            return self.http_request(method="GET", full_url=full_url, params=parameters)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{resource_group_name}/{vm_name}",
                resource_type="Virtual Machines",
                api_function_name="get_vm_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def validate_provisioning_state(self, subscription_id, resource_group, vm_name):
        """
        Ensure that the provisioning state of a VM is 'Succeeded'

        For all provisioning states other than 'Succeeded', this method will raise an
        exception with an informative error message.

        parameter: (dict) args
            The command arguments passed to either the `azure-vm-instance-start` or
            `azure-vm-poweroff-instance` commands

        returns:
            None
        """
        creating_or_updating_err = (
            "Please wait for the VM to finish being"
            " {} before executing this command. To retrieve the "
            "last known state of the VM, execute the "
            "`azure-vm-instance-details-get` command. "
        )
        deleting_err = "You cannot execute this command because the VM is being deleted."
        failed_err = (
            "Unable to power-off or power-on '{}' virtual machine "
            "because the following provisioning failure occurred during "
            'the vm\'s creation.\ncode: "{}"\nmessage: "{}"\nVisit the '
            "Azure Web Portal to take care of this issue."
        )
        provisioning_state_to_errors = {
            "creating": creating_or_updating_err.format("created"),
            "updating": creating_or_updating_err.format("updated"),
            "deleting": deleting_err,
            "failed": failed_err,
        }
        response = self.get_vm_request(subscription_id=subscription_id, resource_group_name=resource_group, vm_name=vm_name)

        properties = response.get("properties")
        provisioning_state = properties.get("provisioningState")
        statuses = properties.get("instanceView", {}).get("statuses")

        # Check if the current ProvisioningState of the VM allows for executing this command
        if provisioning_state.lower() == "failed":
            for status in statuses:
                status_code = status.get("code")
                if "provisioningstate/failed" in status_code.lower():
                    message = status.get("message")
                    err_msg = provisioning_state_to_errors.get("failed")
                    raise Exception(err_msg.format(vm_name, status_code, message))  # type: ignore
            # If the Microsoft API changes and the status code is no longer
            # relevant, preventing the above exception with its detailed error message from
            # being raised, then raise the below exception with a more general error message
            err_msg = "Cannot execute this command because the ProvisioningState of the VM is 'Failed'."
            raise Exception(err_msg)
        elif provisioning_state.lower() in provisioning_state_to_errors:
            err_msg = provisioning_state_to_errors.get(provisioning_state.lower())
            raise Exception(err_msg)

    def get_network_interface_request(self, subscription_id: str, resource_group_name: str, interface_name: str):
        """
        Gets the specified network interface in a given resource group.

        Args:
            subscription_id (str): The ID of the Azure subscription.
            resource_group_name (str): The name of the resource group containing the network interface.
            interface_name (str): The name of the network interface.

        Returns:
            The detailed network interface object.

        Docs:
            https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-interfaces/get?view=rest-virtualnetwork-2023-05-01
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Network/"
            f"networkInterfaces/{interface_name}"
        )
        try:
            return self.http_request(method="GET", full_url=full_url, params={"api-version": "2023-05-01"})
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{resource_group_name}/{interface_name}",
                resource_type="Network Interfaces",
                api_function_name="get_network_interface_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def get_public_ip_details_request(self, subscription_id: str, resource_group_name: str, address_name: str):
        """
        Gets the specified public IP address in a given resource group.

        Args:
            subscription_id (str): The ID of the Azure subscription.
            resource_group_name (str): The name of the resource group containing the public IP.
            address_name (str): The name of the public IP address.

        Returns:
            The detailed public IP address object.

        Docs:
            https://learn.microsoft.com/en-us/rest/api/virtualnetwork/public-ip-addresses/get?view=rest-virtualnetwork-2024-10-01
        """
        full_url = (
            f"{PREFIX_URL_AZURE}{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Network/"
            f"publicIPAddresses/{address_name}"
        )
        try:
            return self.http_request(method="GET", full_url=full_url, params={"api-version": "2023-05-01"})
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{resource_group_name}/{address_name}",
                resource_type="Public IP Addresses",
                api_function_name="get_public_ip_details_request",
                subscription_id=subscription_id,
                resource_group_name=resource_group_name,
            )

    def get_all_public_ip_details_request(self, subscription_id: str):
        """
        Lists all public IP addresses in the specified Azure subscription.

        Args:
            subscription_id (str): The ID of the Azure subscription.

        Returns:
            List of PublicIPAddressListResult objects.

        Docs:
            https://learn.microsoft.com/en-us/rest/api/virtualnetwork/public-ip-addresses/list-all?tabs=HTTP
        """
        full_url = f"{PREFIX_URL_AZURE}{subscription_id}/providers/Microsoft.Network/publicIPAddresses"
        try:
            return self.http_request(method="GET", full_url=full_url)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=f"{subscription_id}",
                resource_type="Public IP Addresses",
                api_function_name="get_all_public_ip_details_request",
                subscription_id=subscription_id,
                resource_group_name=None,
            )

    def billing_usage_list(
        self,
        subscription_id: str,
        expand: str = "",
        filter_: str = "",
        metric: str = "",
        max_results: int = 50,
        next_page_token: str = "",
    ):
        """
        Retrieves actual usage and cost details from Azure Consumption API.
        Args:
            subscription_id (str): Azure subscription ID.
            expand (str): Expand usage details with additional properties.
            filter_ (str): OData filter expression for filtering results.
            metric (str): Specific metric to retrieve (e.g., ActualCost, UsageQuantity).
            max_results (int): Maximum number of results to return (default: 50).
            next_page_token (str): Token for pagination.
        Returns:
            dict: The response from the Azure Consumption API.
        Raises:
            DemistoException: If Azure API call fails, subscription not found, or invalid parameters provided
        """
        scope = f"/{subscription_id}"
        url = f"{scope}/providers/Microsoft.Consumption/usageDetails"
        api_version = "2024-08-01"
        params_ = {
            "$expand": expand,
            "$filter": filter_,
            "metric": metric.lower().replace(" ", ""),
            "api-version": api_version,
            "$top": max_results,
        }
        remove_nulls_from_dictionary(params_)

        try:
            if next_page_token:
                new_url = remove_query_param_from_url(next_page_token, "api-version")
                demisto.debug(f"Azure billing usage request (pagination): {new_url}")
                return self.http_request("GET", full_url=new_url, params={"api-version": api_version})
            else:
                demisto.debug(f"Azure billing usage request: {url}, params: {params_}")
                return self.http_request("GET", url_suffix=url, params=params_)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=subscription_id,
                resource_type="Usage Details",
                subscription_id=subscription_id,
                api_function_name="billing_usage_list",
            )

    def billing_forecast_list(
        self,
        subscription_id: str,
        forecast_type: str,
        aggregation_function_name: str,
        aggregation_function_type: str = "Sum",
        granularity: str = "Daily",
        start_date: str = "",
        end_date: str = "",
        filter_param: str = "",
        include_actual_cost: bool = False,
        include_fresh_partial_cost: bool = False,
    ):
        """
        Returns cost forecast for a subscription over a given time range.
        Args:
            subscription_id (str): Azure subscription ID.
            forecast_type (str): Forecast type (Usage, ActualCost, AmortizedCost).
            aggregation_function_name (str): Aggregation function name.
            aggregation_function_type (str): Aggregation function type (default: "Sum").
            granularity (str): Data granularity (default: "Daily").
            start_date (str): Start date for the forecast.
            end_date (str): End date for the forecast.
            filter_param (str): URL parameter to filter forecasts.
            include_actual_cost (bool): Include actual cost data (default: False).
            include_fresh_partial_cost (bool): Include fresh partial cost data (default: False).
        Returns:
            dict: The response from the Azure Cost Management API.
        Raises:
            DemistoException: If Azure API call fails, subscription not found, or invalid parameters provided
        """

        start_datetime = arg_to_datetime(start_date) or datetime.now(UTC)
        end_datetime = arg_to_datetime(end_date) or (datetime.now(UTC) + timedelta(days=7))

        url = f"{subscription_id}/providers/Microsoft.CostManagement/forecast"
        api_version = "2025-03-01"

        body: dict[str, Any] = {
            "type": forecast_type,
            "timeframe": "Custom",
            "timePeriod": {
                "from": start_datetime.strftime("%Y-%m-%dT00:00:00Z"),
                "to": end_datetime.strftime("%Y-%m-%dT00:00:00Z"),
            },
            "dataset": {
                "granularity": granularity,
                "aggregation": {
                    "totalCost": {
                        "function": aggregation_function_type,
                        "name": aggregation_function_name,
                    }
                },
            },
        }
        if include_actual_cost:
            body["includeActualCost"] = include_actual_cost
        if include_fresh_partial_cost:
            body["includeFreshPartialCost"] = include_fresh_partial_cost

        if filter_param:
            body["dataset"]["filter"] = filter_param  # type: ignore[index]

        demisto.debug(f"Azure billing forecast \nrequest body: \n{body}")
        params_ = {"api-version": api_version}

        try:
            return self.http_request("POST", url_suffix=url, params=params_, json_data=body)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=subscription_id,
                resource_type="Cost Forecast",
                subscription_id=subscription_id,
                api_function_name="billing_forecast_list",
            )

    def billing_budgets_list(
        self,
        subscription_id: str,
        budget_name: str = "",
    ):
        """
        Retrieves budget information from Azure Consumption API.
        Args:
            subscription_id (str): Azure subscription ID.
            budget_name (str): Optional specific budget name to retrieve.
        Returns:
            dict: The response from the Azure Consumption API.
        Raises:
            DemistoException: If Azure API call fails, subscription not found, or invalid parameters provided
        """
        scope = f"/{subscription_id}"
        if budget_name:
            url = f"{scope}/providers/Microsoft.Consumption/budgets/{budget_name}"
        else:
            url = f"{scope}/providers/Microsoft.Consumption/budgets"

        api_version = "2024-08-01"
        params_ = {"api-version": api_version}

        demisto.debug(f"Azure billing budgets request: {url}, params: {params_}")
        try:
            return self.http_request("GET", url_suffix=url, params=params_)
        except Exception as e:
            self.handle_azure_error(
                e=e,
                resource_name=budget_name or subscription_id,
                resource_type="Budget",
                subscription_id=subscription_id,
                api_function_name="billing_budgets_list",
            )


""" HELPER FUNCTIONS """


def get_permissions_from_api_function_name(api_function_name: str, error_msg: str) -> list:
    """
    Extract the relevant missing permission by checking command-to-permissions mapping against an error message.
    Iterates over the permissions mapped to a specific API function and returns the relevant permissions
    that appear in the given error message.

    Args:
        api_function_name (str): The name of the API function used for permission lookup.
        error_msg (str): The error message string to check for missing permissions.

    Returns:
        list: The matching permission names if found, otherwise an empty list.
    """
    permission_names = []
    for permission in API_FUNCTION_TO_PERMISSIONS[api_function_name]:
        if permission.lower() in error_msg.lower():
            demisto.debug(f"Found missing permission via command mapping: {permission}")
            permission_names.append(permission)
    return permission_names


def get_permissions_from_required_role_permissions_list(error_msg: str) -> list:
    """
    Extract the relevant missing permission by searching the required role permissions list against an error message.
    Iterates over the predefined required role permissions and returns the relevant permissions
    that appear in the given error message.

    Args:
        error_msg (str): The error message string to check for missing permissions.

    Returns:
        list: The matching permission names if found, otherwise an empty list.
    """
    permission_names = []
    permissions_to_check = set(REQUIRED_ROLE_PERMISSIONS)
    for permission in permissions_to_check:
        if permission.lower() in error_msg.lower():
            demisto.debug(f"Found missing permission via fallback search: {permission}")
            permission_names.append(permission)

    if not permission_names:
        permission_names.append("N/A")

    return permission_names


def format_rule(rule_json: dict | list, security_rule_name: str):
    """
    Format the rule and create the commandResult object with it
    Args:
        rule_json: the json returned from the http_request
        security_rule_name: the name of the rule

    Returns:
        CommandResults for the rule
    """
    # We want to flatten the rules `properties` key as this is the more important key, and we'd like
    # to be able to display it nicely
    if isinstance(rule_json, dict):
        rule_json.update(rule_json.pop("properties", {}))
    if isinstance(rule_json, list):
        for rule in rule_json:
            rule.update(rule.pop("properties", {}))

    hr = tableToMarkdown(f"Rules {security_rule_name}", rule_json, removeNull=True)

    return CommandResults(outputs_prefix="Azure.NSGRule", outputs_key_field="id", outputs=rule_json, readable_output=hr)


def extract_azure_resource_info(resource_id: str) -> tuple[str | None, str | None, str | None]:
    """Extract subscription ID, resource group, and account name from Azure resource ID.

    Args:
        resource_id: Azure resource ID string

    Returns:
        Tuple of (subscription_id, resource_group, account_name)
    """
    patterns = {
        "subscription_id": r"subscriptions/(.+?)/resourceGroups",
        "resource_group": r"resourceGroups/(.+?)/providers",
        "account_name": r"storageAccounts/(.+?)/blobServices",
    }

    results = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, resource_id)
        results[key] = match.group(1) if match else None

    return results["subscription_id"], results["resource_group"], results["account_name"]


def remove_query_param_from_url(url: str, param: str) -> str:
    """
    Remove a specific query parameter from a given URL and return the updated URL.

    Args:
        url (str): The full URL that may contain a query string.
        param (str): The name of the query parameter to remove.

    Returns:
        str: The URL with the specified query parameter removed. If the parameter
             is not present, the original URL is returned unchanged.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs.pop(param, None)
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


""" COMMAND FUNCTIONS """


def update_security_rule_command(client: AzureClient, params: dict, args: dict) -> CommandResults:
    """
    Update an existing rule.

    As I couldn't find a way to just update specific fields, the command gets the existing rule, then updates
    the wanted fields and sends that as a "new" rule. This will update the rule and not create a new rule.

    Args:
        client: The MS Client
        params: configuration parameters
        args: args dictionary.

    Returns:
    an updated rule
    """
    security_group_name = args.get("security_group_name", "")
    security_rule_name = args.get("security_rule_name", "")
    direction = args.get("direction", "")
    action = args.get("action", "")
    protocol = args.get("protocol", "")
    source = args.get("source", "")
    source_ports = args.get("source_ports", "")
    destination = args.get("destination", "")
    destination_ports = args.get("destination_ports", "")
    priority = args.get("priority", "")
    description = args.get("description", "")
    access = args.get("access", "")
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")

    rule = client.get_rule(
        security_group=security_group_name,
        rule_name=security_rule_name,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
    )
    properties = rule.get("properties")

    updated_properties = assign_params(
        protocol="*" if protocol == "Any" else protocol,
        access=action,
        priority=priority,
        direction=direction,
        description=description,
    )
    if source_ports:
        source_ports_list = argToList(source_ports)
        if len(source_ports_list) > 1:
            properties.pop("sourcePortRange", None)  # Can't supply both sourcePortRange and sourcePortRanges
            updated_properties["sourcePortRanges"] = source_ports_list
        else:
            properties.pop("sourcePortRanges", None)  # Can't supply both sourcePortRange and sourcePortRanges
            updated_properties["sourcePortRange"] = source_ports

    if destination_ports:
        dest_ports_list = argToList(destination_ports)
        if len(dest_ports_list) > 1:
            properties.pop("destinationPortRange", None)  # Can't supply both destinationPortRange,destinationPortRanges
            updated_properties["destinationPortRanges"] = dest_ports_list
        else:
            properties.pop("destinationPortRanges", None)  # Can't supply destinationPortRange and destinationPortRanges
            updated_properties["destinationPortRange"] = destination_ports

    if destination:
        dest_list = argToList(destination)
        if len(dest_list) > 1:
            properties.pop("destinationAddressPrefix", None)  # Can't supply both destinationAddressPrefix and
            # destinationAddressPrefix
            updated_properties["destinationAddressPrefixes"] = dest_list
        else:
            properties.pop("destinationAddressPrefixes", None)  # Can't supply both
            # destinationAddressPrefixes, destinationAddressPrefixes
            updated_properties["destinationAddressPrefix"] = "*" if destination == "Any" else destination

    if source:
        source_list = argToList(source)
        if len(source_list) > 1:
            properties.pop("sourceAddressPrefix", None)  # Can't supply both sourceAddressPrefixes, sourceAddressPrefix
            updated_properties["sourceAddressPrefixes"] = source_list
        else:
            properties.pop("sourceAddressPrefixes", None)  # Can't supply both sourceAddressPrefixes,sourceAddressPrefix
            updated_properties["sourceAddressPrefix"] = "*" if source == "Any" else source

    properties.update(updated_properties)
    if access:
        properties.update({"access": access})

    rule = client.create_or_update_rule(
        security_group=security_group_name,
        rule_name=security_rule_name,
        properties=properties,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
    )

    return format_rule(rule, security_rule_name)


def storage_account_update_command(client: AzureClient, params: dict, args: dict) -> CommandResults | str:
    """
        Creates or updates a given storage account.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments, (like account name).

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    # subscription_id = args.get("subscription_id")
    # resource_group_name = args.get("resource_group_name")
    response = client.storage_account_update_request(
        subscription_id=subscription_id, resource_group_name=resource_group_name, args=args
    )
    if not response.text:
        return f"The request was accepted - the account {args.get('account_name')} will be created shortly."

    response = response.json()

    readable_output = {
        "Account Name": response.get("name"),
        "Subscription ID": subscription_id,
        "Resource Group": resource_group_name,
        "Network Ruleset Bypass": response.get("properties", {}).get("networkAcls", {}).get("bypass")
        if args.get("network_ruleset_bypass")
        else None,
        "Default Action": response.get("properties", {}).get("networkAcls", {}).get("defaultAction")
        if args.get("network_ruleset_default_action")
        else None,
        "Allow Cross Tenant Replication": response.get("properties", {}).get("allowCrossTenantReplication")
        if args.get("allow_cross_tenant_replication")
        else None,
        "Supports Https Traffic Only": response.get("properties", {}).get("supportsHttpsTrafficOnly")
        if args.get("supports_https_traffic_only")
        else None,
    }

    return CommandResults(
        outputs_prefix="Azure.StorageAccount",
        outputs_key_field="id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Azure Storage Account",
            readable_output,
            [
                "Account Name",
                "Subscription ID",
                "Resource Group",
                "Network Ruleset Bypass",
                "Default Action",
                "Allow Cross Tenant Replication",
                "Supports Https Traffic Only",
            ],
            removeNull=True,
        ),
        raw_response=response,
    )


def storage_blob_service_properties_set_command(client: AzureClient, params: dict, args: dict):
    """
        Sets the blob service properties for the storage account.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments, (like account name).

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    # subscription_id = args.get("subscription_id")
    # resource_group_name = args.get("resource_group_name")
    delete_rentention_policy_enabled = args.get("delete_rentention_policy_enabled")
    delete_rentention_policy_days = args.get("delete_rentention_policy_days")
    account_name = args.get("account_name", "")

    response = client.storage_blob_service_properties_set_request(
        subscription_id, resource_group_name, account_name, delete_rentention_policy_enabled, delete_rentention_policy_days
    )

    readable_output = {
        "Name": response.get("name"),
        "ID": response.get("id"),
        "Delete Retention Policy": response.get("properties", {}).get("deleteRetentionPolicy")
        if args.get("delete_rentention_policy_enabled") or args.get("delete_rentention_policy_days")
        else None,
    }

    return CommandResults(
        outputs_prefix="Azure.StorageAccountBlobServiceProperties",
        outputs_key_field="id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Updated Azure Storage Blob Service Properties",
            readable_output,
            ["Name", "ID", "Delete Retention Policy"],
            removeNull=True,
        ),
        raw_response=response,
    )


def storage_blob_containers_update_command(client: AzureClient, params: dict, args: dict):
    """
        Updates a given blob container.
    Args:
        client: The Microsoft client.
        params: The configuration parameters.
        args: User-provided arguments, such as the account name and container name.

    Returns:
        CommandResults: The command results, including the Markdown table and context data.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")

    response = client.storage_blob_containers_create_update_request(
        subscription_id=subscription_id, resource_group_name=resource_group_name, args=args, method="PATCH"
    )

    subscription_id, resource_group, account_name = extract_azure_resource_info(response.get("id", ""))

    readable_output = {
        "Name": response.get("name", ""),
        "Account Name": account_name,
        "Subscription ID": subscription_id,
        "Resource Group": resource_group,
        "Public Access": response.get("properties", {}).get("publicAccess"),
    }

    return CommandResults(
        outputs_prefix="Azure.StorageBlobContainer",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name="Azure Storage Blob Containers Properties",
            t=readable_output,
            headers=["Name", "Account Name", "Subscription ID", "Resource Group", "Public Access"],
            removeNull=True,
        ),
    )


def storage_blob_service_properties_get_command(client: AzureClient, params: dict, args: dict):
    """
        Gets the blob service properties for the storage account.
    Args:
        client: The AzureClient client.
        params: The configuration parameters.
        args: User-provided arguments, such as the account name and container name.

    Returns:
        CommandResults: The command results, including the Markdown table and context data.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    account_name = args.get("account_name", "")
    response = client.storage_blob_service_properties_get_request(
        account_name=account_name, resource_group_name=resource_group_name, subscription_id=subscription_id
    )
    subscription_id, resource_group, account_name = extract_azure_resource_info(response.get("id", ""))

    readable_output = {
        "Name": response.get("name", ""),
        "Account Name": account_name,
        "Subscription ID": subscription_id,
        "Resource Group": resource_group,
        "Change Feed": response.get("properties", {}).get("changeFeed", {}).get("enabled", ""),
        "Delete Retention Policy": response.get("properties", {}).get("deleteRetentionPolicy", {}).get("enabled", ""),
        "Versioning": response.get("properties", {}).get("isVersioningEnabled"),
    }

    return CommandResults(
        outputs_prefix="Azure.StorageBlobServiceProperties",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name="Azure Storage Blob Service Properties",
            t=readable_output,
            headers=[
                "Name",
                "Account Name",
                "Subscription ID",
                "Resource Group",
                "Change Feed",
                "Delete Retention Policy",
                "Versioning",
            ],
            removeNull=True,
        ),
    )


def create_policy_assignment_command(client: AzureClient, params: dict, args: dict):
    """
        Creates a policy assignment.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments.

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    name = args.get("name", "")
    scope = args.get("scope", "")
    policy_definition_id: str = args.get("policy_definition_id", "")
    display_name = args.get("display_name", "")
    parameters = json.loads(args.get("parameters", "{}"))
    description = args.get("description", "")
    response = client.create_policy_assignment(name, policy_definition_id, display_name, parameters, description, scope)
    outputs = [
        {
            "Name": response.get("name"),
            "Policy Definition ID": response.get("properties", {}).get("policyDefinitionId", ""),
            "Display Name": response.get("properties", {}).get("displayName", ""),
            "Description": response.get("properties", {}).get("description", ""),
            "ID": response.get("id"),
            "Parameters": response.get("properties", {}).get("parameters") if parameters else None,
        }
    ]
    md = tableToMarkdown(
        f"Azure policy assignment {name} was successfully created.",
        outputs,
        ["ID", "Name", "Policy Definition ID", "Display Name", "Description", "Parameters"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="Azure.PolicyAssignment",
        outputs_key_field="id",
        outputs=response,
        readable_output=md,
        raw_response=outputs,
    )


def set_postgres_config_command(client: AzureClient, params: dict, args: dict):
    """
        Updates a configuration of PostgreSQL server.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments.

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    server_name = args.get("server_name", "")
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    configuration_name = args.get("configuration_name", "")
    source = args.get("source", "")
    value = args.get("value", "")
    client.set_postgres_config(server_name, subscription_id, resource_group_name, configuration_name, source, value)
    return CommandResults(readable_output=f"Updated the configuration {configuration_name} of the server {server_name}.")


def set_webapp_config_command(client: AzureClient, params: dict, args: dict):
    """
        Sets WebApp configurations.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments.

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    name = args.get("name", "")
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    http20_enabled = args.get("http20_enabled", "")
    remote_debugging_enabled = args.get("remote_debugging_enabled", "")
    min_tls_version = args.get("min_tls_version", "")
    response = client.set_webapp_config(
        name, subscription_id, resource_group_name, http20_enabled, remote_debugging_enabled, min_tls_version
    )
    outputs = [
        {
            "Name": response.get("name"),
            "Http20 Enabled": response.get("properties", {}).get("http20Enabled", "") if http20_enabled else None,
            "Remote Debugging Enabled": response.get("properties", {}).get("remoteDebuggingEnabled", "")
            if remote_debugging_enabled
            else None,
            "Min Tls Version": response.get("properties", {}).get("minTlsVersion", "") if min_tls_version else None,
            "ID": response.get("id"),
        }
    ]
    md = tableToMarkdown(
        f"Web App configuration for {name} was updated successfully.",
        outputs,
        ["Name", "Http20 Enabled", "Remote Debugging Enabled", "Min Tls Version", "ID"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="Azure.WebAppConfig",
        outputs_key_field="id",
        outputs=response,
        readable_output=md,
        raw_response=outputs,
    )


def update_webapp_auth_command(client: AzureClient, params: dict, args: dict):
    """
        Sets WebApp authentication.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments.

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    name = args.get("name", "")
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    enabled = args.get("enabled", "")
    response = client.update_webapp_auth(name, subscription_id, resource_group_name, enabled)
    demisto.debug("Updated webapp auth settings.")
    outputs = [
        {
            "Name": name,
            "Enabled": response.get("properties", {}).get("enabled", "") if enabled else None,
            "ID": response.get("id"),
        }
    ]
    md = tableToMarkdown(
        f"Authentication settings for Web App {name} updated successfully.",
        outputs,
        ["Name", "Enabled", "ID"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="Azure.WebAppAuth",
        outputs_key_field="id",
        outputs=response,
        readable_output=md,
        raw_response=outputs,
    )


def mysql_flexible_server_param_set_command(client: AzureClient, params: dict, args: dict):
    """
        Updates a configuration of MySQL flexible server.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments.

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    configuration_name = args.get("configuration_name", "")
    server_name = args.get("server_name", "")
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    source = args.get("source", "")
    value = args.get("value", "")
    client.flexible_server_param_set(server_name, configuration_name, subscription_id, resource_group_name, source, value)
    return CommandResults(readable_output=f"Updated the configuration {configuration_name} of the server {server_name}.")


def monitor_log_profile_update_command(client: AzureClient, params: dict, args: dict):
    """
        Updates a monitor log profile.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments.

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    log_profile_name = args.get("log_profile_name", "")
    location = args.get("location")
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    retention_policy_days = arg_to_number(args.get("retention_policy_days"))
    retention_policy_enabled = args.get("retention_policy_enabled")
    current_log_profile = client.get_monitor_log_profile(subscription_id, log_profile_name)
    current_log_profile["properties"]["retentionPolicy"]["enabled"] = (
        retention_policy_enabled
        if retention_policy_enabled is not None
        else current_log_profile.get("properties", {}).get("retentionPolicy", {}).get("enabled")
    )
    current_log_profile["properties"]["retentionPolicy"]["days"] = (
        retention_policy_days
        if retention_policy_days
        else current_log_profile.get("properties", {}).get("retentionPolicy", {}).get("days")
    )
    current_log_profile["location"] = location if location else current_log_profile.get("location")
    response = client.monitor_log_profile_update(subscription_id, log_profile_name, current_log_profile)
    outputs = [
        {
            "Name": response.get("name"),
            "ID": response.get("id"),
            "Location": response.get("location", "") if location else None,
            "Retention Policy": response.get("properties", {}).get("retentionPolicy")
            if (retention_policy_enabled or retention_policy_days)
            else None,
        }
    ]
    md = tableToMarkdown(
        f"Log profile {log_profile_name} updated successfully.",
        outputs,
        ["Name", "ID", "Location", "Retention Policy"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="Azure.LogProfile",
        outputs_key_field="id",
        outputs=response,
        readable_output=md,
        raw_response=outputs,
    )


def disk_update_command(client: AzureClient, params: dict, args: dict):
    """
        Updates a disk.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments.

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    disk_name = args.get("disk_name", "")
    public_network_access = args.get("public_network_access")
    network_access_policy = args.get("network_access_policy")
    data_access_auth_mode = args.get("data_access_auth_mode")
    response = client.disk_update(
        subscription_id, resource_group_name, disk_name, public_network_access, network_access_policy, data_access_auth_mode
    )
    outputs = [
        {
            "Name": response.get("name"),
            "ID": response.get("id"),
            "Public Network Access": response.get("properties", {}).get("publicNetworkAccess") if public_network_access else None,
            "Network Access Policy": response.get("properties", {}).get("networkAccessPolicy") if network_access_policy else None,
            "Data Access Auth Mode": response.get("properties", {}).get("dataAccessAuthMode") if data_access_auth_mode else None,
        }
    ]
    md = tableToMarkdown(
        f"Disk {disk_name} updated successfully.",
        outputs,
        ["Name", "ID", "Public Network Access", "Network Access Policy", "Data Access Auth Mode"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="Azure.Disk",
        outputs_key_field="id",
        outputs=response,
        readable_output=md,
        raw_response=outputs,
    )


def webapp_update_command(client: AzureClient, params: dict, args: dict):
    """
    Updates an Azure web application with specified settings.

    Args:
        client (AzureClient): The Azure client instance.
        params (dict): Configuration parameters.
        args (dict): Command arguments including web app name, identity type, HTTPS settings, etc.

    Returns:
        CommandResults: The updated web app configuration formatted for display.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    name = args.get("name", "")
    identity_type = args.get("identity_type")
    https_only = args.get("https_only")
    client_cert_enabled = args.get("client_cert_enabled")
    response = client.webapp_update(subscription_id, resource_group_name, name, identity_type, https_only, client_cert_enabled)
    outputs = [
        {
            "Name": response.get("name"),
            "ID": response.get("id"),
            "Identity": response.get("identity", {}) if identity_type else None,
            "Https Only": response.get("properties", {}).get("httpsOnly") if https_only else None,
            "Client Cert Enabled": response.get("properties", {}).get("clientCertEnabled") if client_cert_enabled else None,
        }
    ]
    md = tableToMarkdown(
        f"Updated the Web App {name}.",
        outputs,
        ["Name", "ID", "Identity", "Https Only", "Client Cert Enabled"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="Azure.WebApp",
        outputs_key_field="id",
        outputs=response,
        readable_output=md,
        raw_response=outputs,
    )


def acr_update_command(client: AzureClient, params: dict, args: dict):
    """
    Updates an Azure Container Registry with specified settings.

    Args:
        client (AzureClient): The Azure client instance.
        params (dict): Configuration parameters.
        args (dict): Command arguments including registry name, access settings, etc.

    Returns:
        CommandResults: The updated container registry configuration formatted for display.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    registry_name = args.get("registry_name", "")
    allow_exports = args.get("allow_exports")
    public_network_access = args.get("public_network_access")
    anonymous_pull_enabled = args.get("anonymous_pull_enabled")
    authentication_as_arm_policy = args.get("authentication_as_arm_policy")
    response = client.acr_update(
        subscription_id,
        resource_group_name,
        registry_name,
        allow_exports,
        public_network_access,
        anonymous_pull_enabled,
        authentication_as_arm_policy,
    )
    outputs = [
        {
            "Name": response.get("name"),
            "ID": response.get("id"),
            "Public Network Access": response.get("properties", {}).get("publicNetworkAccess") if public_network_access else None,
            "Anonymous Pull Enabled": response.get("properties", {}).get("anonymousPullEnabled")
            if anonymous_pull_enabled
            else None,
            "Allow Exports": response.get("properties", {}).get("policies", {}).get("exportPolicy", {}).get("status")
            if allow_exports
            else None,
            "Authentication As Arm Policy": response.get("properties", {})
            .get("policies", {})
            .get("azureADAuthenticationAsArmPolicy", {})
            .get("status")
            if authentication_as_arm_policy
            else None,
        }
    ]
    md = tableToMarkdown(
        f"Updated the container registry {registry_name}.",
        outputs,
        ["Name", "ID", "Public Network Access", "Anonymous Pull Enabled", "Allow Exports", "Authentication As Arm Policy"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="Azure.ACR",
        outputs_key_field="id",
        outputs=response,
        readable_output=md,
        raw_response=outputs,
    )


def postgres_server_update_command(client: AzureClient, params: dict, args: dict):
    """
    Updates a PostgreSQL server with specified SSL enforcement settings.

    Args:
        client (AzureClient): The Azure client instance.
        params (dict): Configuration parameters.
        args (dict): Command arguments including server name and SSL enforcement state.

    Returns:
        CommandResults: The updated PostgreSQL server configuration.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    server_name = args.get("server_name", "")
    ssl_enforcement = args.get("ssl_enforcement", "")
    client.postgres_server_update(subscription_id, resource_group_name, server_name, ssl_enforcement)
    return CommandResults(readable_output=f"Updated postgreSQL server {server_name}.")


def update_key_vault_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]) -> CommandResults:
    """
        updates a key vault.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments.

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    vault_name = args.get("vault_name", "")
    enable_soft_delete = args.get("enable_soft_delete", "")
    enable_purge_protection = args.get("enable_purge_protection", "")
    response = client.update_key_vault_request(
        subscription_id, resource_group_name, vault_name, enable_soft_delete, enable_purge_protection
    )
    outputs = [
        {
            "Name": response.get("name"),
            "ID": response.get("id"),
            "Enable Soft Delete": response.get("properties", {}).get("enableSoftDelete") if enable_soft_delete else None,
            "Enable Purge Protection": response.get("properties", {}).get("enablePurgeProtection")
            if enable_purge_protection
            else None,
        }
    ]
    readable_output = tableToMarkdown(
        f"Updated Key Vault {vault_name}.",
        outputs,
        ["ID", "Name", "Enable Soft Delete", "Enable Purge Protection"],
        removeNull=True,
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        outputs_prefix="Azure.KeyVault",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
        readable_output=readable_output,
        ignore_auto_extract=True,
    )


def sql_db_threat_policy_update_command(client: AzureClient, params: dict[str, Any], args: Dict[str, Any]) -> CommandResults:
    """
    Updates the threat detection policy for a SQL database.

    Args:
        client (AzureClient): The Azure client instance.
        params (dict): Configuration parameters.
        args (dict): Command arguments including server name, database name, and email settings.

    Returns:
        CommandResults: The updated threat detection policy configuration formatted for display.
    """
    server_name = args.get("server_name", "")
    db_name = args.get("db_name", "")
    email_account_admins = args.get("email_account_admins_enabled", "")
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")

    current_db = client.sql_db_threat_policy_get(
        server_name=server_name, db_name=db_name, subscription_id=subscription_id, resource_group_name=resource_group_name
    )
    current_db["properties"]["emailAccountAdmins"] = email_account_admins or current_db.get("properties", {}).get(
        "emailAccountAdmins"
    )
    response = client.sql_db_threat_policy_update(
        server_name=server_name,
        db_name=db_name,
        subscription_id=subscription_id,
        current=current_db,
        resource_group_name=resource_group_name,
    )

    outputs = [
        {
            "Name": response.get("name"),
            "ID": response.get("id"),
            "Email Account Admins": response.get("properties", {}).get("emailAccountAdmins") if email_account_admins else None,
        }
    ]
    readable_output = tableToMarkdown(
        f"Updated Database Threat Detection Policies for {resource_group_name=}",
        outputs,
        ["ID", "Name", "Email Account Admins"],
        removeNull=True,
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Azure.SqlDBThreatPolicy",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def sql_db_tde_set_command(client: AzureClient, params: dict[str, Any], args: Dict[str, Any]) -> CommandResults:
    """
    Sets the transparent data encryption state for a SQL database.

    Args:
        client (AzureClient): The Azure client instance.
        params (dict): Configuration parameters.
        args (dict): Command arguments including server name, database name, and TDE state.

    Returns:
        CommandResults: A message indicating successful TDE state update.
    """
    server_name = args.get("server_name", "")
    db_name = args.get("db_name", "")
    state = args.get("state", "")
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    client.sql_db_tde_set(
        server_name=server_name,
        db_name=db_name,
        subscription_id=subscription_id,
        state=state,
        resource_group_name=resource_group_name,
    )
    # CommandResults don't contain the response because it takes time for the resource to be updated.
    return CommandResults(
        readable_output=f"Updated SQL database {db_name} of the server {server_name}.",
    )


def cosmosdb_update_command(client: AzureClient, params: dict[str, Any], args: Dict[str, Any]) -> CommandResults:
    """
        Updates a Cosmos DB account with specified settings.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments.

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    account_name = args.get("account_name", "")
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    disable_key_based_metadata_write_access = args.get("disable_key_based_metadata_write_access")
    response = client.cosmos_db_update(
        subscription_id, resource_group_name, account_name, disable_key_based_metadata_write_access
    )

    return CommandResults(
        readable_output=f"Updated Cosmos DB {account_name}.",
        outputs_prefix="Azure.CosmosDB",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def nsg_security_groups_list_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]) -> CommandResults:
    """
        List all network security groups.
    Args:
        client: The AzureClient
        params: configuration parameters
        args: args dictionary.

    Returns:
        A detailed list of all network security groups
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    response = client.list_network_security_groups(subscription_id=subscription_id, resource_group_name=resource_group_name)
    network_groups = response.get("value", [])

    # cleans up the tag, remove the "W/\" prefix and the "\" suffix.
    for group in network_groups:
        group["etag"] = group.get("etag", "")[3:-1]
        for rule in group.get("defaultSecurityRules", []):
            rule["etag"] = rule.get("etag", "")[3:-1]

    hr = tableToMarkdown(
        name="Network Security Groups",
        t=network_groups,
        headers=["name", "id", "type", "etag", "location"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        raw_response=response,
        outputs_prefix="Azure.NSGSecurityGroup",
        outputs_key_field="id",
        outputs=network_groups,
        readable_output=hr,
    )


def nsg_security_rule_get_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]) -> CommandResults:
    """
    This command will get a rule from a security group.
    Args:
        client: The AzureClient
        params: configuration parameters
        args: args dictionary.
    Returns:
        CommandResults: The rule that was requested
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    security_group_name = args.get("security_group_name", "")
    security_rule_name = args.get("security_rule_name", "")

    if not security_rule_name and not security_group_name:
        return_error("Please provide security_group_name and security_rule_name.")

    rule = client.get_rule(
        security_group=security_group_name,
        rule_name=security_rule_name,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
    )

    # cleans up the tag, remove the "W/\" prefix and the "\" suffix.
    rule["etag"] = rule.get("etag", "")[3:-1]

    hr = tableToMarkdown(
        name=f"Rule {security_rule_name}",
        t=rule,
        removeNull=True,
        headers=["name", "id", "etag", "type"],
        headerTransform=pascalToSpace,
    )

    return CommandResults(outputs_prefix="Azure.NSGRule", outputs_key_field="id", outputs=rule, readable_output=hr)


def nsg_security_rule_create_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]) -> CommandResults:
    """
    This command will create a rule in a security group.
    Args:
        client: The AzureClient
        params: configuration parameters
        args: args dictionary.
    Returns:
        CommandResults: The rule that was created.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    security_group_name = args.get("security_group_name", "")
    security_rule_name = args.get("security_rule_name", "")
    direction = args.get("direction", "")  # required in API
    priority = args.get("priority", "")  # required in API
    action = args.get("action", "Allow")  # required in API, named as "access" in the API
    protocol = args.get("protocol", "Any")  # required in API
    source = args.get("source", "Any")
    source_ports = args.get("source_ports", "*")
    destination = args.get("destination", "Any")
    destination_ports = args.get("destination_ports", "*")
    description = args.get("description", "")

    if not security_rule_name and not security_group_name and not direction and not priority:
        return_error("Please provide security_group_name, security_rule_name, direction and priority.")

    # The reason for using 'Any' as default instead of '*' is to adhere to the standards in the UI.
    properties = {
        "protocol": "*" if protocol == "Any" else protocol,
        "access": action,
        "priority": priority,
        "direction": direction,
    }
    source_ports_list = argToList(source_ports)
    if len(source_ports_list) > 1:
        properties["sourcePortRanges"] = source_ports_list
    else:
        properties["sourcePortRange"] = source_ports

    dest_ports_list = argToList(destination_ports)
    if len(dest_ports_list) > 1:
        properties["destinationPortRanges"] = dest_ports_list
    else:
        properties["destinationPortRange"] = destination_ports

    source_list = argToList(source)
    if len(source_list) > 1:
        properties["sourceAddressPrefixes"] = source_list
    else:
        properties["sourceAddressPrefix"] = "*" if source == "Any" else source

    dest_list = argToList(destination)
    if len(dest_list) > 1:
        properties["destinationAddressPrefixes"] = dest_list
    else:
        properties["destinationAddressPrefix"] = "*" if destination == "Any" else destination

    if description:
        properties["description"] = description

    rule = client.create_or_update_rule(
        security_group=security_group_name,
        rule_name=security_rule_name,
        properties=properties,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
    )

    # cleans up the tag, remove the "W/\" prefix and the "\" suffix.
    rule["etag"] = rule.get("etag", "")[3:-1]

    hr = tableToMarkdown(
        name=f"The security rule {security_rule_name} was created successfully",
        t=rule,
        removeNull=True,
        headerTransform=pascalToSpace,
    )

    return CommandResults(outputs_prefix="Azure.NSGRule", outputs_key_field="id", outputs=rule, readable_output=hr)


def nsg_security_rule_delete_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]) -> CommandResults:
    """
    Deletes a rule from a security group
    Args:
        client: The AzureClient
        params: configuration parameters
        args: args dictionary.
    Returns:
        Message that the rule was deleted.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    security_group_name = args.get("security_group_name", "")
    security_rule_name = args.get("security_rule_name", "")

    if not security_rule_name and not security_group_name:
        return_error("Please provide security_group_name and security_rule_name.")

    rule_deleted = client.delete_rule(
        security_group_name=security_group_name,
        security_rule_name=security_rule_name,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
    )
    message = ""
    if rule_deleted.status_code == 204:
        message = (
            f"Rule {security_rule_name} with resource_group_name "
            f"{resource_group_name} and subscription id {subscription_id} was not found."
        )
    elif rule_deleted.status_code == 200:
        message = (
            f"Rule {security_rule_name} with resource_group_name "
            f"{resource_group_name} and subscription id {subscription_id} "
            f"was successfully deleted."
        )
    elif rule_deleted.status_code == 202:
        message = (
            f"The delete request for rule {security_rule_name} with resource_group_name"
            f"{resource_group_name} and subscription id {subscription_id} "
            f"was accepted and the operation will complete asynchronously."
        )
    return CommandResults(readable_output=message)


def nsg_resource_group_list_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]) -> CommandResults:
    """
    List all resource groups in the subscription.
    Args:
        client (AzureClient): Azure Client.
        args (Dict[str, Any]): command arguments.
        params (Dict[str, Any]): configuration parameters.
    Returns:
        Command results with raw response, outputs and readable outputs.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    filter_by_tag = azure_tag_formatter(args.get("tag")) if args.get("tag") else ""
    limit = args.get("limit", DEFAULT_LIMIT)

    response = client.list_resource_groups_request(subscription_id=subscription_id, filter_by_tag=filter_by_tag, limit=limit)
    data_from_response = response.get("value", [])

    readable_output = tableToMarkdown(
        name="Resource Groups List",
        t=data_from_response,
        headers=["name", "location", "tags", "provisioningState"],
        removeNull=True,
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        outputs_prefix="Azure.NSGResourceGroup",
        outputs_key_field="id",
        outputs=data_from_response,
        raw_response=response,
        readable_output=readable_output,
    )


def nsg_network_interfaces_list_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]) -> CommandResults:
    """
    List all network interfaces in a resource group.
    Args:
        client (AzureClient): Azure Client.
        args (Dict[str, Any]): command arguments.
        params (Dict[str, Any]): configuration parameters.
    Returns:
        Command results with raw response, outputs and readable outputs.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")

    all_results = argToBoolean(args.get("all_results", "false"))
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))

    response = client.list_networks_interfaces_request(subscription_id=subscription_id, resource_group_name=resource_group_name)
    data_from_response = response.get("value", [])

    if not all_results:
        data_from_response = data_from_response[:limit]

    # cleans up the tag, remove the "W/\" prefix and the "\" suffix.
    for data in data_from_response:
        data["etag"] = data.get("etag", "")[3:-1]

    readable_output = tableToMarkdown(
        name="Network Interfaces List",
        t=data_from_response,
        headers=["name", "id", "type", "etag", "location", "kind"],
        removeNull=True,
        headerTransform=pascalToSpace,
    )

    return CommandResults(
        outputs_prefix="Azure.NSGNetworkInterfaces",
        outputs_key_field="id",
        outputs=data_from_response,
        raw_response=response,
        readable_output=readable_output,
    )


def nsg_public_ip_addresses_list_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]) -> CommandResults:
    """
    List all network interfaces in a resource group.

    Args:
        client (AzureClient): Azure client.
        args (Dict[str, Any]): command arguments.
        params (Dict[str, Any]): configuration parameters.
    Returns:
        Command results with raw response, outputs and readable outputs.
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")

    all_results = argToBoolean(args.get("all_results", "false"))
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))

    response = client.list_public_ip_addresses_request(subscription_id=subscription_id, resource_group_name=resource_group_name)
    data_from_response = response.get("value", [])
    if not all_results:
        data_from_response = data_from_response[:limit]

    # cleans up the tag, remove the "W/\" prefix and the "\" suffix.
    for output in data_from_response:
        output["etag"] = output.get("etag", "")[3:-1]

    readable_output = tableToMarkdown(
        name="Public IP Addresses List",
        t=data_from_response,
        headers=["name", "id", "etag", "provisioningState", "publicIPAddressVersion", "ipAddress", "domainNameLabel", "fqdn"],
        removeNull=True,
        headerTransform=pascalToSpace,
    )
    return CommandResults(
        outputs_prefix="Azure.NSGPublicIPAddress",
        outputs_key_field="id",
        outputs=data_from_response,
        raw_response=response,
        readable_output=readable_output,
    )


def remove_member_from_role(client: AzureClient, args: dict) -> CommandResults:
    """Currently not supported in the integration
    Remove a member from a group by group id and user id.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    role_object_id = str(args.get("role_id"))
    user_id = str(args.get("user_id"))
    client.remove_member_from_role(role_object_id, user_id)
    return CommandResults(readable_output=f"User ID {user_id} has been removed from role {role_object_id}")


def remove_member_from_group_command(client: AzureClient, args: dict) -> CommandResults:
    """Currently not supported in the integration
    Remove a member from a group by group id and user id.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    group_id = str(args.get("group_id"))
    user_id = str(args.get("user_id"))
    client.remove_member_from_group(group_id, user_id)

    human_readable = f'User {user_id} was removed from the Group "{group_id}" successfully.'
    return CommandResults(readable_output=human_readable)


def start_vm_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]):
    """
    Initiates the power-on operation for a specific Azure Virtual Machine (VM).
    This function validates the VM's provisioning state and then requests Azure to
    start the VM.

    Args:
        client (AzureClient): The authenticated Azure client used to make API requests.
        params (dict): Integration or instance-level parameters containing default values.
        args (dict): Command arguments.

    Returns:
        CommandResults: A CommandResults object indicating that the power-on operation
        has been successfully initiated.
    """
    subscription_id = get_from_args_or_params(args=args, params=params, key="subscription_id")
    resource_group_name = get_from_args_or_params(args=args, params=params, key="resource_group_name")
    vm_name = args.get("virtual_machine_name", "")

    client.validate_provisioning_state(subscription_id, resource_group_name, vm_name)

    client.start_vm_request(subscription_id, resource_group_name, vm_name)
    vm_name = vm_name.lower()  # type: ignore
    vm = {"name": vm_name, "resourceGroup": resource_group_name, "powerState": "VM starting"}

    title = f'Power-on of Virtual Machine "{vm_name}" Successfully Initiated'
    human_readable = tableToMarkdown(title, vm, removeNull=True, headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix="Azure.Compute", outputs_key_field="name", outputs=vm, readable_output=human_readable, raw_response=vm
    )


def poweroff_vm_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]):
    """
    Initiates the power-off operation for a specific Azure Virtual Machine (VM).
    This function validates the VM's provisioning state and then requests Azure to
    stop the VM, optionally skipping the guest OS shutdown.

    Args:
        client (AzureClient): The authenticated Azure client used to make API requests.
        params (dict): Integration or instance-level parameters containing default values.
        args (dict): Command arguments.

    Returns:
        CommandResults: A CommandResults object indicating that the power-off operation
        has been successfully initiated.
    """
    subscription_id = get_from_args_or_params(args=args, params=params, key="subscription_id")
    resource_group_name = get_from_args_or_params(args=args, params=params, key="resource_group_name")
    vm_name = args.get("virtual_machine_name", "")
    skip_shutdown = argToBoolean(args.get("skip_shutdown", False))

    client.validate_provisioning_state(subscription_id, resource_group_name, vm_name)

    client.poweroff_vm_request(subscription_id, resource_group_name, vm_name, skip_shutdown)

    vm_name = vm_name.lower()  # type: ignore
    vm = {"name": vm_name, "resourceGroup": resource_group_name, "powerState": "VM stopping"}

    title = f'Power-off of Virtual Machine "{vm_name}" Successfully Initiated'
    human_readable = tableToMarkdown(name=title, t=vm, removeNull=True, headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix="Azure.Compute", outputs_key_field="name", outputs=vm, readable_output=human_readable, raw_response=vm
    )


def get_vm_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]):
    """
    Retrieves details for a specific Azure Virtual Machine (VM).
    This function fetches configuration, storage, networking, and state information
    for a given virtual machine within a specified resource group.

    Args:
        client (AzureClient): The authenticated Azure client used to make API requests.
        params (dict): Integration or instance-level parameters containing default values.
        args (dict): Command arguments.

    Returns:
        CommandResults: A CommandResults object containing the Virtual Machine configuration details.
    """
    subscription_id = get_from_args_or_params(args=args, params=params, key="subscription_id")
    resource_group_name = get_from_args_or_params(args=args, params=params, key="resource_group_name")
    vm_name = args.get("virtual_machine_name", "")

    response = client.get_vm_request(subscription_id, resource_group_name, vm_name, expand=args.get("expand", ""))

    properties = response.get("properties")
    os_disk = properties.get("storageProfile", {}).get("osDisk", {})
    statuses = properties.get("instanceView", {}).get("statuses", [])
    power_state = None

    for status in statuses:
        status_code = status.get("code")
        status_code_prefix = status_code[: status_code.find("/")]
        if status_code_prefix == "PowerState":
            power_state = status.get("displayStatus")

    vm = {
        "Name": vm_name.lower(),  # type: ignore
        "ID": properties.get("vmId"),
        "Size": os_disk.get("diskSizeGB", "NA"),
        "OS": os_disk.get("osType"),
        "ProvisioningState": properties.get("provisioningState"),
        "Location": response.get("location"),
        "PowerState": power_state,
        "ResourceGroup": resource_group_name,
        "NetworkInterfaces": properties.get("networkProfile", {}).get("networkInterfaces"),
        "UserData": properties.get("userData"),
        "Tags": response.get("tags"),
    }

    title = f'Properties of VM "{vm_name}"'
    table_headers = ["Name", "ID", "Size", "OS", "ProvisioningState", "Location", "PowerState"]
    human_readable = tableToMarkdown(title, vm, headers=table_headers, removeNull=True, headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix="Azure.Compute",
        outputs_key_field="name",
        outputs=response,
        readable_output=human_readable,
        raw_response=response,
    )


def get_network_interface_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]):
    """
    Retrieves details for a specific Azure Network Interface (NIC).
    This function fetches configuration, networking, and attachment properties for a given
    network interface within a specified resource group.

    Args:
        client (AzureClient): The authenticated Azure client used to make API requests.
        params (dict): Integration or instance-level parameters containing default values.
        args (dict): Command arguments.

    Returns:
        CommandResults: A CommandResults object containing the Network Interface configuration details.
    """
    subscription_id = get_from_args_or_params(args=args, params=params, key="subscription_id")
    resource_group_name = get_from_args_or_params(args=args, params=params, key="resource_group_name")
    interface_name = args.get("network_interface_name", "")
    response = client.get_network_interface_request(subscription_id, resource_group_name, interface_name)
    properties = response.get("properties")

    ip_configurations = properties.get("ipConfigurations", [])

    ip_configs = []
    for ip_configuration in ip_configurations:
        ip_configs.append(
            {
                "ConfigName": ip_configuration.get("name", "NA"),
                "ConfigID": ip_configuration.get("id", "NA"),
                "PrivateIPAddress": ip_configuration.get("properties", {}).get("privateIPAddress", "NA"),
                "PublicIPAddressID": ip_configuration.get("properties", {}).get("publicIPAddress", {}).get("id"),
            }
        )

    human_readable_network_config = {
        "Name": interface_name.lower(),  # type: ignore
        "ID": response.get("id"),
        "MACAddress": properties.get("macAddress", "NA"),
        "PrivateIPAddresses": [ip.get("PrivateIPAddress") for ip in ip_configs],
        "NetworkSecurityGroup": properties.get("networkSecurityGroup", "NA"),
        "Location": response.get("location"),
        "NICType": properties.get("nicType", "NA"),
        "AttachedVirtualMachine": properties.get("virtualMachine", {}).get("id", "NA"),
    }

    title = f'Properties of Network Interface "{interface_name.lower()}"'
    table_headers = [
        "Name",
        "ID",
        "MACAddress",
        "PrivateIPAddresses",
        "NetworkSecurityGroup",
        "Location",
        "NICType",
        "AttachedVirtualMachine",
    ]
    human_readable = tableToMarkdown(
        name=title, t=human_readable_network_config, headers=table_headers, removeNull=True, headerTransform=pascalToSpace
    )

    response["etag"] = response.get("etag", "")[3:-1]
    for ip_configuration in response.get("properties", {}).get("ipConfigurations", []):
        ip_configuration["etag"] = ip_configuration.get("etag", "")[3:-1]

    return CommandResults(
        outputs_prefix="Azure.Network.Interfaces",
        outputs_key_field="name",
        outputs=response,
        readable_output=human_readable,
        raw_response=response,
    )


def get_single_ip_details_from_list_of_ip_details(list_of_ip_details: list, ip_address):
    """Finds the associated details of target IP Address from a list of PublicIPAddressListResult objects.

    Args:
        list_of_ip_details (list):  List of PublicIPAddressListResult objects.
        ip_address (list | dict): IP Address to search for in list of PublicIPAddressListResult objects.
    """

    def search_entry_for_ip(data, key, value):
        if isinstance(data, list):
            for item in data:
                result = search_entry_for_ip(item, key, value)
                if result:
                    return result
        elif isinstance(data, dict):
            if key in data and data[key] == value:
                return True
            for val in data.values():
                result = search_entry_for_ip(val, key, value)
                if result:
                    return result
        return None

    for entry in list_of_ip_details:
        result = search_entry_for_ip(entry, "ipAddress", ip_address)
        if result:
            return entry
    return None


def get_public_ip_details_command(client: AzureClient, params: dict[str, Any], args: dict[str, Any]):
    """
    Retrieves details for a specific Azure Public IP address.
    This function fetches configuration and networking properties for a given Public IP,
    either within a specified resource group or by searching all IPs under the subscription.

    Args:
        client (AzureClient): The authenticated Azure client used to make API requests.
        params (dict): Integration or instance-level parameters containing default values.
        args (Dict): Command arguments.

    Returns:
        CommandResults: An CommandResults object: Dictionary of the Public IP configuration details
    """
    subscription_id = get_from_args_or_params(args=args, params=params, key="subscription_id")
    address_name = args.get("address_name", "")
    if resource_group_name := (args.get("resource_group_name") or params.get("resource_group_name")):
        response = client.get_public_ip_details_request(subscription_id, resource_group_name, address_name)
    else:
        response_for_all_ips = client.get_all_public_ip_details_request(subscription_id).get("value")
        response = get_single_ip_details_from_list_of_ip_details(response_for_all_ips, address_name)
        if not response:
            raise ValueError(
                f"'{address_name}' was not found. Please try specifying the resource group the IP would be associated with."
            )
        address_id = response.get("id")
        resource_group_name = address_id.split("resourceGroups/")[1].split("/providers")[0]

    response["etag"] = response.get("etag", "")[3:-1]
    properties = response.get("properties")

    human_readable_ip_config = {
        "PublicConfigName": response.get("name"),
        "Location": response.get("location"),
        "PublicIPAddress": properties.get("ipAddress", "NA"),
        "PublicIPAddressVersion": properties.get("publicIPAddressVersion", "NA"),
        "PublicIPAddressAllocationMethod": properties.get("publicIPAllocationMethod", "NA"),
        "ResourceGroup": resource_group_name,
    }

    title = f'Properties of Public Address "{address_name}"'
    table_headers = [
        "PublicConfigName",
        "Location",
        "PublicIPAddress",
        "PublicIPAddressVersion",
        "PublicIPAddressAllocationMethod",
        "ResourceGroup",
    ]
    human_readable = tableToMarkdown(
        name=title, t=human_readable_ip_config, headers=table_headers, removeNull=True, headerTransform=pascalToSpace
    )

    return CommandResults(
        outputs_prefix="Azure.Network.IPConfigurations",
        outputs_key_field="id",
        outputs=response,
        readable_output=human_readable,
        raw_response=response,
    )


def azure_billing_usage_list_command(client: AzureClient, params: dict, args: dict) -> CommandResults:
    """
    Retrieves actual usage and cost details from Azure Consumption API.
    This command provides detailed billing usage information for Azure resources over a specified time period.
    It supports filtering by various criteria and includes pagination for large datasets. The command returns
    usage quantities, costs, and resource details for comprehensive billing analysis.
    Args:
        client (AzureClient): Azure client instance for API communication
        params (dict): Configuration parameters from integration settings
        args (dict): Command arguments containing:
            - subscription_id: Azure subscription ID (required)
            - expand_result: Expand usage details with additional properties
            - filter: OData filter expression for filtering results
            - metric: Specific metric to retrieve (e.g., ActualCost, UsageQuantity)
            - max_results: Maximum number of results to return (default: 50)
            - next_page_token: Token for pagination
    Returns:
        CommandResults: Contains usage data with costs, quantities, and time periods,
                      including pagination support via next page tokens
    Raises:
        DemistoException: If Azure API call fails, subscription not found, or invalid parameters provided
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    expand = args.get("expand_result", "")
    filter_ = args.get("filter", "")
    metric = args.get("metric", "")
    max_results = int(args.get("max_results", 50))
    next_page_token = args.get("next_page_token", "")

    res = client.billing_usage_list(
        subscription_id=subscription_id,
        expand=expand,
        filter_=filter_,
        metric=metric,
        max_results=max_results,
        next_page_token=next_page_token,
    )

    items = res.get("value", [])
    next_token = res.get("nextLink", "")
    demisto.debug(f"Azure billing usage response - results count: {len(items)},\n nextLink: {bool(next_token)}")
    results = []
    for item in items:
        start_date = item.get("properties", {}).get("billingPeriodStartDate")
        end_date = item.get("properties", {}).get("billingPeriodEndDate")
        results.append(
            {
                "Name": item.get("name"),
                "Product": item.get("properties", {}).get("product"),
                "PayGCostUSD": item.get("properties", {}).get("payGPrice"),
                "UsageQuantity": item.get("properties", {}).get("quantity"),
                "PeriodStartDate": datetime.strptime(start_date, "%Y-%m-%dT%H:%M:%S.%f0Z").strftime("%Y-%m-%d"),
                "PeriodEndDate": datetime.strptime(end_date, "%Y-%m-%dT%H:%M:%S.%f0Z").strftime("%Y-%m-%d"),
            }
        )
    metadata = (
        "Run the following command to retrieve the next batch of billings:\n"
        f"!azure-billing-usage-list subscription_id={subscription_id} next_page_token={next_token}"
        if next_token
        else None
    )
    readable_output = tableToMarkdown(
        "Azure Billing Usage",
        results,
        headers=["Name", "Product", "PayGCostUSD", "UsageQuantity", "PeriodStartDate", "PeriodEndDate"],
        headerTransform=pascalToSpace,
        metadata=metadata,
    )

    outputs = {
        "Azure.Billing.Usage(val.name && val.name == obj.name)": items,
        "Azure.Billing(true)": {"UsageNextToken": next_token},
    }
    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=res,
    )


def azure_billing_forecast_list_command(client: AzureClient, params: dict, args: dict) -> CommandResults:
    """
    Returns cost forecast for a subscription over a given time range.
    This command retrieves cost forecast data from Azure Cost Management API using the Forecasts - Usage endpoint.
    It provides forecasted cost information for Azure resources based on historical usage patterns.
    Args:
        client (AzureClient): Azure client instance for API communication
        params (dict): Configuration parameters from integration settings
        args (dict): Command arguments containing:
            - subscription_id: Azure subscription ID (required)
            - type: Forecast type (Usage, Actual Cost, Amortized Cost) (required)
            - aggregation_function_name: Aggregation function name (Pre Tax Cost USD, Cost, Cost USD, Pre Tax Cost) (required)
            - aggregation_function_type: Aggregation function type (default: "Sum")
            - granularity: Data granularity (default: "Daily")
            - start_date: Start date (default: 7 days ago)
            - end_date: End date (default: current time)
            - filter: URL parameter to filter forecasts
            - include_actual_cost: Include actual cost data (default: False)
            - include_fresh_partial_cost: Include fresh partial cost data (default: False)
    Returns:
        CommandResults: Contains forecast data with Name, Time Period, Charge, Currency, and Grain information
    Raises:
        DemistoException: If Azure API call fails, subscription not found, or invalid parameters provided
    """
    subscription_id = args.get("subscription_id", "")
    forecast_type = args.get("type", "")
    aggregation_function_name = args.get("aggregation_function_name", "")

    aggregation_function_type = args.get("aggregation_function_type", "Sum")
    granularity = args.get("granularity", "Daily")
    include_actual_cost = argToBoolean(args.get("include_actual_cost", False))
    include_fresh_partial_cost = argToBoolean(args.get("include_fresh_partial_cost", False))
    filter_param = args.get("filter", "")
    start_date = args.get("start_date", "")
    end_date = args.get("end_date", "")

    response = client.billing_forecast_list(
        subscription_id=subscription_id,
        forecast_type=forecast_type,
        aggregation_function_name=aggregation_function_name,
        aggregation_function_type=aggregation_function_type,
        granularity=granularity,
        start_date=start_date,
        end_date=end_date,
        filter_param=filter_param,
        include_actual_cost=include_actual_cost,
        include_fresh_partial_cost=include_fresh_partial_cost,
    )

    parsed_data = parse_forecast_table_to_dict(response)
    demisto.debug(f"Parsed data:\n {parsed_data}\n")

    results = [
        {
            aggregation_function_name: obj.get(aggregation_function_name),
            "UsageDate": datetime.strptime(str(obj.get("UsageDate")), "%Y%m%d").strftime("%Y-%m-%d"),
            "CostStatus": obj.get("CostStatus"),
            "Currency": obj.get("Currency"),
        }
        for obj in parsed_data
    ]

    context = {"Azure.Billing.Forecast": results}
    readable = tableToMarkdown(
        "Azure Billing Forecast",
        results,
        headers=[aggregation_function_name, "UsageDate", "CostStatus", "Currency"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable,
        outputs=context,
        raw_response=response,
    )


def azure_billing_budgets_list_command(client: AzureClient, params: dict, args: dict) -> CommandResults:
    """
    Retrieves budget information from Azure Consumption API.
    This command lists all configured budgets for a specified Azure subscription or resource group,
    providing detailed information about budget limits, current spending, and time periods.
    Supports retrieving either all budgets or a specific budget by name for targeted analysis.
    Args:
        client (AzureClient): Azure client instance for API communication
        params (dict): Configuration parameters from integration settings
        args (dict): Command arguments containing:
            - subscription_id: Azure subscription ID (required)
            - budget_name: Optional specific budget name to retrieve (if not provided, returns all budgets)
    Returns:
        CommandResults: Contains budget data including names, amounts, current spending,
                      resource types, and time periods for budget monitoring
    Raises:
        DemistoException: If Azure API call fails, subscription not found, budget doesn't exist, or invalid parameters provided
    """
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    budget_name = args.get("budget_name", "")

    res = client.billing_budgets_list(subscription_id=subscription_id, budget_name=budget_name)

    response_data = res.json() if hasattr(res, "json") else res
    if budget_name:
        # Single budget response
        items = [response_data]
        demisto.debug(f"Azure billing budgets response - single budget: {response_data.get('name', '')}")
    else:
        # List of budgets response
        items = response_data.get("value", [])
        demisto.debug(f"Azure billing budgets response - budgets count: {len(items)}")

    results = []
    for item in items:
        time_period = item.get("properties", {}).get("timePeriod", {})
        start_raw = time_period.get("startDate")
        end_raw = time_period.get("endDate")

        start = datetime.fromisoformat(start_raw.replace("Z", "+00:00")).strftime("%Y-%m-%d") if start_raw else None
        end = datetime.fromisoformat(end_raw.replace("Z", "+00:00")).strftime("%Y-%m-%d") if end_raw else None
        results.append(
            {
                "BudgetName": item.get("name"),
                "ResourceType": item.get("type"),
                "TimePeriod": f"{start} - {end}",
                "Amount": item.get("properties", {}).get("amount"),
                "CurrentSpend": item.get("properties", {}).get("currentSpend", {}).get("amount"),
            }
        )
    outputs = {"Azure.Billing.Budget": items}
    readable = tableToMarkdown(
        "Azure Budgets", results, headers=["BudgetName", "ResourceType", "TimePeriod", "Amount", "CurrentSpend"]
    )
    return CommandResults(
        readable_output=readable,
        outputs=outputs,
        raw_response=res,
    )


def parse_forecast_table_to_dict(response: dict) -> list[dict]:
    """
    Parses a generic Azure table-like API response and organizes the data into a list of dictionaries.
    Args:
        response (dict): The raw JSON response from the Azure API.
    Returns:
        list[dict]: A list of dictionaries, where each dictionary represents a row
                    and maps column names to their corresponding values.
    Raises:
        DemistoException: If the response is not in the expected format.
    """
    try:
        properties = response.get("properties", {})
        columns = [column["name"] for column in properties.get("columns", [])]
        rows = properties.get("rows", [])

        parsed_data = []
        for row in rows:
            if len(row) != len(columns):
                # This check ensures data integrity.
                demisto.debug(f"Mismatched data: Found {len(row)} values for {len(columns)} columns. Skipping row.")
                continue

            # Map column names to row values to create a dictionary for each row.
            row_dict = dict(zip(columns, row))
            parsed_data.append(row_dict)

        return parsed_data

    except (KeyError, TypeError) as e:
        raise DemistoException(f"Failed to parse API response. Malformed data structure: {e}")


def test_module(client: AzureClient) -> str:
    """Tests API connectivity and authentication'
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :type AzureClient: ``Client``
    :param Client: client to use
    :return: 'ok' if test passed.
    :rtype: ``str``
    """
    try:
        client.http_request(
            method="GET",
            full_url=f"{PREFIX_URL_AZURE}{client.subscription_id}/providers/Microsoft.Authorization/roleAssignments",
            params={"api-version": PERMISSIONS_VERSION},
        )
    except (ConnectionError, Timeout) as conn_err:
        raise Exception("Connectivity Error: Cannot reach Azure endpoint") from conn_err
    return "ok"


def health_check(shared_creds: dict, subscription_id: str, connector_id: str) -> HealthCheckError | None:  # pragma: no cover
    """
    Tests connectivity to Azure and checks for required permissions.
    This function is specifically used for COOC (Connect on our Cloud) health checks
    to verify connectivity and permissions.
    Args:
        shared_creds (dict): Pre-fetched cloud credentials (format varies by provider).
        subscription_id (str): The Azure subscription ID to check against.
        connector_id (str): The connector ID for the Cloud integration.
    Returns:
        HealthCheckError or None: HealthCheckError if there's an issue, None if successful.
    """
    if not subscription_id:
        return HealthCheckError(
            account_id=subscription_id,
            connector_id=connector_id,
            message="Missing Subscription ID for Azure integration",
            error_type=ErrorType.INTERNAL_ERROR,
        )
    try:
        token = shared_creds.get("access_token")
        if not token:
            return HealthCheckError(
                account_id=subscription_id,
                connector_id=connector_id,
                message="Failed to authenticate with Azure",
                error_type=ErrorType.CONNECTIVITY_ERROR,
            )

        demisto.debug("Using token-based credentials for health check")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}
        client = AzureClient(subscription_id=subscription_id, headers=headers)
        test_module(client)

    except Exception as e:
        return HealthCheckError(
            account_id=subscription_id,
            connector_id=connector_id,
            message=f"Failed to connect to Azure: {str(e)}",
            error_type=ErrorType.CONNECTIVITY_ERROR,
        )

    return None


def get_azure_client(params: dict, args: dict):
    headers = {}
    if not params.get("credentials", {}).get("password"):
        credentials = get_cloud_credentials(
            CloudTypes.AZURE.value, get_from_args_or_params(params=params, args=args, key="subscription_id")
        )
        token = credentials.get("access_token")
        if not token:
            raise DemistoException("Failed to retrieve AZURE access token - token is missing from credentials")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}
        demisto.debug("Using CTS.")

    client = AzureClient(
        app_id=params.get("app_id", ""),
        subscription_id=params.get("subscription_id", ""),
        resource_group_name=params.get("resource_group_name", ""),
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
        tenant_id=params.get("tenant_id"),
        enc_key=params.get("credentials", {}).get("password"),
        scope=SCOPE_AZURE,
        headers=headers,
    )
    return client


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")
    connector_id = get_connector_id()
    demisto.debug(f"{connector_id=}")
    handle_proxy()
    try:
        commands_with_params_and_args = {
            "azure-nsg-security-rule-update": update_security_rule_command,
            "azure-billing-usage-list": azure_billing_usage_list_command,
            "azure-billing-forecast-list": azure_billing_forecast_list_command,
            "azure-billing-budgets-list": azure_billing_budgets_list_command,
            "azure-storage-account-update": storage_account_update_command,
            "azure-storage-blob-service-properties-set": storage_blob_service_properties_set_command,
            "azure-storage-blob-service-properties-get": storage_blob_service_properties_get_command,
            "azure-storage-blob-containers-update": storage_blob_containers_update_command,
            "azure-policy-assignment-create": create_policy_assignment_command,
            "azure-postgres-config-set": set_postgres_config_command,
            "azure-postgres-server-update": postgres_server_update_command,
            "azure-webapp-config-set": set_webapp_config_command,
            "azure-webapp-auth-update": update_webapp_auth_command,
            "azure-mysql-flexible-server-param-set": mysql_flexible_server_param_set_command,
            "azure-monitor-log-profile-update": monitor_log_profile_update_command,
            "azure-disk-update": disk_update_command,
            "azure-webapp-update": webapp_update_command,
            "azure-acr-update": acr_update_command,
            "azure-key-vault-update": update_key_vault_command,
            "azure-sql-db-threat-policy-update": sql_db_threat_policy_update_command,
            "azure-sql-db-transparent-data-encryption-set": sql_db_tde_set_command,
            "azure-cosmos-db-update": cosmosdb_update_command,
            "azure-nsg-security-groups-list": nsg_security_groups_list_command,
            "azure-nsg-security-rule-get": nsg_security_rule_get_command,
            "azure-nsg-security-rule-create": nsg_security_rule_create_command,
            "azure-nsg-security-rule-delete": nsg_security_rule_delete_command,
            "azure-nsg-resource-group-list": nsg_resource_group_list_command,
            "azure-nsg-network-interfaces-list": nsg_network_interfaces_list_command,
            "azure-nsg-public-ip-addresses-list": nsg_public_ip_addresses_list_command,
            "azure-vm-instance-start": start_vm_command,
            "azure-vm-instance-power-off": poweroff_vm_command,
            "azure-vm-instance-details-get": get_vm_command,
            "azure-vm-network-interface-details-get": get_network_interface_command,
            "azure-vm-public-ip-details-get": get_public_ip_details_command,
            "azure-nsg-security-rule-update-quick-action": update_security_rule_command,
            "azure-webapp-assign-managed-identity-quick-action": webapp_update_command,
            "azure-storage-allow-access-quick-action": storage_account_update_command,
            "azure-webapp-set-http2-quick-action": set_webapp_config_command,
            "azure-webapp-auth-update-quick-action": update_webapp_auth_command,
            "azure-storage-disable-cross-tenant-replication-quick-action": storage_account_update_command,
            "azure-set-function-app-http-version2-0-quick-action": set_webapp_config_command,
            "azure-storage-disable-public-access-quick-action": storage_account_update_command,
            "azure-webapp-disable-remote-debugging-quick-action": set_webapp_config_command,
            "azure-nsg-security-rule-delete-quick-action": nsg_security_rule_delete_command,
            "azure-webapp-set-min-tls-version-quick-action": set_webapp_config_command,
            "azure-function-app-set-min-tls-version-quick-action": set_webapp_config_command,
            "azure-mysql-set-secure-transport-quick-action": mysql_flexible_server_param_set_command,
            "azure-network-disable-storage-account-access-quick-action": storage_account_update_command,
            "azure-monitor-log-retention-period-quick-action": monitor_log_profile_update_command,
            "azure-set-storage-account-https-only-quick-action": storage_account_update_command,
            "azure-webapp-update-assign-managed-identity-quick-action": webapp_update_command,
            "azure-storage-blob-enable-soft-delete-quick-action": storage_blob_service_properties_set_command,
            "azure-disable-public-private-access-vm-disk-quick-action": disk_update_command,
            "azure-disk-set-data-access-aad-quick-action": disk_update_command,
            "azure-acr-disable-public-private-access-quick-action": acr_update_command,
            "azure-acr-disable-authentication-as-arm-quick-action": acr_update_command,
            "azure-acr-disable-anonymous-pull-quick-action": acr_update_command,
            "azure-policy-assignment-create-quick-action": create_policy_assignment_command,
            "azure-postgres-config-set-disconnection-logging-quick-action": set_postgres_config_command,
            "azure-postgres-config-set-checkpoint-logging-quick-action": set_postgres_config_command,
            "azure-postgres-config-set-connection-throttling-quick-action": set_postgres_config_command,
            "azure-postgres-config-set-session-connection-logging-quick-action": set_postgres_config_command,
            "azure-postgres-config-set-log-retention-period-quick-action": set_postgres_config_command,
            "azure-postgres-config-set-statement-logging-quick-action": set_postgres_config_command,
            "azure-postgres-server-update-ssl-enforcement-quick-action": postgres_server_update_command,
        }
        if command == "test-module" and connector_id:
            demisto.debug(f"Running health check for connector ID: {connector_id}")
            return return_results(run_health_check_for_accounts(connector_id, CloudTypes.AZURE.value, health_check))

        client = get_azure_client(params, args)
        if command == "test-module":
            return_results(test_module(client))
        elif command in commands_with_params_and_args:
            return_results(commands_with_params_and_args[command](client=client, params=params, args=args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
