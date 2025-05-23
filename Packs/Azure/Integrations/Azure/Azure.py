

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from MicrosoftApiModule import *  # noqa: E402
# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

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

DEFAULT_LIMIT = 50
PREFIX_URL = "https://management.azure.com/subscriptions/"
POLICY_ASSIGNMENT_API_VERSION="2023-04-01"
POSTGRES_API_VERSION="2017-12-01"
WEBAPP_API_VERSION="2024-04-01"
RESOURCE_API_VERSION="2021-04-01"
FLEXIBLE_API_VERSION="2023-06-01-preview"
STORAGE_ACCOUNT_GET_API_VERSION="2024-01-01"
MONITOR_API_VERSION="2016-03-01"
DISKS_API_VERSION="2024-03-02"
ACR_API_VERSION="2023-01-01-preview"
KEY_VAULT_API_VERSION="2022-07-01"
SQL_DB_API_VERSION="2021-11-01"
COSMOS_DB_API_VERSION="2024-11-15"
""" CLIENT CLASS """


class AzureClient:
    @logger
    def __init__(
        self,
        app_id: str,
        subscription_id: str,
        resource_group_name: str,
        verify: bool,
        proxy: bool,
        connection_type: str,
        tenant_id: str = None,
        enc_key: str = None,
        auth_code: str = None,
        redirect_uri: str = None,
        managed_identities_client_id: str = None,
    ):
        if "@" in app_id:
            app_id, refresh_token = app_id.split("@")
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)

        client_args = assign_params(
            self_deployed=True,
            auth_id=app_id,
            token_retrieval_url="https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
            if "Device Code" in connection_type
            else None,
            grant_type=GRANT_BY_CONNECTION.get(connection_type),
            base_url=f"{PREFIX_URL}{subscription_id}",
            verify=verify,
            proxy=proxy,
            resource="https://management.core.windows.net" if "Device" in connection_type else None,
            scope=SCOPE_BY_CONNECTION.get(connection_type),
            tenant_id=tenant_id,
            enc_key=enc_key,
            auth_code=auth_code,
            redirect_uri=redirect_uri,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.management_azure
        )
        self.ms_client = MicrosoftClient(**client_args)
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        self.connection_type = connection_type
        self.tenant_id = tenant_id
        self.enc_key = enc_key
        self.app_id = app_id
        
    @logger
    def http_request(
        self,
        method: str,
        url_suffix: str = None,
        full_url: str = None,
        params: dict = None,
        data: dict = None,
        resp_type: str = "json",
    ) -> requests.Response:
        params = params or {}
        if not params.get("api-version"):
            params["api-version"] = API_VERSION
        return self.ms_client.http_request(
            method=method, url_suffix=url_suffix, full_url=full_url, json_data=data, params=params, resp_type=resp_type
        )

    @logger
    def create_rule(self, security_group: str, rule_name: str, properties: dict, subscription_id: str, resource_group_name: str):
        return self.http_request(
            "PUT",
            full_url=f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}\
/providers/Microsoft.Network/networkSecurityGroups/{security_group}/securityRules/{rule_name}?",
            data={"properties": properties},
        )

    @logger
    def get_rule(self, security_group: str, rule_name: str, subscription_id: str, resource_group_name: str):
        try:
            return self.http_request(
                "GET",
                full_url=(
                    f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
                    f"/providers/Microsoft.Network/networkSecurityGroups/{security_group}/securityRules/{rule_name}?"
                )
            )
        except Exception as e:
            if "404" in str(e):
                raise ValueError(f'Rule {rule_name} under subscription ID "{subscription_id}" \
and resource group "{resource_group_name}" was not found.')
            raise
        
        
            
            
    @logger
    def storage_account_update_request(self, subscription_id: str, resource_group_name: str, args: dict) -> dict:
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
        json_data_args : dict = {"sku": {"name": args.get("sku")}, "kind": args.get("kind"),
                          "location": args.get("location"), "properties": {}}
        if "tags" in args:
            args_tags_list = args["tags"].split(",")
            tags_obj = {f"tag{i + 1!s}": args_tags_list[i] for i in range(len(args_tags_list))}
            json_data_args["tags"] = tags_obj
            
        json_data_args.update({
            "properties": {
                "customDomain": {
                    "name": args.get("custom_domain_name"),
                    "useSubDomainName": args.get("use_sub_domain_name") == "true" if "use_sub_domain_name" in args else None
                },
                "Encryption": {
                    "keySource": args.get("enc_key_source"),
                    "keyvaultproperties": {
                        "keyname": args.get("enc_keyvault_key_name"),
                        "keyversion": args.get("enc_keyvault_key_version"),
                        "keyvaulturi": args.get("enc_keyvault_uri")
                    },
                    "requireInfrastructureEncryption": args.get("enc_requireInfrastructureEncryption")
                },
                "networkAcls": {
                    "bypass": args.get("network_ruleset_bypass"),
                    "defaultAction": args.get("network_ruleset_default_action"),
                    "ipRules": json.loads(args["network_ruleset_ipRules"])
                        if "network_ruleset_ipRules" in args else None,
                    "virtualNetworkRules": json.loads(args["virtual_network_rules"])
                        if "virtual_network_rules" in args else None
                },
                "accessTier": args.get("access_tier"),
                "supportsHttpsTrafficOnly": args.get("supports_https_traffic_only"),
                "isHnsEnabled": args.get("is_hns_enabled"),
                "largeFileSharesState": args.get("large_file_shares_state"),
                "allowCrossTenantReplication": args.get("allow_cross_tenant_replication"),
                "allowBlobPublicAccess": args.get("allow_blob_public_access"),
                "minimumTlsVersion": args.get("minimum_tls_version")
            }
        })
        
        
        json_data_args = remove_empty_elements(json_data_args)
        
        return self.ms_client.http_request(
            method="PATCH",
            full_url=(
                f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
                f"/providers/Microsoft.Storage/storageAccounts/{account_name}"
            ),
            params={
                "api-version": API_VERSION,
            },
            json_data=json_data_args,
            resp_type="response",
        )
        
    
    def storage_blob_service_properties_set_request(
        self, subscription_id: str,
        resource_group_name: str,
        account_name: str,
        delete_rentention_policy_enabled: str | None,
        delete_rentention_policy_days: str | None
    ) -> dict:
        """
        Updates the delete retention policy settings for the Blob service of a given Azure Storage account.
        Args:
            subscription_id (str): Azure subscription ID containing the storage account.
            resource_group_name (str): Name of the resource group that contains the storage account.
            account_name (str): Name of the Azure Storage account.
            delete_rentention_policy_enabled (str): Whether delete retention is enabled ('true' or 'false').
            delete_rentention_policy_days (str): Number of days to retain deleted blobs.

        Returns:
            dict: The full JSON response from the Azure REST API after applying the update.
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Storage/storageAccounts/{account_name}/blobServices/default"
        )
        data = {
            "properties": {
                "deleteRetentionPolicy": {
                    "enabled": delete_rentention_policy_enabled,
                    "days": delete_rentention_policy_days
                }
            }
        }
        params={"api-version": API_VERSION}
        data = remove_empty_elements(data)
        return self.ms_client.http_request(method="PUT", full_url=full_url, params=params, json_data=data)

    def create_policy_assignment(self, name: str, policy_definition_id: str, display_name: str, parameters: str, description: str,
                                 scope: str):
        full_url=(
                f"{PREFIX_URL}{scope}"
                f"/providers/Microsoft.Authorization/policyAssignments/{name}"
            )
        params = {"api-version": POLICY_ASSIGNMENT_API_VERSION}
    
        data = {
            "properties":
            {
                "policyDefinitionId": policy_definition_id,
                "displayName": display_name,
                "parameters": parameters,
                "description": description
            }
        }
        return self.ms_client.http_request(method="PATCH", full_url=full_url, json_data=data, params=params)
    
    def set_postgres_config(self, server_name: str, subscription_id: str, resource_group_name: str, configuration_name: str,
                            source: str, value: str):
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
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.DBforPostgreSQL/servers/{server_name}/configurations/{configuration_name}"
        )
        params = {"api-version": POSTGRES_API_VERSION}
        data = {
            "properties":
            {
                "source": source,
                "value": value
            }
        }
        data = remove_empty_elements(data)
        return self.ms_client.http_request(method="PUT", full_url=full_url, json_data=data, params=params)

    def set_webapp_config(self, name: str, subscription_id: str, resource_group_name: str, http20_enabled: str,
                          remote_debugging_enabled: str, min_tls_version: str):
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
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Web/sites/{name}/config/web"
        )
        params = {"api-version": WEBAPP_API_VERSION}
        data = {
            "properties":
                {
                    "http20Enabled": http20_enabled,
                    "remoteDebuggingEnabled": remote_debugging_enabled,
                    "minTlsVersion":min_tls_version
                }
        }
        return self.ms_client.http_request(method="PATCH", full_url=full_url, json_data=data, params=params)
    
    
    def get_webapp_auth(self, name, subscription_id, resource_group_name):
        """
        Gets the authentication settings of a web app.
        
        Args:
            name (str): Name of the web app.
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the web app.
            
        Returns:
            dict: The authentication settings of the web app.
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Web/sites/{name}/config/authsettings"
        )
        params = {"api-version": WEBAPP_API_VERSION}
        return self.ms_client.http_request(method="GET", full_url=full_url, params=params)
    
    
    def update_webapp_auth(self, name, subscription_id, resource_group_name, enabled):
        """
        Updates the authentication settings of a web app.
        
        Args:
            name (str): Name of the web app.
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the web app.
            enabled (str): Whether authentication is enabled.
            
        Returns:
            dict: The response from the Azure REST API after applying the update.
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Web/sites/{name}/config/authsettings"
        )
        params = {"api-version": WEBAPP_API_VERSION}
        data = {
            "properties":
            {
                "enabled": enabled
            }
        }
        data = remove_empty_elements(data)
        return self.ms_client.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
    

    def resource_update(self, resource_id, allow_blob_public_access, location, account_type):
        """
        Updates an Azure resource.
        
        Args:
            resource_id (str): The ID of the resource to update.
            allow_blob_public_access (str): Whether to allow public access to blobs.
            location (str): The location of the resource.
            account_type (str): The account type.
            
        Returns:
            dict: The response from the Azure REST API after applying the update.
        """
        full_url=(
            f"https://management.azure.com/{resource_id}"
        )
        params = {"api-version": RESOURCE_API_VERSION}
        data = {
            "location": location,
            "properties":
            {
                "allowBlobPublicAccess": allow_blob_public_access,
                # "accountType": account_type,
            },
            "sku": {
                "name": "Standard_LRS"
            }
        }
        return self.ms_client.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
    
    
    def flexible_server_param_set(self, server_name: str, configuration_name: str, subscription_id: str,
                             resource_group_name: str, source: str, value: str):
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
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.DBforMySQL/flexibleServers/{server_name}/configurations/{configuration_name}"
        )
        params = {"api-version": FLEXIBLE_API_VERSION}
        data = {
            "properties":
            {
                "source": source,
                "value": value
            }
        }
        return self.ms_client.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
    
    
    def get_monitor_log_profile(self, subscription_id: str, log_profile_name: str):
        """
        Gets a monitor log profile.
        
        Args:
            subscription_id (str): Azure subscription ID.
            log_profile_name (str): Name of the log profile.
            
        Returns:
            dict: The log profile.
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}"
            f"/providers/Microsoft.Insights/logprofiles/{log_profile_name}"
        )
        params = {"api-version": MONITOR_API_VERSION}
        return self.ms_client.http_request(method="GET", full_url=full_url, params=params)
        
    
    def monitor_log_profile_update(self, subscription_id: str, log_profile_name: str, current_log_profile: dict):
        """
        Updates a monitor log profile.
        
        Args:
            subscription_id (str): Azure subscription ID.
            log_profile_name (str): Name of the log profile.
            current_log_profile (dict): The current log profile to update.
            
        Returns:
            dict: The response from the Azure REST API after applying the update.
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}"
            f"/providers/Microsoft.Insights/logprofiles/{log_profile_name}"
        )
        params = {"api-version": MONITOR_API_VERSION}
        data = current_log_profile
        data = remove_empty_elements(data)
        return self.ms_client.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
    
    
    def disk_update(self, subscription_id: str, resource_group_name: str, disk_name: str, public_network_access: str,
                    network_access_policy: str, data_access_auth_mode: str):
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
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
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
        return self.ms_client.http_request(method="PATCH", full_url=full_url, json_data=data, params=params)
    
    
    # def get_webapp(self, subscription_id, resource_group_name, name):
    #     full_url=(
    #         f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
    #         f"/providers/Microsoft.Web/sites/{name}"
    #     )
    #     params = {"api-version": WEBAPP_API_VERSION}
    #     return self.ms_client.http_request(method="GET", full_url=full_url, params=params)
        
    
    def webapp_update(self, subscription_id: str, resource_group_name: str, name: str, identity_type: str | None,
                      https_only: str | None, client_cert_enabled: str | None):
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
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Web/sites/{name}"
        )
        params = {"api-version": WEBAPP_API_VERSION}
        data = {
            "identity": {
                "type": identity_type,
            },
            "properties": {
                "clientCertEnabled": client_cert_enabled,
                "httpsOnly": https_only,
            }
        }
        data = remove_empty_elements(data)
        return self.ms_client.http_request(method="PATCH", full_url=full_url, json_data=data, params=params)
        
    
    def acr_update(self, subscription_id: str, resource_group_name: str, registry_name: str, allow_exports: str,
              public_network_access: str, anonymous_pull_enabled: str, authentication_as_arm_policy: str):
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
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.ContainerRegistry/registries/{registry_name}"
        )
        params = {"api-version": ACR_API_VERSION}
        data = {
            "properties": {
                "publicNetworkAccess": public_network_access,
                "anonymousPullEnabled": anonymous_pull_enabled,
                "policies": {
                    "azureADAuthenticationAsArmPolicy": {
                        "status": authentication_as_arm_policy
                    },
                    "exportPolicy": {
                        "status": allow_exports
                    },
                }
            },
        }
        data = remove_empty_elements(data)
        return self.ms_client.http_request(method="PATCH", full_url=full_url, json_data=data, params=params)
        
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
        """
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.DBforPostgreSQL/servers/{server_name}"
        )
        params = {"api-version": POSTGRES_API_VERSION}
        data = {
            "properties": {
                "sslEnforcement": ssl_enforcement
            },
        }
        data = remove_empty_elements(data)
        return self.ms_client.http_request(method="PATCH", full_url=full_url, json_data=data, params=params)

    
    def update_key_vault_request(
        self,
        subscription_id: str,
        resource_group_name: str,
        vault_name: str,
        enable_soft_delete: str,
        enable_purge_protection: str
    ) -> dict[str, Any]:
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
        """
        data = {
            "properties": {
                "enableSoftDelete": enable_soft_delete,
                "enablePurgeProtection": enable_purge_protection
            }
        }
        params = {"api-version": KEY_VAULT_API_VERSION}
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.KeyVault/vaults/{vault_name}"
        )

        return self.ms_client.http_request("PATCH", full_url=full_url, json_data=data, params=params)


    def sql_db_threat_policy_get(self, server_name: str, db_name: str, subscription_id: str,
                             resource_group_name: str):
        """
        Gets the threat policy of a SQL database.
        
        Args:
            server_name (str): Name of the SQL server.
            db_name (str): Name of the database.
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the database.
            
        Returns:
            dict: The threat policy of the SQL database.
        """
        params = {"api-version": SQL_DB_API_VERSION}
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Sql/servers/{server_name}/databases/{db_name}/securityAlertPolicies/default"
        )

        return self.ms_client.http_request("GET", full_url=full_url, params=params)


    def sql_db_threat_policy_update(self, server_name: str, db_name: str, subscription_id: str, current: dict,
                                    resource_group_name: str):
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
        """
        data = current
        params = {"api-version": SQL_DB_API_VERSION}
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Sql/servers/{server_name}/databases/{db_name}/securityAlertPolicies/default"
        )

        return self.ms_client.http_request("PUT", full_url=full_url, json_data=data, params=params)
    
    
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
        """
        data = {
            "properties": {
                "state": state
            }
        }
        params = {"api-version": SQL_DB_API_VERSION}
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Sql/servers/{server_name}/databases/{db_name}/transparentDataEncryption/current"
        )

        return self.ms_client.http_request("PUT", full_url=full_url, json_data=data, params=params)
    
    
    def cosmos_db_update(self, subscription_id: str, resource_group_name: str, account_name: str,
                     disable_key_based_metadata_write_access: str | None):
        """
        Updates a Cosmos DB account.
        
        Args:
            subscription_id (str): Azure subscription ID.
            resource_group_name (str): Name of the resource group containing the account.
            account_name (str): Name of the Cosmos DB account.
            disable_key_based_metadata_write_access (str): Whether to disable key-based metadata write access.
            
        Returns:
            dict: The response from the Azure REST API after applying the update.
        """
        data = {
            "properties": {
                "disableKeyBasedMetadataWriteAccess": disable_key_based_metadata_write_access
            }
        }
        data = remove_empty_elements(data)
        params = {"api-version": COSMOS_DB_API_VERSION}
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.DocumentDB/databaseAccounts/{account_name}"
        )

        return self.ms_client.http_request("PATCH", full_url=full_url, json_data=data, params=params)
    
    
    def remove_member_from_role(self, role_object_id: str, user_id: str):
        """Removing a member from a specific role.

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
        full_url = f"https://graph.microsoft.com/v1.0/directoryRoles/{role_object_id}/members/{user_id}/$ref"
        params = {"api-version": COSMOS_DB_API_VERSION}
        response = self.ms_client.http_request(
            "DELETE", full_url=full_url, params=params
        )
        print(response)
        
    
    def remove_member_from_group(self, group_id: str, user_id: str):
        """Remove a single member to a group by sending a DELETE request.
        Args:
            group_id: the group id to add the member to.
            user_id: the user id to remove.
        """
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        #  Using resp_type="text" to avoid parsing error in the calling method.
        params = {"api-version": COSMOS_DB_API_VERSION}
        self.ms_client.http_request(method="DELETE", full_url=f"https://management.azure.com/v1.0/groups/{group_id}/members/{user_id}/$ref", params=params, resp_type="text")
    
        
""" HELPER FUNCTIONS """
def format_rule(rule_json: dict | list, security_rule_name: str):
    """
    format the rule and create the commandResult object with it
    Args:
        rule_json: the json returned from the http_request
        security_rule_name: the name of the rule

    Returns:
        CommandResults for the rule
    """
    # We want to flatten the rules `properties` key as this is the more important key and we'd like
    # to be able to display it nicely
    if isinstance(rule_json, dict):
        rule_json.update(rule_json.pop("properties", {}))
    if isinstance(rule_json, list):
        for rule in rule_json:
            rule.update(rule.pop("properties", {}))

    hr = tableToMarkdown(f"Rules {security_rule_name}", rule_json, removeNull=True)

    return CommandResults(outputs_prefix="Azure.NSGRule", outputs_key_field="id", outputs=rule_json, readable_output=hr)


    
""" COMMAND FUNCTIONS """

@logger
def start_auth(client: AzureClient) -> CommandResults:
    result = client.ms_client.start_auth("!azure-nsg-auth-complete")
    return CommandResults(readable_output=result)


@logger
def complete_auth(client: AzureClient):
    client.ms_client.get_access_token()
    return "✅ Authorization completed successfully."

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
    properties.update({"access": access})
    rule = client.create_rule(
        security_group=security_group_name,
        rule_name=security_rule_name,
        properties=properties,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name
    )

    return format_rule(rule, security_rule_name)



def storage_account_update_command(client: AzureClient, params: dict, args: dict) -> Union[CommandResults, str]:
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
        return f"The request was accepted - the account {args.get('account_name')} will be created shortly"

    response = response.json()

    readable_output = {
        "Account Name": response.get("name"),
        "Subscription ID": subscription_id,
        "Resource Group": resource_group_name,
        "Network Ruleset Bypass": response.get("properties", {}).get("networkAcls", {}).get("bypass") if \
            args.get("network_ruleset_bypass") else None,
        "Default Action": response.get("properties", {}).get("networkAcls", {}).get("defaultAction") if \
            args.get("network_ruleset_default_action") else None,
        "Allow Cross Tenant Replication": response.get("properties", {}).get("allowCrossTenantReplication") if \
            args.get("allow_cross_tenant_replication") else None,
        "Supports Https Traffic Only": response.get("properties", {}).get("supportsHttpsTrafficOnly") if \
            args.get("supports_https_traffic_only") else None,
    }

    return CommandResults(
        outputs_prefix="Azure.StorageAccount",
        outputs_key_field="id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Azure Storage Account",
            readable_output,
            ["Account Name", "Subscription ID", "Resource Group", "Network Ruleset Bypass", "Default Action",
             "Allow Cross Tenant Replication", "Supports Https Traffic Only"],
            removeNull=True
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
        "Delete Retention Policy": response.get("properties", {}).get("deleteRetentionPolicy") if \
            args.get("delete_rentention_policy_enabled") or args.get("delete_rentention_policy_days") else None
    }

    return CommandResults(
        outputs_prefix="Azure.StorageAccountBlobServiceProperties",
        outputs_key_field="id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Updated Azure Storage Blob Service Properties",
            readable_output,
            ["Name", "ID", "Delete Retention Policy"],
            removeNull=True
        ),
        raw_response=response,
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
    policy_definition_id : str = args.get("policy_definition_id", "")
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
            "Parameters": response.get("properties", {}).get("parameters") if parameters else None
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
    return CommandResults(
        readable_output=f"Updated the configuration {configuration_name} of the server {server_name}."
    )

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
    response = client.set_webapp_config(name, subscription_id, resource_group_name, http20_enabled, remote_debugging_enabled,
                                        min_tls_version)
    outputs = [
        {
            "Name": response.get("name"),
            "Http20 Enabled": response.get("properties", {}).get("http20Enabled", "") if http20_enabled else None,
            "Remote Debugging Enabled": response.get("properties", {}).get("remoteDebuggingEnabled", "") if \
                remote_debugging_enabled else None,
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
    name = args.get("name")
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
    enabled = args.get("enabled", "")
    current = client.get_webapp_auth(name, subscription_id, resource_group_name)
    current["properties"]["enabled"] = enabled if enabled else current.get("properties", {}).get("enabled")
    response = client.update_webapp_auth(name, subscription_id, resource_group_name, enabled)
    outputs = [
        {
            "Name": response.get("name"),
            "Enabled": response.get("properties", {}).get("enabled", "") if enabled else None,
            "ID": response.get("id")
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

# def resource_update_command(client: AzureClient, params: dict, args: dict):
#     resource_id = args.get("resource_id")
#     allow_blob_public_access = args.get("allow_blob_public_access")
#     location = args.get("location")
#     account_type = args.get("account_type")
#     response = client.resource_update(resource_id, allow_blob_public_access, location, account_type)
#     outputs = [
#         {
#             "Name": response.get("name"),
#             "Properties": response.get("properties", {}),
#             "ID": response.get("id")
#         }
#     ]
#     md = tableToMarkdown(
#         f"Resource {resource_id} updated successfully.",
#         outputs,
#         ["Name", "Properties", "ID"],
#         removeNull=True,
#     )
#     return CommandResults(
#         outputs_prefix="Azure.Resource",
#         outputs_key_field="id",
#         outputs=response,
#         readable_output=md,
#         raw_response=outputs,
#     )
    
    
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
    return CommandResults(
        readable_output=f"Updated the configuration {configuration_name} of the server {server_name}."
    )
    
    
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
    retention_policy_enabled = args.get("retention_policy_enabled", "")
    current_log_profile = client.get_monitor_log_profile(subscription_id, log_profile_name)
    current_log_profile["properties"]["retentionPolicy"]["enabled"] = retention_policy_enabled if retention_policy_enabled \
        else current_log_profile.get("properties", {}).get("retentionPolicy", {}).get("enabled")
    current_log_profile["properties"]["retentionPolicy"]["days"] = retention_policy_days if retention_policy_days \
        else current_log_profile.get("properties", {}).get("retentionPolicy", {}).get("days")
    current_log_profile["location"] = location if location else current_log_profile.get("location")
    response = client.monitor_log_profile_update(subscription_id, log_profile_name, current_log_profile)
    outputs = [
        {
            "Name": response.get("name"),
            "ID": response.get("id"),
            "Location": response.get("location", "") if location else None,
            "Retention Policy": response.get("properties", {}).get("retentionPolicy") if (retention_policy_enabled or \
                retention_policy_days) else None,
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
    public_network_access = args.get("public_network_access", "")
    network_access_policy = args.get("network_access_policy", "")
    data_access_auth_mode = args.get("data_access_auth_mode", "")
    response = client.disk_update(subscription_id, resource_group_name, disk_name, public_network_access, network_access_policy,
                                  data_access_auth_mode)
    outputs = [
        {
            "Name": response.get("name"),
            "ID": response.get("id"),
            "Public Network Access": response.get("properties", {}).get("publicNetworkAccess") if public_network_access else None,
            "Network Access Policy": response.get("properties", {}).get("networkAccessPolicy") if network_access_policy else None,
            "Data Access Auth Mode": response.get("properties", {}).get("dataAccessAuthMode") if data_access_auth_mode else None
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
    
# def logicapp_update_command(client: AzureClient, params: dict, args: dict):
#     subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
#     resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")
#     name = args.get("name")
#     https_only = args.get("https_only")
#     response = client.logicapp_update(subscription_id, resource_group_name, name, https_only)
#     outputs = [
#         {
#             "Name": response.get("name"),
#             "ID": response.get("id"),
#             "Https Only": response.get("properties", {}).get("httpsOnly") if https_only else None,
#         }
#     ]
#     md = tableToMarkdown(
#         f"Updated the logic App {name}.",
#         outputs,
#         ["Name", "ID", "Identity", "Https Only","Client Cert Enabled"],
#         removeNull=True,
#     )
#     return CommandResults(
#         outputs_prefix="Azure.Logicapp",
#         outputs_key_field="id",
#         outputs=response,
#         readable_output=md,
#         raw_response=outputs,
#     )

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
    allow_exports = args.get("allow_exports", "")
    public_network_access = args.get("public_network_access", "")
    anonymous_pull_enabled = args.get("anonymous_pull_enabled", "")
    authentication_as_arm_policy = args.get("authentication_as_arm_policy", "")
    response = client.acr_update(subscription_id, resource_group_name, registry_name, allow_exports, public_network_access,
                                 anonymous_pull_enabled, authentication_as_arm_policy)
    outputs = [
        {
            "Name": response.get("name"),
            "ID": response.get("id"),
            "Public Network Access": response.get("properties", {}).get("publicNetworkAccess") if public_network_access else None,
            "Anonymous Pull Enabled": response.get("properties", {}).get("anonymousPullEnabled") if anonymous_pull_enabled \
                else None,
            "Allow Exports": response.get("properties", {}).get("policies", {}).get("exportPolicy", {}).get("status") if \
                allow_exports else None,
            "Authentication As Arm Policy": \
                response.get("properties", {}).get("policies", {}).get("azureADAuthenticationAsArmPolicy", {}).get("status") \
                    if authentication_as_arm_policy else None,
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
    response = client.postgres_server_update(subscription_id, resource_group_name, server_name, ssl_enforcement)
    
    
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
        subscription_id,
        resource_group_name,
        vault_name,
        enable_soft_delete,
        enable_purge_protection
    )
    outputs = [
        {
            "Name": response.get("name"),
            "ID": response.get("id"),
            "Enable Soft Delete": response.get("properties", {}).get("enableSoftDelete") if enable_soft_delete else None,
            "Enable Purge Protection": response.get("properties", {}).get("enablePurgeProtection") if enable_purge_protection \
                else None
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
    
    
def sql_db_threat_policy_update_command(
    client: AzureClient, params: dict[str, Any], args: Dict[str, Any]
) -> CommandResults:
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
        server_name=server_name,
        db_name=db_name,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name
    )
    if isinstance(current_db, str):  # if there is 404, an error message will return
        return CommandResults(readable_output=current_db)
    current_db["properties"]["emailAccountAdmins"] = email_account_admins or \
        current_db.get("properties", {}).get("emailAccountAdmins")

    response = client.sql_db_threat_policy_update(
        server_name=server_name,
        db_name=db_name,
        subscription_id=subscription_id,
        current=current_db,
        resource_group_name=resource_group_name
    )

    if isinstance(response, str):  # if there is 404, an error message will return
        return CommandResults(readable_output=response)
    
    outputs = [
        {
            "Name": response.get("name"),
            "ID": response.get("id"),
            "Email Account Admins": response.get("properties", {}).get("emailAccountAdmins") if email_account_admins else None
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
    
def sql_db_tde_set_command(
    client: AzureClient, params: dict[str, Any], args: Dict[str, Any]
) -> CommandResults:
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
        resource_group_name=resource_group_name
    )
    # CommandResults don't contain the response because it takes time for the resource to be updated.
    return CommandResults(
        readable_output=f"Updated SQL database {db_name} of the server {server_name}.",
    )
    
def cosmosdb_update_command(
    client: AzureClient, params: dict[str, Any], args: Dict[str, Any]
) -> CommandResults:
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
    response = client.cosmos_db_update(subscription_id, resource_group_name, account_name,
                                       disable_key_based_metadata_write_access)
    
    return CommandResults(
        readable_output=f"Updated Cosmos DB {account_name}.",
        outputs_prefix="Azure.CosmosDB",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )
    
def remove_member_from_role(client: AzureClient, args: dict) -> CommandResults:
    """Remove a member from a group by group id and user id.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    role_object_id = args.get("role_id")
    user_id = args.get("user_id")
    client.remove_member_from_role(role_object_id, user_id)  # type: ignore
    return CommandResults(readable_output=f"User ID {user_id} has been removed from role {role_object_id}")
    
    
def remove_member_from_group_command(client: AzureClient, args: dict) -> CommandResults:
    """Remove a member from a group by group id and user id.

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
    # This  should validate all the inputs given in the integration configuration panel,
    # either manually or by using an API that uses them.
    if "Device" in client.connection_type:
        raise DemistoException(
            "Please enable the integration and run `!azure-nsg-auth-start`"
            "and `!azure-nsg-auth-complete` to log in."
            "You can validate the connection by running `!azure-nsg-auth-test`\n"
            "For more details press the (?) button."
        )
    elif client.connection_type == "Azure Managed Identities" or client.connection_type == "Client Credentials":
        client.ms_client.get_access_token()
        return "ok"

    else:
        raise Exception(
            "When using user auth flow configuration, "
            "Please enable the integration and run the !azure-nsg-auth-test command in order to test it"
        )



def main():
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")
    try:
        client = AzureClient(
            app_id=params.get("app_id", ""),
            subscription_id=params.get("subscription_id", ""),
            resource_group_name=params.get("resource_group_name", ""),
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            connection_type=params.get("auth_type", "Device Code"),
            tenant_id=params.get("tenant_id"),
            enc_key=params.get("credentials", {}).get("password"),
            auth_code=(params.get("auth_code", {})).get("password"),
            redirect_uri=params.get("redirect_uri"),
            managed_identities_client_id=get_azure_managed_identities_client_id(params),
        )
    
        commands_with_params_and_args = {
            "azure-nsg-security-rule-update": update_security_rule_command,
            "azure-storage-account-update": storage_account_update_command,
            "azure-storage-blob-service-properties-set": storage_blob_service_properties_set_command,
            "azure-policy-assignment-create": create_policy_assignment_command,
            "azure-postgres-config-set": set_postgres_config_command,
            "azure-webapp-config-set": set_webapp_config_command,
            "azure-webapp-auth-update": update_webapp_auth_command,
            # "azure-resource-update": resource_update_command, ### we use storage_account_create_update for this
            "azure-mysql-flexible-server-param-set": mysql_flexible_server_param_set_command,
            "azure-monitor-log-profile-update": monitor_log_profile_update_command,
            "azure-disk-update": disk_update_command,
            "azure-webapp-update": webapp_update_command,
            "azure-acr-update": acr_update_command,
            "azure-postgres-server-update": postgres_server_update_command,
            "azure-key-vault-update": update_key_vault_command,
            "azure-sql-db-threat-policy-update": sql_db_threat_policy_update_command,
            # "azure-logicapp-update": logicapp_update_command,
            "azure-sql-db-transparent-data-encryption-set": sql_db_tde_set_command,
            "azure-cosmos-db-update": cosmosdb_update_command,
        }
        commands_with_args = {
            "azure-remove-member-from-role": remove_member_from_role,
            "azure-remove-member-from-group": remove_member_from_group_command
        }
       
        if command == "test-module":
            return_results(test_module(client))
        elif command in commands_with_params_and_args:
            return_results(commands_with_params_and_args[command](client=client, params=params, args=args))
        elif command in commands_with_args:
            return_results(commands_with_args[command](client=client, args=args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
