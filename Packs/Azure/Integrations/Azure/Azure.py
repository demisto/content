

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
APS_API_VERSION = "2017-08-01-preview"
POLICY_ASSIGNMENT_API_VERSION="2023-04-01"
POSTGRES_CONFIG_API_VERSION="2017-12-01"
WEBAPP_API_VERSION="2024-04-01"
RESOURCE_API_VERSION="2021-04-01"
FLEXIBLE_API_VERSION="2023-06-01-preview"
STORAGE_ACCOUNT_GET_API_VERSION="2024-01-01"
MONITOR_API_VERSION="2016-03-01"
DISKS_API_VERSION="2024-03-02"
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
        
        
    def get_current_storage_account(self, subscription_id: str, resource_group_name: str, name: str) -> dict:
        try:
            full_url=(
                f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
                f"/providers/Microsoft.Storage/storageAccounts/{name}"
            )
            params = {"api-version": API_VERSION}
            return self.ms_client.http_request(method="GET", full_url=full_url, params=params)
        except Exception:
            return {}
            
            
    @logger
    def storage_account_create_update_request(self, subscription_id: str, resource_group_name: str, args: dict, sku: str, location: str, kind: str) -> dict:
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
        json_data_args = {"sku": {"name": sku}, "kind": kind, "location": location, "properties": {}}
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
            method="PUT",
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
        self, subscription_id: str | None, resource_group_name: str | None, args: dict
    ) -> dict:
        """
            Send the user arguments for the blob service in the request body to the API.
        Args:
            subscription_id: The subscription id.
            resource_group_name: The resource group name.
            args: The user arguments.

        Returns:
            The json response from the API call.
        """
        account_name = args.get("account_name")
        properties = {}

        if "change_feed_enabled" in args:
            properties["changeFeed"] = {"enabled": args["change_feed_enabled"] == "true"}

        if "change_feed_retention_days" in args:
            if "changeFeed" not in properties:
                properties["changeFeed"] = {}
            properties["changeFeed"]["retentionInDays"] = args.get("change_feed_retention_days")

        if "container_delete_rentention_policy_enabled" in args:
            properties["containerDeleteRetentionPolicy"] = {
                "enabled": args["container_delete_rentention_policy_enabled"] == "true"
            }

        if "container_delete_rentention_policy_days" in args:
            if "containerDeleteRetentionPolicy" not in properties:
                properties["containerDeleteRetentionPolicy"] = {}
            properties["containerDeleteRetentionPolicy"]["days"] = args.get("container_delete_rentention_policy_days")

        if "delete_rentention_policy_enabled" in args:
            properties["deleteRetentionPolicy"] = {"enabled": args["delete_rentention_policy_enabled"] == "true"}

        if "delete_rentention_policy_days" in args:
            if "deleteRetentionPolicy" not in properties:
                properties["deleteRetentionPolicy"] = {}
            properties["deleteRetentionPolicy"]["days"] = args.get("delete_rentention_policy_days")

        if "versioning" in args:
            properties["isVersioningEnabled"] = argToBoolean(args.get("versioning"))

        if (
            "last_access_time_tracking_policy_enabled" in args
            or "last_access_time_tracking_policy_blob_types" in args
            or "last_access_time_tracking_policy_days" in args
        ):
            properties["lastAccessTimeTrackingPolicy"] = {}

            if "last_access_time_tracking_policy_enabled" in args:
                properties["lastAccessTimeTrackingPolicy"]["enable"] = (
                    args.get("last_access_time_tracking_policy_enabled") == "true"
                )

            if "last_access_time_tracking_policy_blob_types" in args:
                properties["lastAccessTimeTrackingPolicy"]["blobType"] = args[
                    "last_access_time_tracking_policy_blob_types"
                ].split(",")

            if "last_access_time_tracking_policy_days" in args:
                properties["lastAccessTimeTrackingPolicy"]["trackingGranularityInDays"] = args.get(
                    "last_access_time_tracking_policy_days"
                )

        if "restore_policy_enabled" in args or "restore_policy_min_restore_time" in args or "restore_policy_days" in args:
            properties["restorePolicy"] = {}

            if "restore_policy_enabled" in args:
                properties["restorePolicy"]["enabled"] = args.get("restore_policy_enabled") == "true"

            if "restore_policy_min_restore_time" in args:
                properties["restorePolicy"]["minRestoreTime"] = args.get("restore_policy_min_restore_time")

            if "restore_policy_days" in args:
                properties["restorePolicy"]["days"] = args.get("restore_policy_days")

        return self.ms_client.http_request(
            method="PUT",
            full_url=(
                f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
                f"/providers/Microsoft.Storage/storageAccounts/{account_name}/blobServices/default"
            ),
            params={
                "api-version": API_VERSION,
            },
            json_data={"properties": properties},
        )


    def update_aps(self, setting_name, auto_provision):
        """
        Args:
            setting_name (str): Setting name
            auto_provision (str): Auto provision setting (On/Off)

        Returns:
            dict: response body
        """
        cmd_url = f"/providers/Microsoft.Security/autoProvisioningSettings/{setting_name}"
        params = {"api-version": APS_API_VERSION}

        data = {"properties": {"autoProvision": auto_provision}}

        return self.ms_client.http_request(method="PUT", url_suffix=cmd_url, json_data=data, params=params)
    
    def create_policy_assignment(self, name, policy_definition_id, display_name, parameters, description, subscription_id):
        full_url=(
                f"{PREFIX_URL}{subscription_id}"
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
        ### for getting policyDefinitionId run the line below
        # print(self.ms_client.http_request(method="GET", url_suffix="/providers/Microsoft.Authorization/policyDefinitions", params=params))
        return self.ms_client.http_request(method="PUT", full_url=full_url, json_data=data, params=params)

    def set_postgres_config(self, server_name, subscription_id, resource_group_name, configuration_name, source, value):
        full_url=(
                f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
                f"/providers/Microsoft.DBforPostgreSQL/servers/{server_name}/configurations/{configuration_name}"
            )
        params = {"api-version": POSTGRES_CONFIG_API_VERSION}
    
        data = {
            "properties":
            {
                "source": source,
                "value": value,
            }
        }
        ### for getting policyDefinitionId run the line below
        # print(self.ms_client.http_request(method="GET", url_suffix="/providers/Microsoft.Authorization/policyDefinitions", params=params))
        return self.ms_client.http_request(method="PUT", full_url=full_url, json_data=data, params=params)

    def set_webapp_config(self, name, subscription_id, resource_group_name, http20_enabled, remote_debugging_enabled, min_tls_version):
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
        return self.ms_client.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
    
    def update_webapp_auth(self, name, subscription_id, resource_group_name, enabled):
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
        return self.ms_client.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
    
    def resource_update(self, resource_id, allow_blob_public_access, location, account_type):
        #### should check it
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
    
    
    def flexible_server_param_set(self, server_name, configuration_name, subscription_id, resource_group_name, source, value):
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
    
    
    def get_monitor_log_profile(self, subscription_id, log_profile_name):
        full_url=(
            f"{PREFIX_URL}{subscription_id}"
            f"/providers/Microsoft.Insights/logprofiles"
        )
        params = {"api-version": MONITOR_API_VERSION}
        return self.ms_client.http_request(method="GET", full_url=full_url, params=params)
        
    
    def monitor_log_profile_update(self, subscription_id, log_profile_name, location, retention_policy_days, retention_policy_enabled):
        full_url=(
            f"{PREFIX_URL}{subscription_id}"
            f"/providers/Microsoft.Insights/logprofiles/{log_profile_name}"
        )
        params = {"api-version": MONITOR_API_VERSION}
        # data = {
        #     "location": "",
        #     "properties":
        #     {
        #         "retentionPolicy": {
        #             "days": retention_policy_days,
        #             "enabled": retention_policy_enabled
        #         },
        #         "locations": [
        #             "global"
        #         ],
        #         "categories": [
        #             "Write",
        #             "Delete",
        #             "Action"
        #         ]
        #     }
        # }
        data = {
            "location": "",
            "tags": {},
            "properties": {
                "locations": [
                    "global"
                ],
                "categories": [
                    "Write",
                    "Delete",
                    "Action"
                ],
                "retentionPolicy": {
                    "enabled": True,
                    "days": 3
                },
                "storageAccountId": "/subscriptions/df602c9c-7aa0-407d-a6fb-eb20c8bd1192/resourceGroups/JohnKemTest/providers/Microsoft.Storage/storageAccounts/johnkemtest8162",
                "serviceBusRuleId": ""
            }
        }
        data = remove_empty_elements(data)
        return self.ms_client.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
    
    
    def disk_update(self, subscription_id, resource_group_name, disk_name, public_network_access,
                    network_access_policy, data_access_auth_mode):
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
    
    
    def get_webapp(self, subscription_id, resource_group_name, name):
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Web/sites/{name}"
        )
        params = {"api-version": WEBAPP_API_VERSION}
        return self.ms_client.http_request(method="GET", full_url=full_url, params=params)
        
    
    def webapp_identity_assign(self, subscription_id, resource_group_name, name, identity_type, properties, location, 
                               identity_name, client_id, principal_id):
        full_url=(
            f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.Web/sites/{name}"
        )
        params = {"api-version": WEBAPP_API_VERSION}
        data = {
            "location": location,
            "identity": {
                "type": identity_type,
                
            },
            "properties": properties
        }
        if "UserAssigned" in identity_type:
            data.update(
                {
                    "identity":
                    {
                        "type": identity_type,
                        "tenantId": client_id,
                        "principalId": principal_id,
                        # "userAssignedIdentities":{
                        # (f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.ManagedIdentity"
                        #  f"/userAssignedIdentities/{identity_name}"): {
                        #      "clientId": client_id,
                        #      "principalId": principal_id
                        #  }
                        # }
                    }
                }
            )
        data = remove_empty_elements(data)
        return self.ms_client.http_request(method="PUT", full_url=full_url, json_data=data, params=params)
        

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

    return CommandResults(outputs_prefix="Azure.NSG.Rule", outputs_key_field="id", outputs=rule_json, readable_output=hr)

""" COMMAND FUNCTIONS """

@logger
def start_auth(client: AzureClient) -> CommandResults:
    result = client.ms_client.start_auth("!azure-nsg-auth-complete")
    return CommandResults(readable_output=result)


@logger
def complete_auth(client: AzureClient):
    client.ms_client.get_access_token()
    return "✅ Authorization completed successfully."
@logger
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
    # subscription_id and resource_group_name can be passed as command argument or as configuration parameter,
    # if both are passed as arguments, the command argument will be used.
    subscription_id = args.get("subscription_id")
    resource_group_name = args.get("resource_group_name")

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



def storage_account_create_update_command(client: AzureClient, params: dict, args: dict) -> Union[CommandResults, str]:
    """
        Creates or updates a given storage account.
    Args:
        client: The microsoft client.
        params: The configuration parameters.
        args: The users arguments, (like account name).

    Returns:
        CommandResults: The command results in MD table and context data.
    """
    # subscription_id and resource_group_name arguments can be passed as command arguments or as configuration parameters,
    # if both are passed as arguments, the command arguments will be used.
    subscription_id = args.get("subscription_id")
    resource_group_name = args.get("resource_group_name")
    
    current_storage_account = client.get_current_storage_account(subscription_id, resource_group_name, args.get("account_name", ""))
    
    sku = args.get("sku") or current_storage_account.get("sku", {}).get("name", "")
    location = args.get("location") or current_storage_account.get("location", "")
    kind = args.get("kind") or current_storage_account.get("kind", "")
    if not (sku and location and kind):
        raise DemistoException("Account name was not found. For creating new storage account, "
                "please provide the following arguments: sku, location and kind.")
        
    response = client.storage_account_create_update_request(
        subscription_id=subscription_id, resource_group_name=resource_group_name, args=args, sku=sku, location=location, kind=kind
    )
    if not response.text:
        return f"The request was accepted - the account {args.get('account_name')} will be created shortly"

    response = response.json()

    readable_output = {
        "Account Name": response.get("name"),
        "Subscription ID": subscription_id,
        "Resource Group": resource_group_name,
        "Kind": response.get("kind"),
        "Status Primary": response.get("properties", "").get("statusOfPrimary"),
        "Status Secondary": response.get("properties", "").get("statusOfSecondary"),
        "Location": response.get("location"),
    }

    return CommandResults(
        outputs_prefix="Azure.Storage.StorageAccount",
        outputs_key_field="id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Azure Storage Account",
            readable_output,
            ["Account Name", "Subscription ID", "Resource Group", "Kind", "Status Primary", "Status Secondary", "Location"],
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
    # subscription_id and resource_group_name arguments can be passed as command arguments or as configuration parameters,
    # if both are passed as arguments, the command arguments will be used.
    subscription_id = args.get("subscription_id")
    resource_group_name = args.get("resource_group_name")

    response = client.storage_blob_service_properties_set_request(
        subscription_id=subscription_id, resource_group_name=resource_group_name, args=args
    )

    if subscription_id := re.search("subscriptions/(.+?)/resourceGroups", response.get("id", "")):
        subscription_id = subscription_id.group(1)  # type: ignore

    if resource_group := re.search("resourceGroups/(.+?)/providers", response.get("id", "")):
        resource_group = resource_group.group(1)  # type: ignore

    if account_name := re.search("storageAccounts/(.+?)/blobServices", response.get("id", "")):
        account_name = account_name.group(1)  # type: ignore

    readable_output = {
        "Name": response.get("name"),
        "Account Name": account_name,
        "Subscription ID": subscription_id,
        "Resource Group": resource_group,
        "Change Feed": str(response.get("properties", "").get("changeFeed").get("enabled"))
        if response.get("properties", "").get("changeFeed")
        else "",
        "Delete Retention Policy": str(response.get("properties", "").get("deleteRetentionPolicy").get("enabled"))
        if response.get("properties", "").get("deleteRetentionPolicy")
        else "",
        "Versioning": response.get("properties", "").get("isVersioningEnabled"),
    }

    return CommandResults(
        outputs_prefix="Azure.Storage.BlobServiceProperties",
        outputs_key_field="id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Azure Storage Blob Service Properties",
            readable_output,
            ["Name", "Account Name", "Subscription ID", "Resource Group", "Change Feed", "Delete Retention Policy", "Versioning"],
        ),
        raw_response=response,
    )



def update_aps_command(client: AzureClient, params: dict, args: dict):
    """Updating Analytics Platform System

    Args:
        client:
        args (dict): usually demisto.args()
    """
    setting_name = args.get("setting_name")
    auto_provision = args.get("auto_provision")
    setting = client.update_aps(setting_name, auto_provision)
    outputs = [
        {
            "Name": setting.get("name"),
            "AutoProvision": setting["properties"]["auto_provision"]
            if setting.get("properties") and setting.get("properties").get("auto_provision")
            else None,
            "ID": setting.get("id"),
        }
    ]

    md = tableToMarkdown(
        "Azure Security Center - Update Auto Provisioning Setting",
        outputs,
        ["Name", "AutoProvision", "ID"],
        removeNull=True,
    )
    # before the changes these two lines were existing:
    # ec = {"AzureSecurityCenter.AutoProvisioningSetting(val.ID && val.ID === obj.ID)": outputs}
    # return md, ec, setting
    return CommandResults(
        outputs_prefix="Azure.SecurityCenter",
        outputs_key_field="id",
        outputs=setting,
        readable_output=md,
        raw_response=outputs,
    )
    


def create_policy_assignment_command(client: AzureClient, params: dict, args: dict):
    name = args.get("name")
    subscription_id = args.get("subscription_id")
    policy_definition_id : str = args.get("policy_definition_id", "")
    display_name = args.get("display_name", "")
    parameters = json.loads(args.get("parameters", "{}"))
    description = args.get("description", "")
    response = client.create_policy_assignment(name, policy_definition_id, display_name, parameters, description, subscription_id)
    outputs = [
        {
            "Name": response.get("name"),
            "Policy Definition ID": response.get("properties", {}).get("policyDefinitionId", ""),
            "Display Name": response.get("properties", {}).get("displayName", ""),
            "Description": response.get("properties", {}).get("description", ""),
            "ID": response.get("id"),
        }
    ]
    md = tableToMarkdown(
        f"Azure policy assignment {name} was successfully created.",
        outputs,
        ["ID", "Name", "Policy Definition ID", "Display Name", "Description"],
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
    server_name = args.get("server_name")
    subscription_id = args.get("subscription_id")
    resource_group_name = args.get("resource_group_name")
    configuration_name = args.get("configuration_name", "")
    source = args.get("source", "")
    value = json.loads(args.get("value", "{}"))
    response = client.set_postgres_config(server_name, subscription_id, resource_group_name, configuration_name, source, value)
    print(response)


def set_webapp_config_command(client: AzureClient, params: dict, args: dict):
    name = args.get("name")
    subscription_id = args.get("subscription_id")
    resource_group_name = args.get("resource_group_name")
    http20_enabled = args.get("http20_enabled", "")
    remote_debugging_enabled = args.get("remote_debugging_enabled", "")
    min_tls_version = args.get("min_tls_version", "")
    response = client.set_webapp_config(name, subscription_id, resource_group_name, http20_enabled, remote_debugging_enabled, min_tls_version)
    print(response)
    outputs = [
        {
            "Name": response.get("name"),
            "Http20 Enabled": response.get("properties", {}).get("http20Enabled", ""),
            "Remote Debugging Enabled": response.get("properties", {}).get("remoteDebuggingEnabled", ""),
            "Min Tls Version": response.get("properties", {}).get("minTlsVersion", ""),
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
        outputs_prefix="Azure.WebApp.Configuration",
        outputs_key_field="id",
        outputs=response,
        readable_output=md,
        raw_response=outputs,
    )

def update_webapp_auth_command(client: AzureClient, params: dict, args: dict):
    name = args.get("name")
    subscription_id = args.get("subscription_id")
    resource_group_name = args.get("resource_group_name")
    enabled = args.get("enabled", "")
    response = client.update_webapp_auth(name, subscription_id, resource_group_name, enabled)
    print(response)
    outputs = [
        {
            "Name": response.get("name"),
            "Enabled": response.get("properties", {}).get("enabled", ""),
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
        outputs_prefix="Azure.WebApp.Auth",
        outputs_key_field="id",
        outputs=response,
        readable_output=md,
        raw_response=outputs,
    )

def resource_update_command(client: AzureClient, params: dict, args: dict):
    resource_id = args.get("resource_id")
    allow_blob_public_access = args.get("allow_blob_public_access")
    location = args.get("location")
    account_type = args.get("account_type")
    response = client.resource_update(resource_id, allow_blob_public_access, location, account_type)
    print(response)
    outputs = [
        {
            "Name": response.get("name"),
            "Properties": response.get("properties", {}),
            "ID": response.get("id")
        }
    ]
    md = tableToMarkdown(
        f"Resource {resource_id} updated successfully.",
        outputs,
        ["Name", "Properties", "ID"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="Azure.Resource",
        outputs_key_field="id",
        outputs=response,
        readable_output=md,
        raw_response=outputs,
    )
    
    
def flexible_server_param_set_command(client: AzureClient, params: dict, args: dict):
    configuration_name = args.get("configuration_name")
    server_name = args.get("server_name", "")
    subscription_id = args.get("subscription_id")
    resource_group_name = args.get("resource_group_name")
    source = args.get("source", "")
    value = args.get("value", "")
    response = client.flexible_server_param_set(server_name, configuration_name, subscription_id, resource_group_name, source, value)
    print(response)
    
    
def monitor_log_profile_update_command(client: AzureClient, params: dict, args: dict):
    log_profile_name = args.get("log_profile_name")
    location = args.get("location")
    subscription_id = args.get("subscription_id")
    retention_policy_days = arg_to_number(args.get("retention_policy_days"))
    retention_policy_enabled = args.get("retention_policy_enabled", "")
    current_log_profile = client.get_monitor_log_profile(subscription_id, log_profile_name)
    print(current_log_profile)
    response = client.monitor_log_profile_update(subscription_id, log_profile_name, location, retention_policy_days, retention_policy_enabled)
    print(response)
    
    
def disk_update_command(client: AzureClient, params: dict, args: dict):
    subscription_id = args.get("subscription_id")
    resource_group_name = args.get("resource_group_name")
    disk_name = args.get("disk_name")
    public_network_access = args.get("public_network_access")
    network_access_policy = args.get("network_access_policy")
    data_access_auth_mode = args.get("data_access_auth_mode")
    response = client.disk_update(subscription_id, resource_group_name, disk_name, public_network_access, network_access_policy, data_access_auth_mode)
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
        outputs_prefix="Azure.Compute.Disk",
        outputs_key_field="id",
        outputs=response,
        readable_output=md,
        raw_response=outputs,
    )
    
def webapp_identity_assign_command(client: AzureClient, params: dict, args: dict):
    subscription_id = args.get("subscription_id")
    resource_group_name = args.get("resource_group_name")
    name = args.get("name")
    identity_type = args.get("identity_type")
    client_id = args.get("client_id")
    principal_id = args.get("principal_id")
    identity_name = args.get("identity_name")
    current_webapp = client.get_webapp(subscription_id, resource_group_name, name)
    properties = current_webapp.get("properties")
    location = current_webapp.get("location")
    response = client.webapp_identity_assign(subscription_id, resource_group_name, name, identity_type, properties, location, identity_name, client_id, principal_id)
    print(response)
    

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
            "azure-storage-account-create-update": storage_account_create_update_command,
            "azure-storage-blob-service-properties-set": storage_blob_service_properties_set_command,
            "azure-sc-update-aps": update_aps_command,
            "azure-policy-assignment-create": create_policy_assignment_command,
            "azure-postgres-config-set": set_postgres_config_command,
            "azure-webapp-config-set": set_webapp_config_command,
            "azure-webapp-auth-update": update_webapp_auth_command,
            # "azure-resource-update": resource_update_command, ### maybe we use storage_account_create_update for this
            "azure-mysql-flexible-server-param-set": flexible_server_param_set_command,
            "azure-monitor-log-profile-update": monitor_log_profile_update_command,
            "azure-compute-disk-update": disk_update_command,
            "azure-webapp-identity-assign": webapp_identity_assign_command
        }
       
        if command == "test-module":
            return_results(test_module(client))
        elif command in commands_with_params_and_args:
            return_results(commands_with_params_and_args[command](client=client, params=params, args=args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
