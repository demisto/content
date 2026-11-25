import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

from MicrosoftApiModule import *  # noqa: E402
from COOCApiModule import *  # noqa: E402
from requests.exceptions import ConnectionError, Timeout
import datetime as dt
import urllib.parse
from urllib.parse import parse_qs, urlparse

""" CONSTANTS """

BLOB_SERVICE_PREFIX = "blob.core.windows.net"
STORAGE_DATE_FORMAT = "%a, %d %b %Y %H:%M:%S GMT"
API_VERSION = "2022-09-01"
# Azure Storage data-plane (Blob service) REST API version, used for both the x-ms-version
# request header and the SAS token signed version (sv) so the two always stay in sync.
STORAGE_API_VERSION = "2023-11-03"

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
DEFAULT_SCOPE = "https://management.azure.com/.default"
DEFAULT_RESOURCE = "https://management.azure.com/"
STORAGE_SCOPE = "https://storage.azure.com/.default"
STORAGE_RESOURCE = "https://storage.azure.com/"
DEFAULT_AZURE_AD_ENDPOINT = "https://login.microsoftonline.com"

API_FUNCTION_TO_PERMISSIONS = {
    "create_network_security_group": ["Microsoft.Network/networkSecurityGroups/write"],
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
    "sql_servers_list": ["Microsoft.Sql/servers/read"],
    "sql_db_list": ["Microsoft.Sql/servers/read", "Microsoft.Sql/servers/databases/read"],
    "sql_db_server_auditing_settings_list": [
        "Microsoft.Sql/servers/databases/read",
        "Microsoft.Sql/servers/databases/auditingSettings/read",
    ],
    "sql_db_audit_policy_list": [
        "Microsoft.Sql/servers/databases/read",
        "Microsoft.Sql/servers/databases/auditingSettings/read",
    ],
    "sql_db_audit_policy_create_update": [
        "Microsoft.Sql/servers/databases/auditingSettings/read",
        "Microsoft.Sql/servers/databases/auditingSettings/write",
    ],
    "sql_firewall_rules_list": ["Microsoft.Sql/servers/firewallRules/read"],
    "sql_firewall_rule_create_update": ["Microsoft.Sql/servers/firewallRules/write"],
    "sql_firewall_rule_delete": ["Microsoft.Sql/servers/firewallRules/delete"],
    "sql_firewall_rule_replace": ["Microsoft.Sql/servers/firewallRules/write"],
    "postgres_flexible_server_configuration_update": ["Microsoft.DBforPostgreSQL/flexibleServers/configurations/write"],
    "sql_db_threat_policy_update": [
        "Microsoft.Sql/servers/databases/securityAlertPolicies/read",
        "Microsoft.Sql/servers/databases/securityAlertPolicies/write",
    ],
    "sql_db_tde_set": [
        "Microsoft.Sql/servers/databases/transparentDataEncryption/read",
        "Microsoft.Sql/servers/databases/transparentDataEncryption/write",
    ],
    "storage_account_list_request": ["Microsoft.Storage/storageAccounts/read"],
    "storage_blob_container_list_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
    "storage_account_update_request": ["Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/write"],
    "storage_blob_service_properties_set_request": [
        "Microsoft.Storage/storageAccounts/blobServices/read",
        "Microsoft.Storage/storageAccounts/blobServices/write",
    ],
    "aks_clusters_list": ["Microsoft.ContainerService/managedClusters/read"],
    "aks_cluster_get": ["Microsoft.ContainerService/managedClusters/read"],
    "aks_cluster_addon_update": [
        "Microsoft.ContainerService/managedClusters/read",
        "Microsoft.ContainerService/managedClusters/write",
    ],
    "storage_container_create_blob_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"],
    "get_storage_container_properties_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
    "create_storage_container_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/write"],
    "delete_storage_container_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/delete"],
    "storage_container_blob_get_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
    "storage_container_blob_tag_get_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/read"],
    "storage_container_blob_tags_set_request": [
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write",
    ],
    "storage_container_blob_property_get_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
    "storage_container_blob_properties_set_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"],
    "storage_container_block_public_access_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/setAcl/action"],
    "storage_containers_list_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
    "storage_container_blobs_list_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
    "storage_container_blob_delete_request": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"],
    "get_rule": ["Microsoft.Network/networkSecurityGroups/securityRules/read"],
    "update_webapp_auth": ["Microsoft.Web/sites/config/read", "Microsoft.Web/sites/config/write"],
    "set_webapp_config": ["Microsoft.Web/sites/config/read", "Microsoft.Web/sites/config/write"],
    "webapp_update": ["Microsoft.Web/sites/read", "Microsoft.Web/sites/write"],
    "start_vm_request": ["Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/virtualMachines/start/action"],
    "poweroff_vm_request": ["Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/virtualMachines/poweroff/action"],
    "get_vm_request": ["Microsoft.Compute/virtualMachines/read"],
    "list_vm_request": ["Microsoft.Compute/virtualMachines/read"],
    "create_vm_request": ["Microsoft.Compute/virtualMachines/write"],
    "delete_vm_request": [
        "Microsoft.Compute/virtualMachines/deallocate/action",
        "Microsoft.Compute/virtualMachines/delete",
    ],
    "create_network_interface_request": [
        "Microsoft.Network/networkInterfaces/write",
        "Microsoft.Network/virtualNetworks/subnets/join/action",
        "Microsoft.Network/networkSecurityGroups/join/action",
    ],
    "get_network_interface_request": ["Microsoft.Network/networkInterfaces/read"],
    "update_network_interface_request": [
        "Microsoft.Network/networkInterfaces/read",
        "Microsoft.Network/networkInterfaces/write",
        "Microsoft.Network/virtualNetworks/subnets/join/action",
        "Microsoft.Network/publicIPAddresses/join/action",
        "Microsoft.Network/networkSecurityGroups/join/action",
        "Microsoft.Network/loadBalancers/backendAddressPools/join/action",
    ],
    "get_public_ip_details_request": ["Microsoft.Network/publicIPAddresses/read"],
    "get_all_public_ip_details_request": ["Microsoft.Network/publicIPAddresses/read"],
    "list_security_rules": ["Microsoft.Network/networkSecurityGroups/securityRules/read"],
    "waf_policy_get": ["Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read"],
    "waf_policy_list": ["Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read"],
    "waf_policy_upsert": ["Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/write"],
    "waf_policy_delete": ["Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/delete"],
    "waf_front_door_policy_get": ["Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/read"],
    "waf_front_door_policy_list": ["Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/read"],
    "waf_front_door_policy_upsert": ["Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/write"],
    "waf_front_door_policy_delete": ["Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/delete"],
    "firewall_policy_create_or_update": [
        "Microsoft.Network/firewallPolicies/read",
        "Microsoft.Network/firewallPolicies/write",
    ],
    "firewall_policy_get": ["Microsoft.Network/firewallPolicies/read"],
    "firewall_policy_delete": ["Microsoft.Network/firewallPolicies/delete"],
    "firewall_policy_list": ["Microsoft.Network/firewallPolicies/read"],
    "firewall_get": ["Microsoft.Network/azureFirewalls/read"],
    "firewall_update": [
        "Microsoft.Network/azureFirewalls/read",
        "Microsoft.Network/azureFirewalls/write",
        "Microsoft.Network/firewallPolicies/join/action",
    ],
    "create_table_request": ["Microsoft.Storage/storageAccounts/tableServices/tables/write"],
    "delete_table_request": ["Microsoft.Storage/storageAccounts/tableServices/tables/delete"],
    "list_tables_request": ["Microsoft.Storage/storageAccounts/tableServices/tables/read"],
    "insert_entity_request": ["Microsoft.Storage/storageAccounts/tableServices/tables/entities/write"],
    "update_entity_request": ["Microsoft.Storage/storageAccounts/tableServices/tables/entities/write"],
    "replace_entity_request": ["Microsoft.Storage/storageAccounts/tableServices/tables/entities/write"],
    "query_entity_request": ["Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"],
    "delete_entity_request": ["Microsoft.Storage/storageAccounts/tableServices/tables/entities/delete"],
    "ip_group_create": ["Microsoft.Network/ipGroups/write"],
    "ip_group_update": ["Microsoft.Network/ipGroups/read", "Microsoft.Network/ipGroups/write"],
    "ip_group_get": ["Microsoft.Network/ipGroups/read"],
    "ip_group_list": ["Microsoft.Network/ipGroups/read"],
    "ip_group_delete": ["Microsoft.Network/ipGroups/delete"],
    "firewall_list_request": ["Microsoft.Network/azureFirewalls/read"],
    "firewall_get_request": ["Microsoft.Network/azureFirewalls/read"],
    "firewall_policy_rule_collection_list_request": ["Microsoft.Network/firewallPolicies/ruleCollectionGroups/read"],
    "firewall_policy_rule_collection_get_request": ["Microsoft.Network/firewallPolicies/ruleCollectionGroups/read"],
    "firewall_service_tag_list_request": ["Microsoft.Network/locations/serviceTagDetails/read"],
    "resource_graph_list_operations": ["Microsoft.ResourceGraph/operations/read"],
    "resource_graph_query_resources": ["Microsoft.ResourceGraph/resources/read"],
    "list_virtual_networks_request": ["Microsoft.Network/virtualNetworks/read"],
    "list_subscriptions_request": ["Microsoft.Resources/subscriptions/read"],
    "firewall_policy_rule_collection_group_get": ["Microsoft.Network/firewallPolicies/ruleCollectionGroups/read"],
    "firewall_policy_rule_collection_group_create_or_update": [
        "Microsoft.Network/firewallPolicies/ruleCollectionGroups/read",
        "Microsoft.Network/firewallPolicies/ruleCollectionGroups/write",
    ],
    "firewall_policy_rule_collection_group_delete": ["Microsoft.Network/firewallPolicies/ruleCollectionGroups/delete"],
    "log_analytics_saved_searches_list": ["Microsoft.OperationalInsights/workspaces/savedSearches/read"],
    "log_analytics_saved_search_get": ["Microsoft.OperationalInsights/workspaces/savedSearches/read"],
    "log_analytics_saved_search_create_update": [
        "Microsoft.OperationalInsights/workspaces/savedSearches/read",
        "Microsoft.OperationalInsights/workspaces/savedSearches/write",
    ],
    "log_analytics_saved_search_delete": ["Microsoft.OperationalInsights/workspaces/savedSearches/delete"],
    "log_analytics_workspaces_list": ["Microsoft.OperationalInsights/workspaces/read"],
    "log_analytics_table_get": ["Microsoft.OperationalInsights/workspaces/tables/read"],
    "log_analytics_table_run": [
        "Microsoft.OperationalInsights/workspaces/tables/read",
        "Microsoft.OperationalInsights/workspaces/tables/write",
        "Microsoft.OperationalInsights/workspaces/searchJobs/write",
    ],
    "log_analytics_table_delete": ["Microsoft.OperationalInsights/workspaces/tables/delete"],
    "create_share_request": ["Microsoft.Storage/storageAccounts/fileServices/shares/write"],
    "delete_share_request": ["Microsoft.Storage/storageAccounts/fileServices/shares/delete"],
    "list_shares_request": ["Microsoft.Storage/storageAccounts/fileServices/shares/read"],
    "list_directories_and_files_request": [
        "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read",
        "Microsoft.Storage/storageAccounts/fileServices/readFileBackupSemantics/action",
    ],
    "create_directory_request": [
        "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write",
        "Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action",
    ],
    "delete_directory_request": [
        "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/delete",
        "Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action",
    ],
    "create_file_request": [
        "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write",
        "Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action",
    ],
    "add_file_content_request": [
        "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write",
        "Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action",
    ],
    "get_file_request": [
        "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read",
        "Microsoft.Storage/storageAccounts/fileServices/readFileBackupSemantics/action",
    ],
    "delete_file_request": [
        "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/delete",
        "Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action",
    ],
}

REQUIRED_ROLE_PERMISSIONS = [
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/networkSecurityGroups/securityRules/read",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/delete",
    "Microsoft.Network/networkInterfaces/read",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Storage/storageAccounts/write",
    "Microsoft.Storage/storageAccounts/blobServices/read",
    "Microsoft.Storage/storageAccounts/blobServices/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/setAcl/action",
    "Microsoft.Authorization/policyAssignments/read",
    "Microsoft.Authorization/policyAssignments/write",
    "Microsoft.DBforPostgreSQL/servers/read",
    "Microsoft.DBforPostgreSQL/servers/write",
    "Microsoft.DBforPostgreSQL/servers/configurations/read",
    "Microsoft.DBforPostgreSQL/servers/configurations/write",
    "Microsoft.DBforPostgreSQL/flexibleServers/configurations/write",
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
    "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Compute/virtualMachines/deallocate/action",
    "Microsoft.Compute/virtualMachines/delete",
    "Microsoft.Network/networkInterfaces/write",
    "Microsoft.Network/virtualNetworks/subnets/join/action",
    "Microsoft.Network/networkSecurityGroups/join/action",
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
    "Microsoft.ContainerService/managedClusters/read",
    "Microsoft.ContainerService/managedClusters/write",
    "Microsoft.Resources/subscriptions/read",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Network/firewallPolicies/ruleCollectionGroups/read",
    "Microsoft.Network/locations/serviceTagDetails/read",
    "Microsoft.Consumption/usageDetails/read",
    "Microsoft.Consumption/budgets/read",
    "Microsoft.CostManagement/forecast/read",
    "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read",
    "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/write",
    "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/delete",
    "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/read",
    "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/write",
    "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/delete",
    "Microsoft.Network/firewallPolicies/read",
    "Microsoft.Network/firewallPolicies/write",
    "Microsoft.Network/firewallPolicies/delete",
    "Microsoft.Network/firewallPolicies/join/action",
    "Microsoft.Network/azureFirewalls/read",
    "Microsoft.Network/azureFirewalls/write",
    "Microsoft.Storage/storageAccounts/tableServices/tables/read",
    "Microsoft.Storage/storageAccounts/tableServices/tables/write",
    "Microsoft.Storage/storageAccounts/tableServices/tables/delete",
    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read",
    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/write",
    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/delete",
    "Microsoft.Network/ipGroups/read",
    "Microsoft.Network/ipGroups/write",
    "Microsoft.Network/ipGroups/delete",
    "Microsoft.ResourceGraph/operations/read",
    "Microsoft.ResourceGraph/resources/read",
    "Microsoft.Network/firewallPolicies/ruleCollectionGroups/read",
    "Microsoft.Network/firewallPolicies/ruleCollectionGroups/write",
    "Microsoft.Network/firewallPolicies/ruleCollectionGroups/delete",
    "Microsoft.OperationalInsights/workspaces/read",
    "Microsoft.OperationalInsights/workspaces/query/read",
    "Microsoft.OperationalInsights/workspaces/savedSearches/read",
    "Microsoft.OperationalInsights/workspaces/savedSearches/write",
    "Microsoft.OperationalInsights/workspaces/savedSearches/delete",
    "Microsoft.OperationalInsights/workspaces/tables/read",
    "Microsoft.OperationalInsights/workspaces/tables/write",
    "Microsoft.OperationalInsights/workspaces/tables/delete",
    "Microsoft.OperationalInsights/workspaces/searchJobs/write",
    "Microsoft.Storage/storageAccounts/fileServices/shares/read",
    "Microsoft.Storage/storageAccounts/fileServices/shares/write",
    "Microsoft.Storage/storageAccounts/fileServices/shares/delete",
    "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read",
    "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write",
    "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/delete",
    "Microsoft.Storage/storageAccounts/fileServices/readFileBackupSemantics/action",
    "Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action",
    "Microsoft.Sql/servers/read",
    "Microsoft.Sql/servers/databases/read",
    "Microsoft.Sql/servers/databases/auditingSettings/read",
    "Microsoft.Sql/servers/databases/auditingSettings/write",
    "Microsoft.Sql/servers/firewallRules/read",
    "Microsoft.Sql/servers/firewallRules/write",
    "Microsoft.Sql/servers/firewallRules/delete",
]

PREFIX_URL_AZURE = "https://management.azure.com/subscriptions/"
PREFIX_URL_MS_GRAPH = "https://graph.microsoft.com/v1.0"
PERMISSIONS_VERSION = "2022-04-01"

# Commands decorated with @polling_function. The decorator requires the command arguments to be passed as the
# first positional argument, so AzureIntegration dispatches these commands differently from the regular ones.
POLLING_COMMANDS = {
    "azure-vn-ip-group-create",
    "azure-vn-ip-group-update",
    "azure-firewall-rule-collection-groups-create",
    "azure-firewall-rule-collection-groups-update",
    "azure-firewall-rule-collection-groups-delete",
    "azure-firewall-network-rule-create",
    "azure-firewall-network-rule-update",
    "azure-firewall-network-rule-delete",
    "azure-vn-firewall-policy-rule-collection-groups-create",
    "azure-vn-firewall-policy-rule-collection-groups-update",
    "azure-vn-firewall-policy-rule-collection-groups-delete",
    "azure-vn-firewall-policy-network-rule-create",
    "azure-vn-firewall-policy-network-rule-update",
    "azure-vn-firewall-policy-network-rule-delete",
    "azure-log-analytics-table-run",
}

# The following commands require the storage scope, token and resource (see AzureIntegration.is_storage_command).
STORAGE_SPECIAL_COMMANDS = [
    "azure-storage-blob-property-get",
    "azure-storage-blob-property-set",
    "azure-storage-blob-tag-get",
    "azure-storage-blob-create",
    "azure-storage-blob-get",
    "azure-storage-blob-tag-set",
    "azure-storage-table-create",
    "azure-storage-table-delete",
    "azure-storage-tables-list",
    "azure-storage-table-entity-insert",
    "azure-storage-table-entity-update",
    "azure-storage-table-entity-replace",
    "azure-storage-table-entity-query",
    "azure-storage-table-entity-delete",
    "azure-storage-blobs-list",
    "azure-storage-blob-update",
    "azure-storage-blob-delete",
    # File share DATA-PLANE commands (file.core.windows.net) require the storage scope/resource.
    # The share-level commands (create/delete/list) use the Microsoft.Storage ARM control plane
    # and therefore stay on the default management scope, so they are intentionally excluded here.
    "azure-storage-fileshare-content-list",
    "azure-storage-fileshare-directory-create",
    "azure-storage-fileshare-directory-delete",
    "azure-storage-fileshare-file-create",
    "azure-storage-fileshare-file-get",
    "azure-storage-fileshare-file-delete",
]

# Auth-helper commands establish or reset authentication and therefore must not require the
# Authorization code, which is only obtained by first running azure-generate-login-url. Requiring
# it here would create a chicken-and-egg block on the command whose purpose is to produce the code.
AUTH_HELPER_COMMANDS = {
    "azure-generate-login-url",
    "azure-auth-start",
    "azure-auth-complete",
    "azure-auth-reset",
    "azure-auth-test",
}


class TokenScope:
    STORAGE = "STORAGE"
    GRAPH = "GRAPH"
    NETWORK = "NETWORK"
    COMPUTE = "COMPUTE"
    VAULT = "VAULT"
    CONTAINER_REGISTRY = "CONTAINER_REGISTRY"
    DATABASE = "DATABASE"
    COSMOS = "COSMOS"
    DATA_LAKE_1 = "DATA_LAKE_1"
    DATA_LAKE_2 = "DATA_LAKE_2"
    SIGNALR = "SIGNALR"
    EVENT_HUBS = "EVENT_HUBS"
    SERVICE_BUS = "SERVICE_BUS"
    MONITOR = "MONITOR"
    DIGITAL_TWINS = "DIGITAL_TWINS"
    COGNITIVE_SERVICES = "COGNITIVE_SERVICES"
    SYNAPSE_ANALYTICS = "SYNAPSE_ANALYTICS"
    ML = "ML"
    NONE = "NONE"
    DEFAULT = "DEFAULT"
    SEARCH = "SEARCH"
    WORKSPACE_MEMBERSHIP = "WORKSPACE_MEMBERSHIP"
    WORKSPACE_GROUP = "WORKSPACE_GROUP"
    WORKSPACE_USER = "WORKSPACE_USER"
    WORKSPACE_DOMAIN = "WORKSPACE_DOMAIN"
    WORKSPACE_CUSTOMER = "WORKSPACE_CUSTOMER"


""" PERMISSION HELPERS """


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


""" CLIENT CLASS """


class AzureBaseClient:
    """Azure HTTP client core: authentication, ``http_request`` and ``handle_azure_error``.

    - **Marketplace path** (Cortex XSOAR / Cortex XSIAM): ``MicrosoftClient`` authenticates with the
      configured ``connection_type``.
    - **Cortex Platform path**: ``headers`` carry a CTS bearer token and requests go through ``BaseClient``.

    Integrations subclass it with their resource request methods (Azure: ``AzureClient``) and pass the
    subclass to ``AzureIntegration`` as ``client_class``.
    """

    def __init__(
        self,
        app_id: str = "",
        subscription_id: str = "",
        resource_group_name: str = "",
        verify: bool = False,
        proxy: bool = False,
        tenant_id: str | None = None,
        enc_key: str | None = None,
        resource: str | None = None,
        scope: str | None = None,
        headers: dict | None = {},
        connection_type: str = "Client Credentials",
        azure_ad_endpoint: str = "https://login.microsoftonline.com",
        auth_code: str | None = None,
        redirect_uri: str | None = None,
        managed_identities_client_id: str | None = None,
    ):
        self.connection_type = connection_type
        if not headers:
            is_device_code = "Device Code" in connection_type
            # Managed Identities authenticate against the IMDS endpoint, not an AAD token endpoint,
            # so they must not receive a token_retrieval_url.
            is_managed_identities = "Managed Identities" in connection_type
            token_retrieval_url: str | None
            ms_scope: str | None
            ms_resource: str | None
            if is_device_code:
                # Use the configured tenant when available so single-tenant apps get a tenant-scoped
                # authority. Fall back to the "organizations" endpoint only for multi-tenant apps with
                # no configured tenant; otherwise Microsoft returns "No tenant-identifying information
                # found in either the request or implied by any provided credentials".
                tenant_segment = tenant_id or "organizations"
                token_retrieval_url = urllib.parse.urljoin(azure_ad_endpoint, f"{tenant_segment}/oauth2/v2.0/token")
                # Use the per-command resource (management or storage) as the single source of truth,
                # then derive the matching Device Code delegated scope from it (space-delimited form,
                # unlike the `.default` form used by the other flows). This keeps storage-container
                # commands storage-scoped under Device Code auth instead of always management-scoped.
                ms_resource = (resource or DEFAULT_RESOURCE).rstrip("/")
                ms_scope = f"{ms_resource}/user_impersonation offline_access user.read"
            else:
                # Build the token authority from the configured Azure AD endpoint so that Client Credentials
                # and Authorization Code flows target the correct cloud (e.g. US Gov login.microsoftonline.us).
                # Without this, MicrosoftClient falls back to the commercial login.microsoftonline.com authority
                # while the scope/resource point to a national cloud, which Microsoft rejects with
                # "Confidential Client is not supported in Cross Cloud request".
                token_retrieval_url = (
                    None
                    if is_managed_identities
                    else urllib.parse.urljoin(azure_ad_endpoint, f"{tenant_id or ''}/oauth2/v2.0/token")
                )
                ms_scope = scope
                # The Client Credentials and Authorization Code flows use the v2.0 token endpoint, which
                # authorizes via the `.default` scope and rejects the v1.0 `resource` parameter. Sending both
                # results in "invalid_target: The resource parameter provided in the request doesn't match with
                # the requested scopes". Only Device Code (v1.0-style) uses `resource`.
                ms_resource = None
            ms_client_args = assign_params(
                self_deployed=True,
                auth_id=app_id,
                token_retrieval_url=token_retrieval_url,
                grant_type=GRANT_BY_CONNECTION.get(connection_type),
                base_url=f"{PREFIX_URL_AZURE}",
                verify=verify,
                proxy=proxy,
                resource=ms_resource,
                scope=ms_scope,
                azure_ad_endpoint=azure_ad_endpoint,
                tenant_id=tenant_id,
                enc_key=enc_key,
                auth_code=auth_code,
                redirect_uri=redirect_uri,
                managed_identities_client_id=managed_identities_client_id,
                managed_identities_resource_uri=(resource or DEFAULT_RESOURCE).rstrip("/")
                if is_managed_identities
                else (ms_resource or Resources.management_azure),
                command_prefix="azure",
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
        params: dict[str, Any] = {},
        resp_type: str = "json",
        json_data: dict | None = None,
        data: dict | bytes | None = None,
    ) -> requests.Response | dict[str, Any]:
        if not params:
            params = {}
        if not self.headers:
            self.headers = {}
        # A paginated `full_url` (an Azure `nextLink`) already carries its own `api-version` in its query
        # string. Injecting the default here would send the parameter twice, and ARM joins the two values
        # into one invalid version (e.g. "2025-09-01,2022-09-01"), failing the request with InvalidResourceType.
        url_has_api_version = bool(full_url) and "api-version" in parse_qs(urlparse(full_url or "").query)
        if not params.get("api-version") and not url_has_api_version and "x-ms-version" not in self.headers:
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
                data=data,
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
        demisto.debug(
            f"Azure API error for {subscription_id=} {error_msg=} {resource_type} '{resource_name}': {type(e).__name__}"
        )

        if "404" in error_msg or "not found" in error_msg:
            error_details = f'{resource_type} "{resource_name}"'
            if subscription_id and resource_group_name:
                error_details += f' under subscription ID "{subscription_id}" and resource group "{resource_group_name}"'
            elif subscription_id:
                error_details += f' under subscription ID "{subscription_id}"'
            raise ValueError(f"{error_details} was not found. {str(e)}")

        elif ("403" in error_msg or "forbidden" in error_msg) or ("401" in error_msg or "unauthorized" in error_msg):
            demisto.debug(f"Permission error, trying to find the missing permission. {e=}")
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

    def storage_container_set_headers(self, custom_headers: dict = {}, api_version: str = STORAGE_API_VERSION):
        """
        Set the headers for the storage container request.
        Args:
            custom_headers (dict, optional): Custom headers to be added to the request.
            api_version (str, optional): The storage data-plane REST API version sent in the x-ms-version header.
                Defaults to STORAGE_API_VERSION.
        """
        request_headers = {
            "x-ms-version": api_version,
            "x-ms-date": dt.datetime.utcnow().strftime(STORAGE_DATE_FORMAT),
        }
        if self.headers:
            self.headers |= request_headers
        else:
            self.headers = request_headers

        if custom_headers:
            self.headers |= custom_headers

        demisto.debug(f"Request headers: {self.headers}")


""" AUTH AND GOV HELPERS """


def switch_to_gov_account() -> None:
    global BLOB_SERVICE_PREFIX
    global SCOPE_BY_CONNECTION
    global DEFAULT_SCOPE
    global DEFAULT_RESOURCE
    global PREFIX_URL_AZURE
    global PREFIX_URL_MS_GRAPH

    BLOB_SERVICE_PREFIX = "blob.core.usgovcloudapi.net"
    SCOPE_BY_CONNECTION = {
        "Device Code": "https://management.usgovcloudapi.net/user_impersonation offline_access user.read",
        "Authorization Code": "https://management.usgovcloudapi.net/.default",
        "Client Credentials": "https://management.usgovcloudapi.net/.default",
    }
    DEFAULT_SCOPE = "https://management.usgovcloudapi.net/.default"
    DEFAULT_RESOURCE = "https://management.usgovcloudapi.net/"
    PREFIX_URL_AZURE = "https://management.usgovcloudapi.net/subscriptions/"
    PREFIX_URL_MS_GRAPH = "https://graph.microsoft.us/v1.0"


""" INTEGRATION CLASS """


class AzureIntegration(CloudIntegration):
    """COOC Azure implementation of ``CloudIntegration``.

    - **Marketplace path** (Cortex XSOAR / Cortex XSIAM): ``MicrosoftClient`` authenticates with the
      configured ``auth_type``.
    - **Cortex Platform path**: fetches a CTS access token for the ``subscription_id`` with the token
      scope of the command.

    ``get_client()`` builds ``client_class``: the integration's ``AzureBaseClient`` subclass with the resource
    request methods (Azure: ``AzureClient``), passed in by ``main()``.

    - **Registered commands** (``@AzureIntegration.register``): ``(client, args)``, or ``(args, client)``
      when registered with ``polling=True``.
    - **Existing commands** (``commands_mapping``): ``(client=, params=, args=)``, or
      ``(args, client=, params=)`` for ``POLLING_COMMANDS``.
    - **Auth helper commands** (``AUTH_HELPER_COMMANDS``) are handled by ``execute_auth_command``.

    The Gov endpoints are selected once per execution by ``switch_to_gov_account_if_needed``.
    """

    cloud_type = CloudTypes.AZURE.value
    account_id_arg = "subscription_id"
    uses_proxy_env = True

    def __init__(self, command: str, args: dict, params: dict, client_class: type[AzureBaseClient] = AzureBaseClient) -> None:
        super().__init__(command, args, params)
        self.client_class = client_class
        self.azure_ad_endpoint: str = params.get("azure_ad_endpoint") or DEFAULT_AZURE_AD_ENDPOINT

    def get_client(self) -> AzureBaseClient:
        """Build ``client_class`` for the current command.

        On the Cortex Platform path a CTS token is fetched for the token scope of the command. On the
        marketplace path the mandatory parameters of the configured auth type are validated, and
        ``MicrosoftClient`` handles authentication.

        Raises:
            DemistoException: If the CTS token is missing or mandatory auth parameters are not configured.
        """
        client_scope, token_scopes = self.get_command_and_token_scopes(self.command)
        connection_type = self.params.get("auth_type") or "Client Credentials"
        headers: dict = {}
        # The Cortex Platform (COOC) path is selected when a connector ID is present. There, the CTS
        # token flow (get_cloud_credentials -> demisto._platformAPICall) handles authentication.
        # On Cortex XSOAR / Cortex XSIAM (version < 3.0) there is no connector, so authentication is done
        # by MicrosoftClient using the configured auth_type.
        if self.connector_id:
            if not self.account_id:
                raise DemistoException(
                    "No subscription_id was provided. Please provide a subscription_id either in the instance "
                    "configuration or as a command argument."
                )
            token = self.get_credentials(scopes=token_scopes).get("access_token")
            if not token:
                raise DemistoException("Failed to retrieve AZURE access token - token is missing from credentials")
            headers = self._bearer_headers(token)
            demisto.debug("Using CTS.")
        else:
            # Marketplace path: ensure all mandatory parameters for the selected auth type are configured
            # before attempting any API call.
            self.validate_auth_params(self.params, connection_type, self.command)
        return self.client_class(
            app_id=self.params.get("app_id", ""),
            subscription_id=self.params.get("subscription_id", ""),
            resource_group_name=self.params.get("resource_group_name", ""),
            verify=not self.params.get("insecure", False),
            proxy=self.params.get("proxy", False),
            tenant_id=self.params.get("tenant_id"),
            enc_key=(self.params.get("credentials") or {}).get("password"),
            resource=self.get_command_resource(self.command),
            scope=client_scope,
            headers=headers,
            connection_type=connection_type,
            azure_ad_endpoint=self.azure_ad_endpoint,
            auth_code=(self.params.get("auth_code", {}) or {}).get("password"),
            redirect_uri=self.params.get("redirect_uri"),
            managed_identities_client_id=get_azure_managed_identities_client_id(self.params),
        )

    def is_gov_account(self, account_id: Optional[str] = None) -> bool:
        """Return whether an account of this connector is an Azure US Government cloud account.

        Checks the account's cloud partition via the onboarding API (``iter_accounts``). Account pages are
        fetched only until the account is found.

        Args:
            account_id: The subscription to check. Defaults to ``self.account_id``. When empty, the first
                account of the connector is checked (the account that ``run_health_check`` checks).

        Returns:
            ``True`` if the account's cloud partition is ``"GOV"``. ``False`` otherwise, if no connector ID
            is available, or if the accounts cannot be fetched (the commercial endpoints are used).
        """
        if not self.connector_id:
            return False

        account_id = self.account_id if account_id is None else account_id
        try:
            relevant_account = self._find_account(account_id)
        except Exception as e:
            demisto.error(f"[Azure] Failed to fetch the accounts of {self.connector_id=}, using the commercial endpoints: {e}")
            return False

        if not relevant_account:
            demisto.debug(f"[Azure] No account matching {account_id=} was found for {self.connector_id=}.")
            return False

        if account_cloud_partition := relevant_account.get("cloud_partition", ""):
            demisto.debug(f"[Azure] The found {account_cloud_partition=}")
            return account_cloud_partition.upper() == "GOV"

        demisto.debug(f"[Azure] No cloud partition information for account_id: {account_id}, {relevant_account=}.")
        return False

    def switch_to_gov_account_if_needed(self, account_id: Optional[str] = None) -> None:
        """Switch the Azure endpoints to the US Government cloud for Gov accounts.

        - **Cortex Platform path**: the cloud partition of the account (``is_gov_account(account_id)``).
        - **Marketplace path**: a non-commercial ``azure_ad_endpoint`` parameter.

        Args:
            account_id: Passed to ``is_gov_account``. Defaults to ``self.account_id``; empty checks the first
                account of the connector.
        """
        if self.connector_id:
            is_gov = self.is_gov_account(account_id)
        else:
            is_gov = self.azure_ad_endpoint.rstrip("/") != DEFAULT_AZURE_AD_ENDPOINT
        if is_gov:
            demisto.debug(f"Gov account ({self.connector_id=}, {self.azure_ad_endpoint=}); switching to Gov account.")
            switch_to_gov_account()

    def run_health_check(self) -> str | CommandResults:
        """Run the COOC health check (Cortex Platform path) against the Gov or commercial endpoints.

        The health check runs on the first account of the connector, so the Gov decision is made for
        that account (``account_id=""``) and not for the ``subscription_id`` parameter.
        """
        self.switch_to_gov_account_if_needed(account_id="")
        demisto.debug(f"Running health check for connector ID: {self.connector_id}")
        return super().run_health_check()

    def health_check(self, credentials: dict, account_id: str, connector_id: str) -> HealthCheckError | None:
        """Test connectivity to Azure for one subscription with pre-fetched CTS credentials.

        Args:
            credentials: CTS credentials for ``account_id``.
            account_id: The Azure subscription ID to check.
            connector_id: The Cortex connector ID.

        Returns:
            ``None`` if successful, otherwise a ``HealthCheckError``.
        """
        if not account_id:
            return HealthCheckError(
                account_id=account_id,
                connector_id=connector_id,
                message="Missing Subscription ID for Azure integration",
                error_type=ErrorType.INTERNAL_ERROR,
            )
        token = credentials.get("access_token")
        if not token:
            return HealthCheckError(
                account_id=account_id,
                connector_id=connector_id,
                message="Failed to authenticate with Azure",
                error_type=ErrorType.CONNECTIVITY_ERROR,
            )
        try:
            demisto.debug("Using token-based credentials for health check")
            self._test_connectivity(AzureBaseClient(subscription_id=account_id, headers=self._bearer_headers(token)))
        except Exception as e:
            return HealthCheckError(
                account_id=account_id,
                connector_id=connector_id,
                message=f"Failed to connect to Azure: {str(e)}",
                error_type=ErrorType.CONNECTIVITY_ERROR,
            )
        return None

    def test_module(self) -> str:
        """Test connectivity and authentication on the marketplace path (Test button).

        Raises:
            DemistoException: For the Device Code auth type, which cannot be validated by the Test button.
        """
        self.switch_to_gov_account_if_needed()
        return self._test_connectivity(self.get_client())

    def execute_command(self, commands_mapping: dict) -> Any:
        """Select the Gov endpoints, then run auth helper commands here and all other commands through the base flow."""
        self.switch_to_gov_account_if_needed()
        if self.command in AUTH_HELPER_COMMANDS:
            return self.execute_auth_command()
        return super().execute_command(commands_mapping)

    def execute_mapped_command(self, handler: Callable) -> Any:
        """Call an existing command: ``(args, client=, params=)`` for ``POLLING_COMMANDS``,
        ``(client=, params=, args=)`` otherwise."""
        client = self.get_client()
        if self.command in POLLING_COMMANDS:
            # Polling commands are decorated with @polling_function and therefore take args as their first
            # positional argument instead of receiving it as a keyword argument.
            return handler(self.args, client=client, params=self.params)
        return handler(client=client, params=self.params, args=self.args)

    def execute_auth_command(self) -> CommandResults | str:
        """Run a marketplace auth helper command (``AUTH_HELPER_COMMANDS``).

        ``azure-auth-reset`` runs without building a client. The other commands use the ``MicrosoftClient``
        of the client, which exists only on the marketplace path.

        Raises:
            DemistoException: On the Cortex Platform path, where these commands are not applicable.
        """
        if self.command == "azure-auth-reset":
            return reset_auth()

        ms_client = self._get_ms_client(self.get_client())
        if self.command == "azure-generate-login-url":
            return generate_login_url(ms_client, self.azure_ad_endpoint)
        if self.command == "azure-auth-start":
            return CommandResults(readable_output=ms_client.start_auth("!azure-auth-complete"))
        if self.command == "azure-auth-complete":
            ms_client.get_access_token()
            return "Authorization completed successfully."
        # azure-auth-test: if authentication fails, MicrosoftApiModule raises an error.
        ms_client.get_access_token()
        return "Success!"

    # ------------------------------------------------------------------
    # Azure-specific helpers
    # ------------------------------------------------------------------

    def _find_account(self, account_id: str) -> dict:
        """Return the connector account with ``account_id`` (the first account when empty), or ``{}`` if none matches.

        Stops fetching account pages as soon as the account is found.
        """
        return next(
            (account for account in self.iter_accounts() if not account_id or account.get("account_id") == account_id),
            {},
        )

    @staticmethod
    def is_storage_command(command: str) -> bool:
        """Return whether ``command`` uses the storage scope, token and resource instead of the management ones.

        Some 'azure-storage-blob' commands (such as azure-storage-blob-service-properties-get) use the management
        API, so only 'storage-container' commands and ``STORAGE_SPECIAL_COMMANDS`` are storage commands.
        """
        return "storage-container" in command or command in STORAGE_SPECIAL_COMMANDS

    @staticmethod
    def get_command_and_token_scopes(command: str) -> tuple[str, list[str]]:
        """Return the client scope and the CTS token scopes of ``command`` (storage or default)."""
        if AzureIntegration.is_storage_command(command):
            return STORAGE_SCOPE, [TokenScope.STORAGE]
        return DEFAULT_SCOPE, [TokenScope.DEFAULT]

    @staticmethod
    def get_command_resource(command: str) -> str:
        """Return the resource of ``command`` (storage or the default management resource)."""
        return STORAGE_RESOURCE if AzureIntegration.is_storage_command(command) else DEFAULT_RESOURCE

    @staticmethod
    def validate_auth_params(params: dict, connection_type: str, command: str = "") -> None:
        """Validate that all mandatory parameters for the selected authentication type are configured.

        This runs only on the Cortex XSOAR / Cortex XSIAM (marketplace) path.

        The mandatory parameters per authentication type are:
            - Client Credentials:     Application ID, Tenant ID, Client Secret, Default Subscription ID
            - Device Code:            Application ID, Default Subscription ID
            - Authorization Code:     Application ID, Application redirect URI, Authorization code,
                                      Default Subscription ID
            - Azure Managed Identities: Azure Managed Identities Client ID, Default Subscription ID

        The Authorization code is not required for auth-helper commands (e.g. azure-generate-login-url),
        since those commands are used to obtain/establish authentication before a code exists.

        Raises:
            DemistoException: If one or more mandatory parameters for the selected auth type are missing.
        """
        app_id = params.get("app_id")
        subscription_id = params.get("subscription_id")
        authorization_code_required: dict[str, Any] = {
            "Application ID": app_id,
            "Application redirect URI": params.get("redirect_uri"),
            "Default Subscription ID": subscription_id,
        }
        # Only demand the Authorization code itself when the caller is an actual data command, not an
        # auth-helper command such as azure-generate-login-url that is run to obtain the code.
        if command not in AUTH_HELPER_COMMANDS:
            authorization_code_required["Authorization code"] = (params.get("auth_code") or {}).get("password")

        required_by_auth_type: dict[str, dict[str, Any]] = {
            "Client Credentials": {
                "Application ID": app_id,
                "Tenant ID": params.get("tenant_id"),
                "Client Secret": (params.get("credentials") or {}).get("password"),
                "Default Subscription ID": subscription_id,
            },
            "Device Code": {
                "Application ID": app_id,
                "Default Subscription ID": subscription_id,
            },
            "Authorization Code": authorization_code_required,
            "Azure Managed Identities": {
                "Azure Managed Identities Client ID": get_azure_managed_identities_client_id(params),
                "Default Subscription ID": subscription_id,
            },
        }

        required_params = required_by_auth_type.get(connection_type, {})
        missing = [display_name for display_name, value in required_params.items() if not value]
        if missing:
            raise DemistoException(
                f"Missing required parameter(s) for the '{connection_type}' authentication type: "
                f"{', '.join(missing)}. Configure these in the integration instance and try again."
            )

    @staticmethod
    def _bearer_headers(token: str) -> dict:
        """Return the request headers for a CTS access token (Cortex Platform path)."""
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}

    @staticmethod
    def _get_ms_client(client: AzureBaseClient) -> "MicrosoftClient":
        """Return the ``MicrosoftClient`` of ``client``, used by the marketplace auth helper commands.

        Raises:
            DemistoException: On the Cortex Platform path, where authentication is handled by the connector.
        """
        ms_client = getattr(client, "ms_client", None)
        if ms_client is None:
            raise DemistoException(
                "This command is supported only on Cortex XSOAR and Cortex XSIAM. On the Cortex Platform, "
                "authentication is handled automatically and does not require these auth commands."
            )
        return ms_client

    @staticmethod
    def _test_connectivity(client: AzureBaseClient) -> str:
        """Send a lightweight request with ``client`` to validate connectivity and authentication.

        Returns:
            ``"ok"`` if the request succeeded.

        Raises:
            DemistoException: For the Device Code auth type, which cannot be validated without the auth commands.
            Exception: If the Azure endpoint cannot be reached, or the request fails.
        """
        if "Device Code" in client.connection_type:
            raise DemistoException(
                "When using the Device Code authentication type, the Test button cannot validate the "
                "connection. Save the instance, run the `!azure-auth-start` and `!azure-auth-complete` "
                "commands to log in, and then run the `!azure-auth-test` command to validate the connection. "
                "For more details, see the Detailed Instructions (?) Help section in the integration configuration."
            )
        try:
            if "Azure Managed Identities" in client.connection_type:
                # The roleAssignments call requires the Microsoft.Authorization/roleAssignments/read
                # permission, which a Managed Identity often lacks even when it can run other commands.
                # Validate the connection with a lightweight resource-groups list call, which only requires
                # the baseline Microsoft.Resources/subscriptions/resourceGroups/read permission.
                client.http_request(
                    method="GET",
                    full_url=f"{PREFIX_URL_AZURE}{client.subscription_id}/resourcegroups",
                    params={"$top": "1"},
                )
            else:
                client.http_request(
                    method="GET",
                    full_url=f"{PREFIX_URL_AZURE}{client.subscription_id}/providers/Microsoft.Authorization/roleAssignments",
                    params={"api-version": PERMISSIONS_VERSION},
                )
        except (ConnectionError, Timeout) as conn_err:
            raise Exception("Connectivity Error: Cannot reach Azure endpoint") from conn_err
        return "ok"
