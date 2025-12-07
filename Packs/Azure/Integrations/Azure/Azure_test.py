import json

import demistomock as demisto
import pytest
import Azure
from Azure import (
    AzureClient,
    format_rule,
    update_security_rule_command,
    storage_account_update_command,
    storage_blob_service_properties_set_command,
    create_policy_assignment_command,
    set_postgres_config_command,
    set_webapp_config_command,
    update_webapp_auth_command,
    mysql_flexible_server_param_set_command,
    monitor_log_profile_update_command,
    disk_update_command,
    webapp_update_command,
    acr_update_command,
    update_key_vault_command,
    sql_db_threat_policy_update_command,
    sql_db_tde_set_command,
    cosmosdb_update_command,
    remove_member_from_group_command,
    get_azure_client,
    remove_member_from_role,
    postgres_server_update_command,
    extract_azure_resource_info,
    WEBAPP_API_VERSION,
    FLEXIBLE_API_VERSION,
    CommandResults,
    DemistoException,
    CloudTypes,
    API_VERSION,
    SCOPE_BY_CONNECTION,
    PREFIX_URL_AZURE,
)


@pytest.fixture
def mock_params():
    return {
        "app_id": "test_app_id",
        "subscription_id": "test_subscription_id",
        "resource_group_name": "test_resource_group",
        "insecure": False,
        "proxy": False,
        "auth_type": "Client Credentials",
        "tenant_id": "test_tenant_id",
        "credentials": {"password": "test_enc_key"},
    }


@pytest.fixture
def client(mocker, mock_params):
    mocker.patch("MicrosoftApiModule.MicrosoftClient.http_request")
    mocker.patch("MicrosoftApiModule.MicrosoftClient.get_access_token")
    return AzureClient(
        app_id=mock_params.get("app_id", ""),
        subscription_id=mock_params.get("subscription_id", ""),
        resource_group_name=mock_params.get("resource_group_name", ""),
        verify=not mock_params.get("insecure", False),
        proxy=mock_params.get("proxy", False),
        tenant_id=mock_params.get("tenant_id"),
        enc_key=mock_params.get("credentials", {}).get("password"),
    )


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_update_security_rule_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update a security rule.
    When: The update_security_rule_command function is called with valid parameters.
    Then: The function should return the updated rule information in the expected format.
    """

    # Prepare mock responses
    rule_response = {
        "name": "test-rule",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-sg/\
            securityRules/test-rule",
        "properties": {
            "protocol": "Tcp",
            "sourcePortRange": "*",
            "destinationPortRange": "443",
            "sourceAddressPrefix": "Internet",
            "destinationAddressPrefix": "10.0.0.0/24",
            "access": "Allow",
            "priority": 100,
            "direction": "Inbound",
            "description": "Test rule",
        },
    }

    mocker.patch.object(client, "get_rule", return_value=rule_response)
    mocker.patch.object(client, "create_or_update_rule", return_value=rule_response)

    # Call the function
    args = {
        "security_group_name": "test-sg",
        "security_rule_name": "test-rule",
        "action": "Allow",
        "direction": "Inbound",
        "protocol": "Tcp",
        "source": "Internet",
        "destination": "10.0.0.0/24",
        "destination_ports": "443",
        "priority": "100",
        "description": "Test rule",
        "access": "Allow",
    }

    result = update_security_rule_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.NSGRule"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "test-rule"
    assert result.outputs["access"] == "Allow"


def test_storage_account_update_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update a storage account.
    When: The storage_account_update_command function is called with valid parameters.
    Then: The function should return the updated storage account information in the expected format.
    """
    # Prepare mock response
    storage_response = {
        "name": "teststorage",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage",
        "properties": {
            "networkAcls": {"bypass": "AzureServices", "defaultAction": "Deny"},
            "allowCrossTenantReplication": False,
            "supportsHttpsTrafficOnly": True,
        },
    }

    # Create a mock response object without using MagicMock
    class MockResponse:
        def __init__(self, json_data, text):
            self._json_data = json_data
            self.text = text

        def json(self):
            return self._json_data

    mock_response = MockResponse(storage_response, json.dumps(storage_response))

    mocker.patch.object(client, "storage_account_update_request", return_value=mock_response)

    # Call the function
    args = {
        "account_name": "teststorage",
        "sku": "Standard_LRS",
        "kind": "StorageV2",
        "location": "eastus",
        "network_ruleset_bypass": "AzureServices",
        "network_ruleset_default_action": "Deny",
        "allow_cross_tenant_replication": "false",
        "supports_https_traffic_only": "true",
    }

    result = storage_account_update_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.StorageAccount"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "teststorage"
    assert result.outputs["properties"]["supportsHttpsTrafficOnly"] is True


def test_storage_blob_service_properties_set_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to set blob service properties.
    When: The storage_blob_service_properties_set_command function is called with valid parameters.
    Then: The function should return the updated blob service properties in the expected format.
    """

    # Prepare mock response
    properties_response = {
        "name": "default",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage/blobServices/\
            default",
        "properties": {"deleteRetentionPolicy": {"enabled": True, "days": 7}},
    }

    mocker.patch.object(client, "storage_blob_service_properties_set_request", return_value=properties_response)

    # Call the function
    args = {"account_name": "teststorage", "delete_rentention_policy_enabled": "true", "delete_rentention_policy_days": "7"}

    result = storage_blob_service_properties_set_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.StorageAccountBlobServiceProperties"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "default"
    assert result.outputs["properties"]["deleteRetentionPolicy"]["enabled"] is True
    assert result.outputs["properties"]["deleteRetentionPolicy"]["days"] == 7


def test_create_policy_assignment_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to create a policy assignment.
    When: The create_policy_assignment_command function is called with valid parameters.
    Then: The function should return the created policy assignment in the expected format.
    """

    # Prepare mock response
    policy_response = {
        "name": "test-policy",
        "id": "/subscriptions/sub-id/providers/Microsoft.Authorization/policyAssignments/test-policy",
        "properties": {
            "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/policy-def-id",
            "displayName": "Test Policy",
            "description": "Test policy description",
            "parameters": {},
        },
    }

    mocker.patch.object(client, "create_policy_assignment", return_value=policy_response)

    # Call the function
    args = {
        "name": "test-policy",
        "scope": "sub-id",
        "policy_definition_id": "/providers/Microsoft.Authorization/policyDefinitions/policy-def-id",
        "display_name": "Test Policy",
        "description": "Test policy description",
        "parameters": "{}",
    }

    result = create_policy_assignment_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.PolicyAssignment"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "test-policy"
    assert result.outputs["properties"]["displayName"] == "Test Policy"


def test_set_postgres_config_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to set PostgreSQL configurations.
    When: The set_postgres_config_command function is called with valid parameters.
    Then: The function should return a success message.
    """

    # Prepare mock
    mocker.patch.object(client, "set_postgres_config", return_value=None)

    # Call the function
    args = {"server_name": "test-postgres", "configuration_name": "log_checkpoints", "source": "user-override", "value": "on"}

    result = set_postgres_config_command(client, mock_params, args)

    # Verify results
    assert "Updated the configuration log_checkpoints of the server test-postgres" in result.readable_output


def test_set_webapp_config_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to set WebApp configurations.
    When: The set_webapp_config_command function is called with valid parameters.
    Then: The function should return the updated WebApp configurations in the expected format.
    """

    # Prepare mock response
    webapp_response = {
        "name": "test-webapp",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-webapp",
        "properties": {"http20Enabled": True, "remoteDebuggingEnabled": False, "minTlsVersion": "1.2"},
    }

    mocker.patch.object(client, "set_webapp_config", return_value=webapp_response)

    # Call the function
    args = {"name": "test-webapp", "http20_enabled": "true", "remote_debugging_enabled": "false", "min_tls_version": "1.2"}

    result = set_webapp_config_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.WebAppConfig"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "test-webapp"
    assert result.outputs["properties"]["http20Enabled"] is True


def test_update_webapp_auth_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update WebApp authentication settings.
    When: The update_webapp_auth_command function is called with valid parameters.
    Then: The function should return the updated WebApp authentication settings in the expected format.
    """

    # Prepare mock responses
    current_auth = {
        "name": "authsettings",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-webapp/config/authsettings",
        "properties": {"enabled": False},
    }

    updated_auth = {
        "name": "authsettings",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-webapp/config/authsettings",
        "properties": {"enabled": True},
    }

    mocker.patch.object(client, "get_webapp_auth", return_value=current_auth)
    mocker.patch.object(client, "update_webapp_auth", return_value=updated_auth)

    # Call the function
    args = {"name": "test-webapp", "enabled": "true"}

    result = update_webapp_auth_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.WebAppAuth"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "authsettings"
    assert result.outputs["properties"]["enabled"] is True


def test_mysql_flexible_server_param_set_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to set MySQL flexible server parameters.
    When: The mysql_flexible_server_param_set_command function is called with valid parameters.
    Then: The function should return a success message.
    """

    # Prepare mock
    mocker.patch.object(client, "flexible_server_param_set", return_value=None)

    # Call the function
    args = {
        "server_name": "test-mysql",
        "configuration_name": "require_secure_transport",
        "source": "user-override",
        "value": "ON",
    }

    result = mysql_flexible_server_param_set_command(client, mock_params, args)

    # Verify results
    assert "Updated the configuration require_secure_transport of the server test-mysql" in result.readable_output


def test_monitor_log_profile_update_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update monitor log profile.
    When: The monitor_log_profile_update_command function is called with valid parameters.
    Then: The function should return the updated log profile in the expected format.
    """

    # Prepare mock responses
    current_profile = {
        "name": "test-profile",
        "id": "/subscriptions/sub-id/providers/Microsoft.Insights/logprofiles/test-profile",
        "location": "eastus",
        "properties": {"retentionPolicy": {"enabled": False, "days": 0}},
    }
    updated_profile = {
        "name": "test-profile",
        "id": "/subscriptions/sub-id/providers/Microsoft.Insights/logprofiles/test-profile",
        "location": "westus",
        "properties": {"retentionPolicy": {"enabled": True, "days": 30}},
    }

    mocker.patch.object(client, "get_monitor_log_profile", return_value=current_profile)
    mocker.patch.object(client, "monitor_log_profile_update", return_value=updated_profile)

    # Call the function
    args = {
        "log_profile_name": "test-profile",
        "location": "westus",
        "subscription_id": "sub-id",
        "retention_policy_days": "30",
        "retention_policy_enabled": "true",
    }

    result = monitor_log_profile_update_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.LogProfile"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "test-profile"
    assert result.outputs["location"] == "westus"
    assert result.outputs["properties"]["retentionPolicy"]["enabled"] is True
    assert result.outputs["properties"]["retentionPolicy"]["days"] == 30


def test_disk_update_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update disk properties.
    When: The disk_update_command function is called with valid parameters.
    Then: The function should return the updated disk properties in the expected format.
    """

    # Prepare mock response
    disk_response = {
        "name": "test-disk",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Compute/disks/test-disk",
        "properties": {
            "publicNetworkAccess": "Disabled",
            "networkAccessPolicy": "DenyAll",
            "dataAccessAuthMode": "AzureActiveDirectory",
        },
    }

    mocker.patch.object(client, "disk_update", return_value=disk_response)

    # Call the function
    args = {
        "disk_name": "test-disk",
        "public_network_access": "Disabled",
        "network_access_policy": "DenyAll",
        "data_access_auth_mode": "AzureActiveDirectory",
    }

    result = disk_update_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.Disk"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "test-disk"
    assert result.outputs["properties"]["publicNetworkAccess"] == "Disabled"
    assert result.outputs["properties"]["networkAccessPolicy"] == "DenyAll"
    assert result.outputs["properties"]["dataAccessAuthMode"] == "AzureActiveDirectory"


def test_webapp_update_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update webapp properties.
    When: The webapp_update_command function is called with valid parameters.
    Then: The function should return the updated webapp properties in the expected format.
    """

    # Prepare mock response
    webapp_response = {
        "name": "test-webapp",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-webapp",
        "identity": {"type": "SystemAssigned"},
        "properties": {"httpsOnly": True, "clientCertEnabled": True},
    }

    mocker.patch.object(client, "webapp_update", return_value=webapp_response)

    # Call the function
    args = {"name": "test-webapp", "identity_type": "SystemAssigned", "https_only": "true", "client_cert_enabled": "true"}

    result = webapp_update_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.WebApp"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "test-webapp"
    assert result.outputs["identity"]["type"] == "SystemAssigned"
    assert result.outputs["properties"]["httpsOnly"] is True
    assert result.outputs["properties"]["clientCertEnabled"] is True


def test_acr_update_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update Azure Container Registry properties.
    When: The acr_update_command function is called with valid parameters.
    Then: The function should return the updated ACR properties in the expected format.
    """

    # Prepare mock response
    acr_response = {
        "name": "testregistry",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.ContainerRegistry/registries/testregistry",
        "properties": {
            "publicNetworkAccess": "Disabled",
            "anonymousPullEnabled": False,
            "policies": {"exportPolicy": {"status": "disabled"}, "azureADAuthenticationAsArmPolicy": {"status": "enabled"}},
        },
    }

    mocker.patch.object(client, "acr_update", return_value=acr_response)

    # Call the function
    args = {
        "registry_name": "testregistry",
        "allow_exports": "disabled",
        "public_network_access": "Disabled",
        "anonymous_pull_enabled": "false",
        "authentication_as_arm_policy": "enabled",
    }

    result = acr_update_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.ACR"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "testregistry"
    assert result.outputs["properties"]["publicNetworkAccess"] == "Disabled"
    assert result.outputs["properties"]["anonymousPullEnabled"] is False
    assert result.outputs["properties"]["policies"]["exportPolicy"]["status"] == "disabled"
    assert result.outputs["properties"]["policies"]["azureADAuthenticationAsArmPolicy"]["status"] == "enabled"


def test_postgres_server_update_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update PostgreSQL server properties.
    When: The postgres_server_update_command function is called with valid parameters.
    Then: The function should successfully call the server update method.
    """

    # Prepare mock response
    postgres_response = {
        "name": "test-postgres",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.DBforPostgreSQL/servers/test-postgres",
        "properties": {"sslEnforcement": "Enabled"},
    }

    mocker.patch.object(client, "postgres_server_update", return_value=postgres_response)

    # Call the function
    args = {"server_name": "test-postgres", "ssl_enforcement": "Enabled"}

    # This command doesn't have a return value to test, just ensure it calls the client method
    postgres_server_update_command(client, mock_params, args)

    # Verify the client's method was called with the correct parameters
    client.postgres_server_update.assert_called_once_with(
        mock_params.get("subscription_id"), mock_params.get("resource_group_name"), "test-postgres", "Enabled"
    )


def test_update_key_vault_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update Key Vault properties.
    When: The update_key_vault_command function is called with valid parameters.
    Then: The function should return the updated Key Vault properties in the expected format.
    """

    # Prepare mock response
    keyvault_response = {
        "name": "test-keyvault",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-keyvault",
        "properties": {"enableSoftDelete": True, "enablePurgeProtection": True},
    }

    mocker.patch.object(client, "update_key_vault_request", return_value=keyvault_response)

    # Call the function
    args = {"vault_name": "test-keyvault", "enable_soft_delete": "true", "enable_purge_protection": "true"}

    result = update_key_vault_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.KeyVault"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "test-keyvault"
    assert result.outputs["properties"]["enableSoftDelete"] is True
    assert result.outputs["properties"]["enablePurgeProtection"] is True


def test_sql_db_threat_policy_update_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update SQL database threat policy.
    When: The sql_db_threat_policy_update_command function is called with valid parameters.
    Then: The function should return the updated threat policy in the expected format.
    """

    # Prepare mock responses
    current_policy = {
        "name": "default",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-db/\
            securityAlertPolicies/default",
        "properties": {"emailAccountAdmins": False},
    }

    updated_policy = {
        "name": "default",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-db/\
            securityAlertPolicies/default",
        "properties": {"emailAccountAdmins": True},
    }

    mocker.patch.object(client, "sql_db_threat_policy_get", return_value=current_policy)
    mocker.patch.object(client, "sql_db_threat_policy_update", return_value=updated_policy)

    # Call the function
    args = {"server_name": "test-server", "db_name": "test-db", "email_account_admins_enabled": "true"}

    result = sql_db_threat_policy_update_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.SqlDBThreatPolicy"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "default"
    assert result.outputs["properties"]["emailAccountAdmins"] is True


def test_sql_db_threat_policy_update_command_not_found(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update SQL database threat policy for a non-existent database.
    When: The sql_db_threat_policy_update_command function is called with invalid parameters.
    Then: The function should handle the error case properly.
    """

    # Mock a realistic 404 error response
    def mock_get_threat_policy(*args, **kwargs):
        # Simulate what the actual Azure API would return
        raise DemistoException("Resource not found - Database 'test-db' does not exist on server 'test-server'")

    mocker.patch.object(client, "sql_db_threat_policy_get", side_effect=mock_get_threat_policy)

    # Call the function
    args = {"server_name": "test-server", "db_name": "test-db", "email_account_admins_enabled": "true"}

    # Test that the function handles the exception appropriately
    with pytest.raises(DemistoException) as excinfo:
        sql_db_threat_policy_update_command(client, mock_params, args)

    # Verify the error message contains expected information
    assert "test-db" in str(excinfo.value)
    assert "test-server" in str(excinfo.value)


def test_sql_db_tde_set_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to set transparent data encryption for a SQL database.
    When: The sql_db_tde_set_command function is called with valid parameters.
    Then: The function should return a success message.
    """

    # Prepare mock
    mocker.patch.object(client, "sql_db_tde_set", return_value=None)

    # Call the function
    args = {"server_name": "test-server", "db_name": "test-db", "state": "Enabled"}

    result = sql_db_tde_set_command(client, mock_params, args)

    # Verify results
    assert "Updated SQL database test-db of the server test-server" in result.readable_output


def test_cosmosdb_update_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update Cosmos DB settings.
    When: The cosmosdb_update_command function is called with valid parameters.
    Then: The function should return the updated Cosmos DB settings in the expected format.
    """

    # Prepare mock response
    cosmos_response = {
        "name": "test-cosmos",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.DocumentDB/databaseAccounts/test-cosmos",
        "properties": {"disableKeyBasedMetadataWriteAccess": True},
    }

    mocker.patch.object(client, "cosmos_db_update", return_value=cosmos_response)

    # Call the function
    args = {"account_name": "test-cosmos", "disable_key_based_metadata_write_access": "true"}

    result = cosmosdb_update_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.CosmosDB"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "test-cosmos"
    assert result.outputs["properties"]["disableKeyBasedMetadataWriteAccess"] is True


def test_storage_account_update_command_empty_response(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update a storage account that returns an empty response.
    When: The storage_account_update_command function is called with valid parameters.
    Then: The function should return a message indicating the account will be created shortly.
    """

    # Prepare mock response with empty text
    class MockResponse:
        def __init__(self, text=""):
            self.text = text

    mock_response = MockResponse("")

    mocker.patch.object(client, "storage_account_update_request", return_value=mock_response)

    # Call the function
    args = {"account_name": "teststorage", "sku": "Standard_LRS", "kind": "StorageV2", "location": "eastus"}

    result = storage_account_update_command(client, mock_params, args)

    # Verify results
    assert isinstance(result, str)
    assert "The request was accepted - the account teststorage will be created shortly" in result


def test_update_security_rule_command_rule_not_found(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update a non-existent security rule.
    When: The update_security_rule_command function is called with invalid parameters.
    Then: The function should handle the error case properly by raising a ValueError.
    """

    # Mock a 404 error response by raising a ValueError with 404 in it
    error_message = 'Rule test-rule under subscription ID "test_subscription_id" and resource group "test_resource_group" was\
        not found.'
    mocker.patch.object(client, "get_rule", side_effect=ValueError(error_message))

    # Call the function and expect it to raise the ValueError
    args = {"security_group_name": "test-sg", "security_rule_name": "test-rule"}

    with pytest.raises(ValueError) as e:
        update_security_rule_command(client, mock_params, args)

    # Verify the error message
    assert error_message in str(e.value)


def test_main_function_success(mocker):
    """
    Given: A command and valid parameters.
    When: The main function is called.
    Then: The appropriate command function should be called and results returned.
    """
    from Azure import main

    # Mock demisto functions
    mocker.patch.object(demisto, "command", return_value="azure-storage-account-update")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "app_id": "test_app_id",
            "subscription_id": "test_subscription_id",
            "resource_group_name": "test_resource_group",
            "auth_type": "Client Credentials",
            "tenant_id": "test_tenant_id",
            "credentials": {"password": "test_enc_key"},
        },
    )
    mocker.patch.object(
        demisto,
        "args",
        return_value={"account_name": "teststorage", "sku": "Standard_LRS", "kind": "StorageV2", "location": "eastus"},
    )

    # Mock return_results
    mock_return_results = mocker.patch("Azure.return_results")

    # Mock AzureClient
    mock_client = mocker.Mock()
    mocker.patch("Azure.AzureClient", return_value=mock_client)
    # mocker.patch("COOCApiModule.is_gov_account", return_value=False)

    # Mock storage_account_update_command to return a CommandResults object
    mock_cmd_result = mocker.Mock()
    mock_storage_account_update = mocker.patch("Azure.storage_account_update_command", return_value=mock_cmd_result)

    # Call main function
    main()

    # Verify that storage_account_update_command was called and results returned
    mock_storage_account_update.assert_called_once()
    mock_return_results.assert_called_once_with(mock_cmd_result)


def test_storage_blob_service_properties_set_command_empty_values(mocker, client, mock_params):
    """
    Given: An Azure client and a request to set blob service properties with empty values.
    When: The storage_blob_service_properties_set_command function is called with minimal parameters.
    Then: The function should make the API call with only the specified parameters.
    """

    # Prepare mock response
    properties_response = {
        "name": "default",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage/blobServices/\
            default",
        "properties": {},
    }

    mocker.patch.object(client, "storage_blob_service_properties_set_request", return_value=properties_response)

    # Call the function with minimal args
    args = {"account_name": "teststorage"}

    result = storage_blob_service_properties_set_command(client, mock_params, args)

    # Verify results
    assert result.outputs_prefix == "Azure.StorageAccountBlobServiceProperties"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "default"

    # Verify client method was called with None values for optional parameters
    client.storage_blob_service_properties_set_request.assert_called_once_with(
        mock_params.get("subscription_id"), mock_params.get("resource_group_name"), "teststorage", None, None
    )


def test_remove_member_from_role(mocker, client):
    """
    Given: An Azure client and arguments for removing a member from a role.
    When: The remove_member_from_role function is called.
    Then: The function should call the client's remove_member_from_role method and return a success message.
    """
    # Mock arguments
    args = {"role_id": "12345678-1234-1234-1234-123456789012", "user_id": "87654321-4321-4321-4321-210987654321"}

    # Mock the client's remove_member_from_role method
    mocker.patch.object(client, "remove_member_from_role")

    # Call the function
    result = remove_member_from_role(client, args)

    # Verify results
    assert isinstance(result, CommandResults)
    assert f"User ID {args['user_id']} has been removed from role {args['role_id']}" in result.readable_output
    client.remove_member_from_role.assert_called_once_with(args["role_id"], args["user_id"])


def test_remove_member_from_group_command(mocker, client):
    """
    Given: An Azure client and arguments for removing a member from a group.
    When: The remove_member_from_group_command function is called.
    Then: The function should call the client's remove_member_from_group method and return a success message.
    """
    # Mock arguments
    args = {"group_id": "11111111-2222-3333-4444-555555555555", "user_id": "87654321-4321-4321-4321-210987654321"}

    # Mock the client's remove_member_from_group method
    mocker.patch.object(client, "remove_member_from_group")

    # Call the function
    result = remove_member_from_group_command(client, args)

    # Verify results
    assert isinstance(result, CommandResults)
    assert f"User {args['user_id']} was removed from the Group \"{args['group_id']}\" successfully." in result.readable_output
    client.remove_member_from_group.assert_called_once_with(args["group_id"], args["user_id"])


def test_get_azure_client_no_token(mocker, mock_params):
    """
    Given: Parameters without credentials and no token from cloud credentials.
    When: The get_azure_client function is called.
    Then: The function should raise an exception.
    """
    # Setup mocks
    args = {"subscription_id": "arg_subscription_id"}

    mocker.patch("Azure.get_from_args_or_params", return_value="mocked_subscription_id")
    mocker.patch("Azure.get_cloud_credentials", return_value={})  # No token

    # Test without credentials and no token
    params = mock_params.copy()
    params["credentials"] = {}

    # Verify exception is raised
    with pytest.raises(DemistoException) as excinfo:
        get_azure_client(params, args)

    assert "Failed to retrieve AZURE access token" in str(excinfo.value)


def test_get_azure_client_with_stored_credentials(mocker, mock_params):
    """
    Given: Parameters with stored credentials, arguments, and an Azure command.
    When: The get_azure_client function is called.
    Then: The function should return an initialized Azure client using stored credentials without cloud authentication.
    """
    # Setup mocks
    args = {"subscription_id": "arg_subscription_id"}
    mock_client = mocker.Mock()

    mock_azure_client_constructor = mocker.patch("Azure.AzureClient", return_value=mock_client)

    # Test with credentials (stored credentials path)
    params = mock_params.copy()
    params["credentials"] = {"password": "test_password"}

    # Call the function
    result = get_azure_client(params, args)

    # Verify results
    assert result == mock_client

    # Verify AzureClient was instantiated with correct parameters
    mock_azure_client_constructor.assert_called_once_with(
        app_id=params["app_id"],
        subscription_id=params["subscription_id"],
        resource_group_name=params["resource_group_name"],
        verify=not params["insecure"],
        proxy=params["proxy"],
        tenant_id=params["tenant_id"],
        enc_key="test_password",
        scope=SCOPE_BY_CONNECTION.get("Client Credentials"),
        headers={},
    )


def test_get_azure_client_with_cloud_credentials_azure_command(mocker, mock_params):
    """
    Given: Parameters without stored credentials, arguments, and an Azure command.
    When: The get_azure_client function is called.
    Then: The function should retrieve cloud credentials and return a client with proper headers and scope.
    """
    # Setup mocks
    args = {"subscription_id": "arg_subscription_id"}
    mock_client = mocker.Mock()
    mock_token = "mock_access_token"

    mocker.patch("Azure.get_from_args_or_params", return_value="test_subscription_id")
    mocker.patch("Azure.get_cloud_credentials", return_value={"access_token": mock_token})
    mock_azure_client_constructor = mocker.patch("Azure.AzureClient", return_value=mock_client)

    # Test without stored credentials (cloud credentials path)
    params = mock_params.copy()
    params["credentials"] = {}  # No stored credentials

    # Call the function
    result = get_azure_client(params, args)

    # Verify results
    assert result == mock_client

    # Verify cloud credentials were retrieved with correct parameters
    Azure.get_cloud_credentials.assert_called_once_with(CloudTypes.AZURE.value, "test_subscription_id")

    # Verify AzureClient was instantiated with correct parameters including headers
    expected_headers = {"Authorization": f"Bearer {mock_token}", "Content-Type": "application/json", "Accept": "application/json"}
    mock_azure_client_constructor.assert_called_once_with(
        app_id=params["app_id"],
        subscription_id=params["subscription_id"],
        resource_group_name=params["resource_group_name"],
        verify=not params["insecure"],
        proxy=params["proxy"],
        tenant_id=params["tenant_id"],
        enc_key=None,
        scope=SCOPE_BY_CONNECTION.get("Client Credentials"),
        headers=expected_headers,
    )


def test_get_azure_client_no_token_raises_exception(mocker, mock_params):
    """
    Given: Parameters without stored credentials and cloud credentials that return no token.
    When: The get_azure_client function is called.
    Then: The function should raise a DemistoException about missing token.
    """
    # Setup mocks
    args = {"subscription_id": "arg_subscription_id"}

    mocker.patch("Azure.get_from_args_or_params", return_value="test_subscription_id")
    mocker.patch("Azure.get_cloud_credentials", return_value={})  # No access_token

    # Test without credentials and no token
    params = mock_params.copy()
    params["credentials"] = {}

    # Verify exception is raised
    with pytest.raises(DemistoException) as excinfo:
        get_azure_client(params, args)

    assert "Failed to retrieve AZURE access token - token is missing from credentials" in str(excinfo.value)


def test_get_azure_client_insecure_and_proxy_settings(mocker, mock_params):
    """
    Given: Parameters with insecure=True and proxy=True settings.
    When: The get_azure_client function is called.
    Then: The function should pass the correct verify and proxy parameters to AzureClient.
    """
    # Setup mocks
    args = {"subscription_id": "arg_subscription_id"}
    mock_client = mocker.Mock()

    mock_azure_client_constructor = mocker.patch("Azure.AzureClient", return_value=mock_client)

    # Test with insecure and proxy settings
    params = mock_params.copy()
    params["insecure"] = True
    params["proxy"] = True
    params["credentials"] = {"password": "test_password"}

    # Call the function
    result = get_azure_client(params, args)

    # Verify results
    assert result == mock_client

    # Verify correct verify and proxy parameters
    call_args = mock_azure_client_constructor.call_args
    assert call_args[1]["verify"] is False  # insecure=True means verify=False
    assert call_args[1]["proxy"] is True


def test_get_azure_client_missing_optional_params(mocker):
    """
    Given: Parameters with missing optional fields.
    When: The get_azure_client function is called.
    Then: The function should handle missing parameters gracefully with default values.
    """
    # Setup mocks
    args = {}
    mock_client = mocker.Mock()

    mock_azure_client_constructor = mocker.patch("Azure.AzureClient", return_value=mock_client)

    # Test with minimal parameters
    params = {"credentials": {"password": "test_password"}}

    # Call the function
    result = get_azure_client(params, args)

    # Verify results
    assert result == mock_client

    # Verify default values were used
    call_args = mock_azure_client_constructor.call_args
    assert call_args[1]["app_id"] == ""
    assert call_args[1]["subscription_id"] == ""
    assert call_args[1]["resource_group_name"] == ""
    assert call_args[1]["verify"] is True  # Default for insecure=False
    assert call_args[1]["proxy"] is False  # Default
    assert call_args[1]["tenant_id"] is None


def test_format_rule_dict_input(mocker):
    """
    Given: A rule JSON as dictionary and security rule name.
    When: The format_rule function is called.
    Then: The function should format the rule properly and return CommandResults.
    """
    # Prepare test data
    rule_json = {
        "name": "test-rule",
        "id": (
            "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-sg/"
            "securityRules/test-rule"
        ),
        "properties": {
            "protocol": "Tcp",
            "sourcePortRange": "*",
            "destinationPortRange": "443",
            "access": "Allow",
            "priority": 100,
            "direction": "Inbound",
        },
    }
    security_rule_name = "test-rule"

    # Mock tableToMarkdown
    mock_table = mocker.patch("Azure.tableToMarkdown", return_value="Mock Table")

    # Call the function
    result = format_rule(rule_json, security_rule_name)

    # Verify results
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.NSGRule"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "test-rule"
    assert result.outputs["protocol"] == "Tcp"
    assert result.outputs["access"] == "Allow"
    assert "properties" not in result.outputs  # Properties should be flattened

    # Verify tableToMarkdown was called
    mock_table.assert_called_once()


def test_format_rule_list_input(mocker):
    """
    Given: A rule JSON as list and security rule name.
    When: The format_rule function is called.
    Then: The function should format all rules properly and return CommandResults.
    """
    # Prepare test data
    rule_json = [
        {
            "name": "rule1",
            "id": (
                "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-sg/"
                "securityRules/rule1"
            ),
            "properties": {"protocol": "Tcp", "access": "Allow"},
        },
        {
            "name": "rule2",
            "id": (
                "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-sg/"
                "securityRules/rule2"
            ),
            "properties": {"protocol": "Udp", "access": "Deny"},
        },
    ]
    security_rule_name = "test-rules"

    # Mock tableToMarkdown
    mocker.patch("Azure.tableToMarkdown", return_value="Mock Table")

    # Call the function
    result = format_rule(rule_json, security_rule_name)

    # Verify results
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.NSGRule"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 2
    assert result.outputs[0]["name"] == "rule1"
    assert result.outputs[0]["protocol"] == "Tcp"
    assert result.outputs[1]["name"] == "rule2"
    assert result.outputs[1]["protocol"] == "Udp"

    # Verify properties were flattened for all rules
    for rule in result.outputs:
        assert "properties" not in rule


def test_azure_client_handle_azure_error_404(mocker, client):
    """
    Given: An Azure client and a 404 error.
    When: The handle_azure_error method is called.
    Then: The function should raise a ValueError with appropriate message.
    """
    # Prepare test data
    error = Exception("404 - Not Found")
    resource_name = "test-resource"
    resource_type = "Storage Account"
    subscription_id = "test-subscription"
    resource_group_name = "test-rg"

    # Verify ValueError is raised for 404 errors
    with pytest.raises(ValueError) as excinfo:
        client.handle_azure_error(
            e=error,
            resource_name=resource_name,
            resource_type=resource_type,
            api_function_name="test",
            subscription_id=subscription_id,
            resource_group_name=resource_group_name,
        )

    assert 'Storage Account "test-resource"' in str(excinfo.value)
    assert 'subscription ID "test-subscription"' in str(excinfo.value)
    assert 'resource group "test-rg"' in str(excinfo.value)
    assert "was not found" in str(excinfo.value)


def test_azure_client_handle_azure_error_using_return_multiple_permissions_error_function(mocker):
    """
    Test the permission lookup logic and return_multiple_permissions_error call in handle_azure_error.

    Tests:
    1. Permission found via API function mapping
    2. Permission found via fallback method
    """
    from Azure import AzureClient

    mock_get_permissions_from_api = mocker.patch("Azure.get_permissions_from_api_function_name")
    mock_get_permissions_from_required = mocker.patch("Azure.get_permissions_from_required_role_permissions_list")
    mock_return_multiple_permissions_error = mocker.patch("Azure.return_multiple_permissions_error")
    client = AzureClient("tenant_id", "client_id", "client_secret")

    # Test case 1: Permission found via API function mapping
    mock_get_permissions_from_api.return_value = ["Microsoft.Network/networkInterfaces/read"]
    mock_get_permissions_from_required.return_value = None
    exception_403 = Exception("403 Forbidden: Access denied")

    client.handle_azure_error(
        e=exception_403,
        resource_name="test-nic",
        resource_type="Network Interface",
        api_function_name="list_networks_interfaces_request",
        subscription_id="sub123",
    )

    mock_get_permissions_from_api.assert_called_with("list_networks_interfaces_request", "403 forbidden: access denied")
    mock_get_permissions_from_required.assert_not_called()

    expected_error_entries = [
        {"account_id": "sub123", "message": "403 forbidden: access denied", "name": "Microsoft.Network/networkInterfaces/read"}
    ]
    mock_return_multiple_permissions_error.assert_called_once_with(expected_error_entries)

    mock_get_permissions_from_api.reset_mock()
    mock_get_permissions_from_required.reset_mock()
    mock_return_multiple_permissions_error.reset_mock()

    # Test case 2: Permission found via fallback method
    mock_get_permissions_from_api.return_value = None
    mock_get_permissions_from_required.return_value = ["Microsoft.Storage/storageAccounts/write"]
    exception_401 = Exception("401 Unauthorized")

    client.handle_azure_error(
        e=exception_401,
        resource_name="test-storage",
        resource_type="Storage Account",
        api_function_name="storage_account_update_request",
        subscription_id="sub456",
    )

    mock_get_permissions_from_api.assert_called_with("storage_account_update_request", "401 unauthorized")
    mock_get_permissions_from_required.assert_called_with("401 unauthorized")
    expected_error_entries = [
        {"account_id": "sub456", "message": "401 unauthorized", "name": "Microsoft.Storage/storageAccounts/write"}
    ]
    mock_return_multiple_permissions_error.assert_called_once_with(expected_error_entries)


def test_azure_client_handle_azure_error_400(mocker, client):
    """
    Given: An Azure client and a 400 error.
    When: The handle_azure_error method is called.
    Then: The function should raise a DemistoException with bad request error message.
    """
    # Prepare test data
    error = Exception("400 - Bad Request")
    resource_name = "test-resource"
    resource_type = "Disk"

    # Verify DemistoException is raised for 400 errors
    with pytest.raises(DemistoException) as excinfo:
        client.handle_azure_error(e=error, resource_name=resource_name, resource_type=resource_type, api_function_name="test")

    assert 'Invalid request for Disk "test-resource"' in str(excinfo.value)


def test_azure_client_handle_azure_error_generic(mocker, client):
    """
    Given: An Azure client and a generic error.
    When: The handle_azure_error method is called.
    Then: The function should raise a DemistoException with the original error.
    """
    # Prepare test data
    error = Exception("Some other error")
    resource_name = "test-resource"
    resource_type = "Virtual Machine"

    # Verify DemistoException is raised for generic errors
    with pytest.raises(DemistoException) as excinfo:
        client.handle_azure_error(e=error, resource_name=resource_name, resource_type=resource_type, api_function_name="test")

    assert 'Failed to access Virtual Machine "test-resource"' in str(excinfo.value)
    assert "Some other error" in str(excinfo.value)


def test_azure_client_http_request_with_headers(mocker, mock_params):
    """
    Given: An Azure client with headers and request parameters.
    When: The http_request method is called.
    Then: The function should make the request with proper headers and proxy settings.
    """
    # Setup mocks
    headers = {"Authorization": "Bearer token", "Content-Type": "application/json"}
    mock_base_client = mocker.Mock()
    mocker.patch("Azure.get_proxydome_token", return_value="proxy_token")
    mocker.patch("Azure.BaseClient", return_value=mock_base_client)

    # Create client with headers
    client = AzureClient(headers=headers)

    # Call the function
    client.http_request(method="GET", url_suffix="/test", params={"param1": "value1"})

    # Verify BaseClient was used and proxydome token was added
    expected_headers = headers.copy()
    expected_headers["x-caller-id"] = "proxy_token"

    mock_base_client._http_request.assert_called_once()
    call_args = mock_base_client._http_request.call_args
    assert call_args[1]["headers"] == expected_headers
    assert "proxies" in call_args[1]


def test_azure_client_http_request_without_headers(mocker, mock_params):
    """
    Given: An Azure client without headers.
    When: The http_request method is called.
    Then: The function should use MicrosoftClient for the request.
    """
    # Setup mocks
    mock_ms_client = mocker.Mock()
    mocker.patch("Azure.MicrosoftClient", return_value=mock_ms_client)

    # Create client without headers
    client = AzureClient()

    # Call the function
    client.http_request(method="GET", url_suffix="/test")

    # Verify MicrosoftClient was used
    mock_ms_client.http_request.assert_called_once_with(
        method="GET", url_suffix="/test", full_url=None, json_data=None, params={"api-version": "2022-09-01"}, resp_type="json"
    )


def test_azure_client_http_request_api_version_override(mocker, mock_params):
    """
    Given: An Azure client and request parameters with custom api-version.
    When: The http_request method is called.
    Then: The function should use the provided api-version instead of default.
    """
    # Setup mocks
    mock_ms_client = mocker.Mock()
    mocker.patch("Azure.MicrosoftClient", return_value=mock_ms_client)

    # Create client
    client = AzureClient()

    # Call the function with custom api-version
    custom_params = {"api-version": "2023-01-01", "other-param": "value"}
    client.http_request(method="GET", url_suffix="/test", params=custom_params)

    # Verify custom api-version was preserved
    mock_ms_client.http_request.assert_called_once()
    call_args = mock_ms_client.http_request.call_args
    assert call_args[1]["params"]["api-version"] == "2023-01-01"
    assert call_args[1]["params"]["other-param"] == "value"


def test_azure_client_initialization_without_refresh_token(mocker):
    """
    Given: An app_id without a refresh token.
    When: AzureClient is initialized.
    Then: The client should not modify the integration context.
    """
    # Mock integration context functions
    mocker.patch("Azure.get_integration_context", return_value={})
    mock_set_context = mocker.patch("Azure.set_integration_context")
    mocker.patch("Azure.MicrosoftClient")

    # Initialize client without refresh token
    AzureClient(app_id="test_app_id")

    # Verify integration context was not modified
    mock_set_context.assert_not_called()


def test_azure_client_http_request_with_base_client(mocker):
    """
    Given: An Azure client with headers configured.
    When: The http_request method is called.
    Then: The function should use BaseClient with proper headers and proxy settings.
    """
    # Setup mocks
    headers = {"Authorization": "Bearer token", "Content-Type": "application/json"}
    mock_base_client = mocker.Mock()
    mock_base_client._http_request.return_value = {"result": "success"}
    mocker.patch("Azure.BaseClient", return_value=mock_base_client)
    mocker.patch("Azure.get_proxydome_token", return_value="proxy_token")

    # Create client with headers
    client = AzureClient(headers=headers)

    # Call the function
    result = client.http_request(method="GET", url_suffix="/test")

    # Verify BaseClient was used with correct parameters
    expected_headers = headers.copy()
    expected_headers["x-caller-id"] = "proxy_token"

    mock_base_client._http_request.assert_called_once()
    call_args = mock_base_client._http_request.call_args
    assert call_args[1]["headers"] == expected_headers
    assert "proxies" in call_args[1]
    assert result == {"result": "success"}


def test_azure_client_http_request_with_microsoft_client(mocker):
    """
    Given: An Azure client without headers configured.
    When: The http_request method is called.
    Then: The function should use MicrosoftClient.
    """
    # Setup mocks
    mock_ms_client = mocker.Mock()
    mock_ms_client.http_request.return_value = {"result": "success"}
    mocker.patch("Azure.MicrosoftClient", return_value=mock_ms_client)

    # Create client without headers
    client = AzureClient()

    # Call the function
    result = client.http_request(method="POST", url_suffix="/test", json_data={"key": "value"})

    # Verify MicrosoftClient was used
    mock_ms_client.http_request.assert_called_once_with(
        method="POST",
        url_suffix="/test",
        full_url=None,
        json_data={"key": "value"},
        params={"api-version": "2022-09-01"},
        resp_type="json",
    )
    assert result == {"result": "success"}


def test_azure_client_get_rule(mocker, client):
    """
    Given: An Azure client and security rule parameters.
    When: The get_rule method is called.
    Then: The function should make the correct API call.
    """
    # Setup mock response
    mock_response = {
        "name": "test-rule",
        "id": (
            "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-sg/"
            "securityRules/test-rule"
        ),
        "properties": {"access": "Allow", "protocol": "Tcp"},
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    # Call the function
    result = client.get_rule("test-sg", "test-rule", "sub-id", "test-rg")

    # Verify correct API call was made
    expected_url = (
        f"{PREFIX_URL_AZURE}sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-sg/"
        "securityRules/test-rule"
    )
    client.http_request.assert_called_once_with("GET", full_url=expected_url)
    assert result == mock_response


def test_azure_client_create_policy_assignment(mocker, client):
    """
    Given: An Azure client and policy assignment parameters.
    When: The create_policy_assignment method is called.
    Then: The function should make the correct API call with policy properties.
    """
    # Setup mock response
    mock_response = {
        "name": "test-policy",
        "properties": {"policyDefinitionId": "/providers/Microsoft.Authorization/policySetDefinitions/test-def"},
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    # Call the function
    client.create_policy_assignment(
        name="test-policy",
        policy_definition_id="test-def",
        display_name="Test Policy",
        description="Test description",
        parameters={"param1": "value1"},
        scope="/scope",
    )

    # Verify correct API call was made
    expected_url = "https://management.azure.com/scope/providers/Microsoft.Authorization/policyAssignments/test-policy"
    client.http_request.assert_called_once()
    call_args = client.http_request.call_args
    assert call_args[1]["method"] == "PUT"
    assert call_args[1]["full_url"] == expected_url

    # Verify policy properties were included
    json_data = call_args[1]["json_data"]
    properties = json_data["properties"]
    assert properties["policyDefinitionId"] == "/providers/Microsoft.Authorization/policySetDefinitions/test-def"
    assert properties["displayName"] == "Test Policy"
    assert properties["description"] == "Test description"
    assert properties["parameters"] == {"param1": "value1"}


def test_azure_client_create_rule_success(mocker, client):
    """
    Given: An Azure client and valid rule creation parameters.
    When: The create_or_update_rule method is called.
    Then: The function should make the correct API call with rule properties and return the response.
    """
    # Setup mock response
    mock_response = {
        "name": "test-rule",
        "id": (
            "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-sg/"
            "securityRules/test-rule"
        ),
        "properties": {
            "protocol": "Tcp",
            "sourcePortRange": "*",
            "destinationPortRange": "443",
            "sourceAddressPrefix": "Internet",
            "destinationAddressPrefix": "10.0.0.0/24",
            "access": "Allow",
            "priority": 100,
            "direction": "Inbound",
            "description": "Test rule",
        },
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    # Prepare rule properties
    properties = {
        "protocol": "Tcp",
        "sourcePortRange": "*",
        "destinationPortRange": "443",
        "sourceAddressPrefix": "Internet",
        "destinationAddressPrefix": "10.0.0.0/24",
        "access": "Allow",
        "priority": 100,
        "direction": "Inbound",
        "description": "Test rule",
    }

    # Call the function
    result = client.create_or_update_rule(
        security_group="test-sg",
        rule_name="test-rule",
        properties=properties,
        subscription_id="sub-id",
        resource_group_name="test-rg",
    )

    # Verify correct API call was made
    expected_url = (
        f"{PREFIX_URL_AZURE}sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-sg/"
        "securityRules/test-rule?"
    )
    client.http_request.assert_called_once_with("PUT", full_url=expected_url, json_data={"properties": properties})

    # Verify response
    assert result == mock_response
    assert result["name"] == "test-rule"
    assert result["properties"]["protocol"] == "Tcp"
    assert result["properties"]["access"] == "Allow"


def test_azure_client_create_rule_with_complex_properties(mocker, client):
    """
    Given: An Azure client and complex rule properties with multiple ports and addresses.
    When: The create_or_update_rule method is called.
    Then: The function should handle complex properties correctly.
    """
    # Setup mock response
    mock_response = {
        "name": "complex-rule",
        "id": (
            "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-sg/"
            "securityRules/complex-rule"
        ),
        "properties": {
            "protocol": "*",
            "sourcePortRanges": ["80", "443", "8080-8090"],
            "destinationPortRanges": ["22", "3389"],
            "sourceAddressPrefixes": ["10.0.0.0/24", "192.168.1.0/24"],
            "destinationAddressPrefixes": ["172.16.0.0/16"],
            "access": "Deny",
            "priority": 200,
            "direction": "Outbound",
            "description": "Complex rule with multiple ranges",
        },
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    # Prepare complex rule properties
    properties = {
        "protocol": "*",
        "sourcePortRanges": ["80", "443", "8080-8090"],
        "destinationPortRanges": ["22", "3389"],
        "sourceAddressPrefixes": ["10.0.0.0/24", "192.168.1.0/24"],
        "destinationAddressPrefixes": ["172.16.0.0/16"],
        "access": "Deny",
        "priority": 200,
        "direction": "Outbound",
        "description": "Complex rule with multiple ranges",
    }

    # Call the function
    result = client.create_or_update_rule(
        security_group="test-sg",
        rule_name="complex-rule",
        properties=properties,
        subscription_id="sub-id",
        resource_group_name="test-rg",
    )

    # Verify correct API call was made
    expected_url = (
        f"{PREFIX_URL_AZURE}sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-sg/"
        "securityRules/complex-rule?"
    )
    client.http_request.assert_called_once_with("PUT", full_url=expected_url, json_data={"properties": properties})

    # Verify response contains complex properties
    assert result == mock_response
    assert result["properties"]["sourcePortRanges"] == ["80", "443", "8080-8090"]
    assert result["properties"]["destinationPortRanges"] == ["22", "3389"]
    assert result["properties"]["sourceAddressPrefixes"] == ["10.0.0.0/24", "192.168.1.0/24"]


def test_azure_client_storage_account_update_request_success(mocker, client):
    """
    Given: An Azure client and valid storage account update parameters.
    When: The storage_account_update_request method is called.
    Then: The function should make the correct API call with storage account properties and return the response.
    """
    # Setup mock response
    mock_response = mocker.Mock()
    mock_response.text = '{"name": "teststorage", "properties": {"supportsHttpsTrafficOnly": true}}'
    mock_response.json.return_value = {
        "name": "teststorage",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage",
        "properties": {"supportsHttpsTrafficOnly": True, "networkAcls": {"bypass": "AzureServices", "defaultAction": "Deny"}},
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    # Prepare arguments
    args = {
        "account_name": "teststorage",
        "sku": "Standard_LRS",
        "kind": "StorageV2",
        "location": "eastus",
        "supports_https_traffic_only": "true",
        "network_ruleset_bypass": "AzureServices",
        "network_ruleset_default_action": "Deny",
    }

    # Call the function
    result = client.storage_account_update_request(subscription_id="sub-id", resource_group_name="test-rg", args=args)

    # Verify correct API call was made
    expected_url = f"{PREFIX_URL_AZURE}sub-id/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage"
    client.http_request.assert_called_once()
    call_args = client.http_request.call_args

    assert call_args[1]["method"] == "PATCH"
    assert call_args[1]["full_url"] == expected_url
    assert call_args[1]["params"]["api-version"] == API_VERSION
    assert call_args[1]["resp_type"] == "response"

    # Verify JSON data structure
    json_data = call_args[1]["json_data"]
    assert json_data["sku"]["name"] == "Standard_LRS"
    assert json_data["kind"] == "StorageV2"
    assert json_data["location"] == "eastus"
    assert json_data["properties"]["supportsHttpsTrafficOnly"] == "true"
    assert json_data["properties"]["networkAcls"]["bypass"] == "AzureServices"
    assert json_data["properties"]["networkAcls"]["defaultAction"] == "Deny"

    # Verify response
    assert result == mock_response


def test_azure_client_storage_blob_service_properties_set_request_success(mocker, client):
    """
    Given: An Azure client and valid blob service properties parameters.
    When: The storage_blob_service_properties_set_request method is called.
    Then: The function should make the correct API call with blob properties and return the response.
    """
    # Setup mock response
    mock_response = {
        "name": "default",
        "id": (
            "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage/"
            "blobServices/default"
        ),
        "properties": {"deleteRetentionPolicy": {"enabled": True, "days": 7}},
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    # Call the function
    result = client.storage_blob_service_properties_set_request(
        subscription_id="sub-id",
        resource_group_name="test-rg",
        account_name="teststorage",
        delete_rentention_policy_enabled="true",
        delete_rentention_policy_days="7",
    )

    # Verify correct API call was made
    expected_url = (
        f"{PREFIX_URL_AZURE}sub-id/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage/"
        "blobServices/default"
    )
    client.http_request.assert_called_once()
    call_args = client.http_request.call_args

    assert call_args[1]["method"] == "PUT"
    assert call_args[1]["full_url"] == expected_url
    assert call_args[1]["params"]["api-version"] == API_VERSION

    # Verify JSON data structure
    json_data = call_args[1]["json_data"]
    assert json_data["properties"]["deleteRetentionPolicy"]["enabled"] == "true"
    assert json_data["properties"]["deleteRetentionPolicy"]["days"] == "7"

    # Verify response
    assert result == mock_response
    assert result["name"] == "default"
    assert result["properties"]["deleteRetentionPolicy"]["enabled"] is True
    assert result["properties"]["deleteRetentionPolicy"]["days"] == 7


def test_azure_client_handle_azure_error_other(client):
    """
    Given: An unknown error from Azure API.
    When: handle_azure_error is called.
    Then: The function should raise DemistoException with generic message.
    """
    error = Exception("500 - Internal Server Error")

    with pytest.raises(DemistoException) as excinfo:
        client.handle_azure_error(e=error, resource_name="test-resource", resource_type="SQL Database", api_function_name="test")

    assert 'Failed to access SQL Database "test-resource"' in str(excinfo.value)
    assert "500 - Internal Server Error" in str(excinfo.value)


def test_azure_client_update_webapp_auth_success(mocker, client):
    """
    Given: An Azure client and webapp authentication update parameters.
    When: The update_webapp_auth method is called.
    Then: The function should make the correct API call and return updated settings.
    """
    # Setup mock response
    enabled = True
    mock_response = {"name": "authsettings", "properties": {"enabled": enabled}}
    mocker.patch.object(client, "http_request", return_value=mock_response)

    # Call the function
    result = client.update_webapp_auth(
        name="test-webapp", subscription_id="sub-id", resource_group_name="test-rg", enabled=enabled
    )

    # Verify correct API call
    expected_url = (
        f"{PREFIX_URL_AZURE}sub-id/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-webapp/config/authsettings"
    )
    client.http_request.assert_called_once_with(
        method="PUT",
        full_url=expected_url,
        json_data={"properties": {"enabled": True}},
        params={"api-version": WEBAPP_API_VERSION},
    )

    # Verify response
    assert result == mock_response


def test_azure_client_flexible_server_param_set_success(mocker, client):
    """
    Given: An Azure client and valid MySQL flexible server parameters.
    When: The flexible_server_param_set method is called.
    Then: The function should make the correct API call with proper parameters and return the response.
    """
    # Setup mock response
    mock_response = {
        "name": "require_secure_transport",
        "id": (
            "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.DBforMySQL/flexibleServers/test-mysql/"
            "configurations/require_secure_transport"
        ),
        "properties": {"value": "ON", "source": "user-override", "description": "Whether to require SSL connections"},
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    # Call the function
    result = client.flexible_server_param_set(
        server_name="test-mysql",
        configuration_name="require_secure_transport",
        subscription_id="sub-id",
        resource_group_name="test-rg",
        source="user-override",
        value="ON",
    )

    # Verify correct API call was made
    expected_url = (
        f"{PREFIX_URL_AZURE}sub-id/resourceGroups/test-rg/providers/Microsoft.DBforMySQL/flexibleServers/test-mysql/"
        "configurations/require_secure_transport"
    )
    client.http_request.assert_called_once_with(
        method="PUT",
        full_url=expected_url,
        json_data={"properties": {"source": "user-override", "value": "ON"}},
        params={"api-version": FLEXIBLE_API_VERSION},
    )

    # Verify response
    assert result == mock_response
    assert result["name"] == "require_secure_transport"
    assert result["properties"]["value"] == "ON"
    assert result["properties"]["source"] == "user-override"


def test_set_webapp_config(mocker, client):
    """
    Given: An Azure client and arguments for setting webapp configuration.
    When: The set_webapp_config method is called.
    Then: The method should make the correct HTTP request with proper parameters and handle the response.
    """
    # Mock arguments
    name = "test-webapp"
    subscription_id = "12345678-1234-1234-1234-123456789012"
    resource_group_name = "test-resource-group"
    http20_enabled = "true"
    remote_debugging_enabled = "false"
    min_tls_version = "1.2"

    # Mock response
    mock_response = {
        "id": (
            f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Web/sites/{name}/config/"
            "web"
        ),
        "name": "web",
        "properties": {"http20Enabled": True, "remoteDebuggingEnabled": False, "minTlsVersion": "1.2"},
    }

    # Mock the client's http_request method
    mocker.patch.object(client, "http_request", return_value=mock_response)

    # Call the method
    result = client.set_webapp_config(
        name=name,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
        http20_enabled=http20_enabled,
        remote_debugging_enabled=remote_debugging_enabled,
        min_tls_version=min_tls_version,
    )

    # Verify the HTTP request was called with correct parameters
    expected_url = (
        f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}"
        f"/providers/Microsoft.Web/sites/{name}/config/web"
    )
    expected_data = {
        "properties": {
            "http20Enabled": http20_enabled,
            "remoteDebuggingEnabled": remote_debugging_enabled,
            "minTlsVersion": min_tls_version,
        }
    }
    expected_params = {"api-version": "2024-04-01"}

    client.http_request.assert_called_once_with(
        method="PATCH", full_url=expected_url, json_data=expected_data, params=expected_params
    )

    # Verify the result matches the mock response
    assert result == mock_response


def test_get_webapp_auth_error_handling(mocker, client):
    """
    Given: An Azure client and arguments for getting webapp authentication settings.
    When: The get_webapp_auth method is called and an exception occurs.
    Then: The method should call handle_azure_error with appropriate parameters.
    """
    # Mock arguments
    name = "test-webapp"
    subscription_id = "12345678-1234-1234-1234-123456789012"
    resource_group_name = "test-resource-group"

    # Mock exception
    mock_exception = Exception("404 Not Found")

    # Mock the client's methods
    mocker.patch.object(client, "http_request", side_effect=mock_exception)
    mocker.patch.object(client, "handle_azure_error", side_effect=ValueError("Web App not found"))

    # Call the method and expect it to raise an exception
    with pytest.raises(ValueError, match="Web App not found"):
        client.get_webapp_auth(name=name, subscription_id=subscription_id, resource_group_name=resource_group_name)

    # Verify handle_azure_error was called with correct parameters
    client.handle_azure_error.assert_called_once_with(
        e=mock_exception,
        resource_name=name,
        api_function_name="get_webapp_auth",
        resource_type="Web App",
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
    )


def test_update_webapp_auth_error_handling(mocker, client):
    """
    Given: An Azure client and arguments for updating webapp authentication settings.
    When: The update_webapp_auth method is called and an exception occurs.
    Then: The method should call handle_azure_error with appropriate parameters.
    """
    # Mock arguments
    name = "test-webapp"
    enabled = True
    subscription_id = "12345678-1234-1234-1234-123456789012"
    resource_group_name = "test-resource-group"

    # Mock exception
    mock_exception = Exception("403 Forbidden")

    # Mock the client's methods
    mocker.patch.object(client, "http_request", side_effect=mock_exception)
    mocker.patch.object(client, "handle_azure_error", side_effect=DemistoException("Insufficient permissions"))

    # Call the method and expect it to raise an exception
    with pytest.raises(DemistoException, match="Insufficient permissions"):
        client.update_webapp_auth(
            name=name, subscription_id=subscription_id, resource_group_name=resource_group_name, enabled=enabled
        )

    # Verify handle_azure_error was called with correct parameters
    client.handle_azure_error.assert_called_once_with(
        e=mock_exception,
        resource_name=name,
        api_function_name="update_webapp_auth",
        resource_type="Web App",
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
    )


def test_flexible_server_param_set(mocker, client):
    """
    Given: An Azure client and arguments for setting MySQL flexible server parameters.
    When: The flexible_server_param_set method is called.
    Then: The method should make the correct HTTP request with proper parameters.
    """
    # Mock arguments
    server_name = "test-mysql-server"
    configuration_name = "max_connections"
    subscription_id = "12345678-1234-1234-1234-123456789012"
    resource_group_name = "test-resource-group"
    source = "user-override"
    value = "1000"

    # Mock response
    mock_response = {
        "id": (
            f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.DBforMySQL/"
            f"flexibleServers/{server_name}/configurations/{configuration_name}"
        ),
        "name": configuration_name,
        "properties": {"source": source, "value": value},
    }

    # Mock the client's http_request method
    mocker.patch.object(client, "http_request", return_value=mock_response)

    # Call the method
    result = client.flexible_server_param_set(
        server_name=server_name,
        configuration_name=configuration_name,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
        source=source,
        value=value,
    )

    # Verify the HTTP request was called with correct parameters
    expected_url = (
        f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}"
        f"/providers/Microsoft.DBforMySQL/flexibleServers/{server_name}/configurations/{configuration_name}"
    )
    expected_data = {"properties": {"source": source, "value": value}}
    expected_params = {"api-version": "2023-12-30"}

    client.http_request.assert_called_once_with(
        method="PUT", full_url=expected_url, json_data=expected_data, params=expected_params
    )

    # Verify the result matches the mock response
    assert result == mock_response


def test_flexible_server_param_set_error_handling(mocker, client):
    """
    Given: An Azure client and arguments for setting MySQL flexible server parameters.
    When: The flexible_server_param_set method is called and an exception occurs.
    Then: The method should call handle_azure_error with appropriate parameters.
    """
    # Mock arguments
    server_name = "test-mysql-server"
    configuration_name = "max_connections"
    subscription_id = "12345678-1234-1234-1234-123456789012"
    resource_group_name = "test-resource-group"
    source = "user-override"
    value = "1000"

    # Mock exception
    mock_exception = Exception("404 Not Found")

    # Mock the client's methods
    mocker.patch.object(client, "http_request", side_effect=mock_exception)
    mocker.patch.object(client, "handle_azure_error", side_effect=ValueError("MySQL Flexible Server Configuration not found"))

    # Call the method and expect it to raise an exception
    with pytest.raises(ValueError, match="MySQL Flexible Server Configuration not found"):
        client.flexible_server_param_set(
            server_name=server_name,
            configuration_name=configuration_name,
            subscription_id=subscription_id,
            resource_group_name=resource_group_name,
            source=source,
            value=value,
        )

    # Verify handle_azure_error was called with correct parameters
    client.handle_azure_error.assert_called_once_with(
        e=mock_exception,
        resource_name=f"{server_name}/{configuration_name}",
        resource_type="MySQL Flexible Server Configuration",
        api_function_name="flexible_server_param_set",
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
    )


def test_get_monitor_log_profile(mocker, client):
    """
    Given: An Azure client and arguments for getting a monitor log profile.
    When: The get_monitor_log_profile method is called.
    Then: The method should make the correct HTTP request and return the log profile.
    """
    # Mock arguments
    subscription_id = "12345678-1234-1234-1234-123456789012"
    log_profile_name = "test-log-profile"

    # Mock response
    mock_response = {
        "id": f"/subscriptions/{subscription_id}/providers/Microsoft.Insights/logprofiles/{log_profile_name}",
        "name": log_profile_name,
        "location": "global",
        "properties": {
            "storageAccountId": "/subscriptions/test/resourceGroups/test/providers/Microsoft.Storage/storageAccounts/test",
            "retentionPolicy": {"enabled": True, "days": 30},
        },
    }

    # Mock the client's http_request method
    mocker.patch.object(client, "http_request", return_value=mock_response)

    # Call the method
    result = client.get_monitor_log_profile(subscription_id=subscription_id, log_profile_name=log_profile_name)

    # Verify the HTTP request was called with correct parameters
    expected_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Insights/logprofiles/{log_profile_name}"
    expected_params = {"api-version": "2016-03-01"}

    client.http_request.assert_called_once_with(method="GET", full_url=expected_url, params=expected_params)

    # Verify the result matches the mock response
    assert result == mock_response


def test_get_monitor_log_profile_error_handling(mocker, client):
    """
    Given: An Azure client and arguments for getting a monitor log profile.
    When: The get_monitor_log_profile method is called and an exception occurs.
    Then: The method should call handle_azure_error with appropriate parameters.
    """
    # Mock arguments
    subscription_id = "12345678-1234-1234-1234-123456789012"
    log_profile_name = "test-log-profile"

    # Mock exception
    mock_exception = Exception("404 Not Found")

    # Mock the client's methods
    mocker.patch.object(client, "http_request", side_effect=mock_exception)
    mocker.patch.object(client, "handle_azure_error", side_effect=ValueError("Monitor Log Profile not found"))

    # Call the method and expect it to raise an exception
    with pytest.raises(ValueError, match="Monitor Log Profile not found"):
        client.get_monitor_log_profile(subscription_id=subscription_id, log_profile_name=log_profile_name)

    # Verify handle_azure_error was called with correct parameters
    client.handle_azure_error.assert_called_once_with(
        e=mock_exception,
        resource_name=log_profile_name,
        api_function_name="get_monitor_log_profile",
        resource_type="Monitor Log Profile",
        subscription_id=subscription_id,
        resource_group_name=None,
    )


def test_format_rule():
    """
    Given: rule data and rule name
    Then: Command outputs is returned as expected and flattens the `properties` field.

    """
    from Azure import format_rule

    rule = util_load_json("test_data/get_rule_response.json")
    cr = format_rule(rule_json=rule, security_rule_name="RuleName")
    assert cr.raw_response["name"] == "wow"
    assert cr.raw_response["sourceAddressPrefix"] == "3.2.3.2"
    assert "### Rules RuleName" in cr.readable_output


def test_nsg_public_ip_addresses_list_command(mocker):
    """
    Given: An Azure client mock and the list_public_ip_addresses_response.json file.
    When: nsg_public_ip_addresses_list_command is called
          1. With a limit of 2 (all_results=False).
          2. With all_results=True.
    Then:
          1. It should return only 2 results when limited.
          2. It should return all results when all_results=True.
          3. The results should contain expected fields such as name, id, fqdn.
          4. The etag field should be cleaned up (first 3 chars and last char removed).
    """
    from Azure import nsg_public_ip_addresses_list_command

    mock_response = util_load_json("test_data/list_public_ip_addresses_response.json")

    mock_client = mocker.Mock()
    mock_client.list_public_ip_addresses_request.return_value = mock_response

    params = {"subscription_id": "subid", "resource_group_name": "rg1"}

    args = {"limit": "2", "all_results": "false"}
    result: CommandResults = nsg_public_ip_addresses_list_command(mock_client, params, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.NSGPublicIPAddress"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 2
    assert "name" in result.outputs[0]
    assert "id" in result.outputs[0]

    # "123etag3" should become "etag" after [3:-1]
    first_item_with_etag = result.outputs[0]  # First item has etag "123etag3"
    if first_item_with_etag.get("etag"):
        assert first_item_with_etag.get("etag") == "etag"

    args = {"all_results": "true"}
    result_all: CommandResults = nsg_public_ip_addresses_list_command(mock_client, params, args)

    assert isinstance(result_all, CommandResults)
    assert len(result_all.outputs) == len(mock_response["value"])  # Should be 3 items

    fqdn_values = [
        out.get("properties", {}).get("dnsSettings", {}).get("fqdn")
        for out in result_all.outputs
        if out.get("properties", {}).get("dnsSettings", {}).get("fqdn")
    ]

    assert len(fqdn_values) == 2
    assert "testlbl.westus.cloudapp.azure.com" in fqdn_values
    assert "testlbl.hxdwgjcdfgbhgebs.eastus.sysgen.cloudapp.azure.com" in fqdn_values

    # Check readable_output is generated
    assert result_all.readable_output
    assert "Public IP Addresses List" in result_all.readable_output


def test_nsg_network_interfaces_list_command(mocker):
    """
    Given: An Azure client mock and the list_networks_interfaces_response.json file.
    When: nsg_network_interfaces_list_command is called
          1. With a limit of 1 (all_results=False).
          2. With all_results=True.
    Then:
          1. It should return only 1 result when limited.
          2. It should return all results when all_results=True.
          3. The results should contain expected fields such as name, id.
          4. The etag field should be cleaned up (first 3 chars and last char removed).
    """
    from Azure import nsg_network_interfaces_list_command

    mock_response = util_load_json("test_data/list_networks_interfaces_response.json")

    mock_client = mocker.Mock()
    mock_client.list_networks_interfaces_request.return_value = mock_response

    params = {"subscription_id": "subid", "resource_group_name": "rg1"}

    # --- Case 1: with limit=1 ---
    args = {"limit": "1", "all_results": "false"}
    result: CommandResults = nsg_network_interfaces_list_command(mock_client, params, args)

    assert result.outputs_prefix == "Azure.NSGNetworkInterfaces"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1
    first = result.outputs[0]

    assert first["name"] == "test-nic"
    assert first["id"] == "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/test-nic"

    # --- Case 2: with all_results=True ---
    args = {"all_results": "true"}
    result_all: CommandResults = nsg_network_interfaces_list_command(mock_client, params, args)

    assert isinstance(result_all, CommandResults)
    assert len(result_all.outputs) == len(mock_response["value"])  # Should be 2 items
    assert len(result_all.outputs) == 2

    names = [item["name"] for item in result_all.outputs]
    assert "test-nic" in names
    assert "test-nic2" in names

    for item in result_all.outputs:
        if item.get("etag"):
            assert item["etag"] == "etag"

    assert result_all.readable_output
    assert "Network Interfaces List" in result_all.readable_output


def test_nsg_resource_group_list_command(mocker):
    """
    Given: An Azure client mock and the list_resource_groups_response.json file.
    When: nsg_resource_group_list_command is called
          1. With a limit of 1.
          2. Without limit (default).
    Then:
          1. It should respect the limit argument.
          2. It should return the resource group data with expected fields.
          3. It should generate proper readable output.
    """
    from Azure import nsg_resource_group_list_command

    mock_response = util_load_json("test_data/list_resource_groups_response.json")

    mock_client = mocker.Mock()
    mock_client.list_resource_groups_request.return_value = mock_response

    params = {"subscription_id": "subscription1"}

    # --- Case 1: with limit=1 ---
    args = {"limit": "1"}
    result: CommandResults = nsg_resource_group_list_command(mock_client, params, args)

    # Check that client method was called with correct parameters including limit
    mock_client.list_resource_groups_request.assert_called_with(subscription_id="subscription1", filter_by_tag="", limit="1")

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.NSGResourceGroup"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 1

    first = result.outputs[0]
    assert first["name"] == "resourceGroup1"
    assert first["location"] == "centralus"
    assert "tags" in first
    assert "properties" in first
    assert first["properties"]["provisioningState"] == "Succeeded"

    # Check readable_output is generated
    assert result.readable_output
    assert "Resource Groups List" in result.readable_output

    # --- Case 2: no limit (default) ---
    args = {}
    result_default: CommandResults = nsg_resource_group_list_command(mock_client, params, args)

    assert isinstance(result_default, CommandResults)
    assert len(result_default.outputs) == 1
    assert result_default.outputs[0]["id"] == "/subscriptions/subscription1/resourceGroups/resourceGroup1"


def test_nsg_security_rule_create_command(mocker):
    """
    Given: An Azure client mock and arguments for creating a security rule.
    When: nsg_security_rule_create_command is called.
    Then:
        1. It should call create_or_update_rule with correct properties.
        2. The returned CommandResults should include the created rule data.
        3. The etag should be cleaned up.
        4. Readable output should be generated.
    """
    from Azure import nsg_security_rule_create_command

    mock_response = util_load_json("test_data/create_or_update_rule_response.json")

    mock_client = mocker.Mock()
    mock_client.create_or_update_rule.return_value = mock_response

    params = {"subscription_id": "subid", "resource_group_name": "rg1"}
    args = {
        "security_group_name": "testnsg",
        "security_rule_name": "rule1",
        "action": "Deny",
        "direction": "Outbound",
        "priority": 100,
        "protocol": "Any",
        "source": "10.0.0.0/8",
        "destination": "11.0.0.0/8",
        "destination_ports": "8080",
    }

    result: CommandResults = nsg_security_rule_create_command(mock_client, params, args)

    # --- Check the properties passed to create_or_update_rule ---
    expected_properties = {
        "protocol": "*",
        "access": "Deny",
        "priority": 100,
        "direction": "Outbound",
        "sourcePortRange": "*",
        "destinationPortRange": "8080",
        "sourceAddressPrefix": "10.0.0.0/8",
        "destinationAddressPrefix": "11.0.0.0/8",
    }

    mock_client.create_or_update_rule.assert_called_once_with(
        security_group="testnsg",
        rule_name="rule1",
        properties=expected_properties,
        subscription_id="subid",
        resource_group_name="rg1",
    )

    # --- Check the returned CommandResults ---
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.NSGRule"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "rule1"

    # Check that etag is cleaned up
    if result.outputs.get("etag"):
        assert result.outputs.get("etag") == "etag"

    # Check readable_output is generated
    assert result.readable_output
    assert f"The security rule {args['security_rule_name']} was created successfully" in result.readable_output


def test_nsg_security_rule_get_command(mocker):
    """
    Given: An Azure client mock and a security rule JSON.
    When: nsg_security_rule_get_command is called.
    Then:
        1. It should call client.get_rule with correct arguments.
        2. The returned CommandResults should contain the rule data.
        3. The etag should be cleaned up.
        4. Readable output should be generated.
    """
    from Azure import nsg_security_rule_get_command

    mock_rule = util_load_json("test_data/get_rule_response.json")

    mock_client = mocker.Mock()
    mock_client.get_rule.return_value = mock_rule

    params = {"subscription_id": "subid", "resource_group_name": "rg1"}
    args = {"security_group_name": "testnsg", "security_rule_name": "wow"}

    result: CommandResults = nsg_security_rule_get_command(mock_client, params, args)

    # Check that get_rule was called correctly
    mock_client.get_rule.assert_called_once_with(
        security_group="testnsg",
        rule_name="wow",
        subscription_id="subid",
        resource_group_name="rg1",
    )

    # Check the returned CommandResults
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.NSGRule"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_rule

    # Check that etag is cleaned up
    if result.outputs.get("etag"):
        assert result.outputs["etag"] == "etag"

    # Check readable_output is generated
    assert result.readable_output
    assert f"Rule {args['security_rule_name']}" in result.readable_output


def test_nsg_security_groups_list_command(mocker):
    """
    Given: An Azure client mock and the list_network_security_groups_response.json file.
    When: nsg_security_groups_list_command is called.
    Then:
        1. It should call client.list_network_security_groups with correct parameters.
        2. The etag fields should be cleaned up for both groups and default security rules.
        3. The CommandResults should have correct outputs and readable_output.
    """
    from Azure import nsg_security_groups_list_command

    mock_response = util_load_json("test_data/list_network_security_groups_response.json")

    mock_client = mocker.Mock()
    mock_client.list_network_security_groups.return_value = mock_response

    params = {"subscription_id": "subid", "resource_group_name": "rg1"}
    args = {}

    result: CommandResults = nsg_security_groups_list_command(mock_client, params, args)

    mock_client.list_network_security_groups.assert_called_once_with(subscription_id="subid", resource_group_name="rg1")

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.NSGSecurityGroup"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == len(mock_response["value"])

    # Check that etag fields are cleaned up
    for group in result.outputs:
        if group.get("etag"):
            assert group["etag"] == "etag"
        for rule in group.get("defaultSecurityRules", []):
            if rule.get("etag"):
                assert rule["etag"] == "etag"

        assert "name" in group
        assert "id" in group
        assert "location" in group

    # Check readable_output is generated
    assert result.readable_output
    assert "Network Security Groups" in result.readable_output

    # The readable_output should contain the NSG names
    for group in result.outputs:
        assert group["name"] in result.readable_output


def test_nsg_security_rule_delete_command(mocker):
    """
    Given: An Azure client mock and various scenarios.
    When: nsg_security_rule_delete_command is called.
    Then:
        1. It should call client.delete_rule with correct arguments for valid inputs.
        2. It should return appropriate messages based on status codes (200=success, 202=async, 204=not found).
        3. It should call return_error when required parameters are missing or empty.
    """
    from Azure import nsg_security_rule_delete_command

    mock_client = mocker.Mock()
    params = {"subscription_id": "subid", "resource_group_name": "rg1"}

    mock_response = mocker.Mock()
    mock_response.status_code = 202
    mock_client.delete_rule.return_value = mock_response

    args = {"security_group_name": "testnsg", "security_rule_name": "testrule"}
    result = nsg_security_rule_delete_command(mock_client, params, args)

    mock_client.delete_rule.assert_called_with(
        security_group_name="testnsg",
        security_rule_name="testrule",
        subscription_id="subid",
        resource_group_name="rg1",
    )
    assert isinstance(result, CommandResults)
    assert "was accepted and the operation will complete asynchronously" in result.readable_output

    mock_response.status_code = 200
    result = nsg_security_rule_delete_command(mock_client, params, args)
    assert "was successfully deleted" in result.readable_output

    mock_response.status_code = 204
    result = nsg_security_rule_delete_command(mock_client, params, args)
    assert "was not found" in result.readable_output


def test_get_permissions_from_api_function_name(mocker):
    """
    Given: An API function name and an error message.
    When: get_permissions_from_api_function_name is called.
    Then:
          1. It should return the matching permission found in the error message.
          2. It should return None if no permission is found in the error message.
          3. It should be case-insensitive when matching.
          4. Multiple permissions in function, return all matched permissions.
    """
    from Azure import get_permissions_from_api_function_name

    # Test case 1: Permission found in error message
    api_function_name = "list_networks_interfaces_request"
    error_msg = "Access denied. Missing permission: Microsoft.Network/networkInterfaces/read"
    result = get_permissions_from_api_function_name(api_function_name, error_msg)
    assert result == ["Microsoft.Network/networkInterfaces/read"]

    # Test case 2: Case-insensitive matching
    error_msg_upper = "Access denied. Missing permission: MICROSOFT.NETWORK/NETWORKINTERFACES/READ"
    result = get_permissions_from_api_function_name(api_function_name, error_msg_upper)
    assert result == ["Microsoft.Network/networkInterfaces/read"]

    # Test case 3: No permission found in error message
    error_msg_no_match = "Some unrelated error message"
    result = get_permissions_from_api_function_name(api_function_name, error_msg_no_match)
    assert result == []

    # Test case 4: Multiple permissions in function, return all matched permissions
    api_function_name_multi = "acr_update"  # Has both read and write permissions
    error_msg_write = (
        "Missing Microsoft.ContainerRegistry/registries/read, Microsoft.ContainerRegistry/registries/write permissions"
    )
    result = get_permissions_from_api_function_name(api_function_name_multi, error_msg_write)
    assert result == ["Microsoft.ContainerRegistry/registries/read", "Microsoft.ContainerRegistry/registries/write"]


def test_get_permissions_from_required_role_permissions_list(mocker):
    """
    Given: An error message.
    When: get_permissions_from_required_role_permissions_list is called.
    Then:
          1. It should return the first matching permission found in the error message.
          2. It should return None if no permission is found in the error message.
          3. It should be case-insensitive when matching.
          4. It should search through all required role permissions.
    """
    from Azure import get_permissions_from_required_role_permissions_list

    # Test case 1: Permission found in error message
    error_msg = "Access denied. Missing permission: Microsoft.Network/networkSecurityGroups/read"
    result = get_permissions_from_required_role_permissions_list(error_msg)
    assert result == ["Microsoft.Network/networkSecurityGroups/read"]

    # Test case 2: Case-insensitive matching
    error_msg_mixed_case = "Access denied. Missing permission: microsoft.network/networksecuritygroups/READ"
    result = get_permissions_from_required_role_permissions_list(error_msg_mixed_case)
    assert result == ["Microsoft.Network/networkSecurityGroups/read"]

    # Test case 3: No permission found in error message
    error_msg_no_match = "Some completely unrelated error message without permissions"
    result = get_permissions_from_required_role_permissions_list(error_msg_no_match)
    assert result == ["N/A"]

    # Test case 4: Empty error message
    error_msg_empty = ""
    result = get_permissions_from_required_role_permissions_list(error_msg_empty)
    assert result == ["N/A"]


def test_handle_azure_error_forbidden_text_match(mocker, client):
    """
    Given: An Azure client and an error containing "forbidden" text.
    When: The handle_azure_error method is called.
    Then: The function should trigger permission error handling.
    """
    mock_get_permissions_from_api = mocker.patch(
        "Azure.get_permissions_from_api_function_name", return_value=["Microsoft.ContainerRegistry/registries/read"]
    )
    mock_get_permissions_from_required = mocker.patch("Azure.get_permissions_from_required_role_permissions_list")
    mock_return_multiple_permissions_error = mocker.patch("Azure.return_multiple_permissions_error")

    error = Exception("Access forbidden - insufficient privileges")
    resource_name = "test"
    resource_type = "test resource"
    subscription_id = "test-sub"

    client.handle_azure_error(
        e=error,
        resource_name=resource_name,
        resource_type=resource_type,
        api_function_name="acr_update",
        subscription_id=subscription_id,
    )

    mock_get_permissions_from_api.assert_called_once_with("acr_update", "access forbidden - insufficient privileges")
    mock_get_permissions_from_required.assert_not_called()

    expected_error_entries = [
        {
            "account_id": "test-sub",
            "message": "access forbidden - insufficient privileges",
            "name": "Microsoft.ContainerRegistry/registries/read",
        }
    ]
    mock_return_multiple_permissions_error.assert_called_once_with(expected_error_entries)


def test_handle_azure_error_permission_error_no_permissions_found(mocker, client):
    """
    Given: An Azure client and a permission error where no permissions are found.
    When: The handle_azure_error method is called.
    Then: The function should call return_multiple_permissions_error with empty list.
    """
    mock_get_permissions_from_api = mocker.patch("Azure.get_permissions_from_api_function_name", return_value=None)
    mock_get_permissions_from_required = mocker.patch(
        "Azure.get_permissions_from_required_role_permissions_list", return_value=["N/A"]
    )
    mock_return_multiple_permissions_error = mocker.patch("Azure.return_multiple_permissions_error")

    error = Exception("403 Forbidden")
    resource_name = "test-resource"
    resource_type = "Unknown Resource"

    client.handle_azure_error(
        e=error,
        resource_name=resource_name,
        resource_type=resource_type,
        api_function_name="unknown_function",
    )

    mock_get_permissions_from_api.assert_not_called()
    mock_get_permissions_from_required.assert_called_once()
    mock_return_multiple_permissions_error.assert_called_once_with(
        [{"account_id": None, "message": str(error).lower(), "name": "N/A"}]
    )


def test_handle_azure_error_permission_error_multiple_permissions(mocker, client):
    """
    Given: An Azure client and a permission error with multiple permissions found.
    When: The handle_azure_error method is called.
    Then: The function should call return_multiple_permissions_error with all permissions.
    """
    mock_return_multiple_permissions_error = mocker.patch("Azure.return_multiple_permissions_error")

    error = Exception("401 Unauthorized missing Microsoft.Storage/storageAccounts/read")
    resource_name = "test-storage"
    resource_type = "Storage Account"
    subscription_id = "sub-123"
    resource_group_name = "rg-test"

    client.handle_azure_error(
        e=error,
        resource_name=resource_name,
        resource_type=resource_type,
        api_function_name="storage_account_update_request",
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
    )

    expected_error_entries = [
        {
            "account_id": "sub-123",
            "message": "401 unauthorized missing microsoft.storage/storageaccounts/read",
            "name": "Microsoft.Storage/storageAccounts/read",
        }
    ]
    mock_return_multiple_permissions_error.assert_called_once_with(expected_error_entries)


def test_storage_blob_service_properties_get_command(mocker):
    """
    Given: An Azure client mock and the get_blob_service_properties.json file.
    When: storage_blob_service_properties_get_command is called.
    Then:
        1. It should call client.storage_blob_service_properties_get_request with correct parameters.
        2. It should extract subscription_id, resource_group, and account_name from the response ID.
        3. The CommandResults should have correct outputs, readable_output, and metadata.
    """
    from Azure import storage_blob_service_properties_get_command

    mock_response = util_load_json("test_data/get_blob_service_properties.json")

    mock_client = mocker.Mock()
    mock_client.storage_blob_service_properties_get_request.return_value = mock_response

    params = {"subscription_id": "subid", "resource_group_name": "rg1"}
    args = {"account_name": "teststorage"}

    result: CommandResults = storage_blob_service_properties_get_command(mock_client, params, args)

    mock_client.storage_blob_service_properties_get_request.assert_called_once_with(
        account_name="teststorage", resource_group_name="rg1", subscription_id="subid"
    )

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.StorageBlobServiceProperties"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response
    assert result.raw_response == mock_response

    assert "Azure Storage Blob Service Properties" in result.readable_output
    assert "default" in result.readable_output
    assert "sto8607" in result.readable_output
    assert "subscription-id" in result.readable_output
    assert "res4410" in result.readable_output
    assert "true" in result.readable_output.lower()

    expected_headers = [
        "Name",
        "Account Name",
        "Subscription ID",
        "Resource Group",
        "Change Feed",
        "Delete Retention Policy",
        "Versioning",
    ]
    for header in expected_headers:
        assert header in result.readable_output


def test_storage_blob_containers_update_command(mocker):
    """
    Given: An Azure client mock and the update_blob_container.json file.
    When: storage_blob_containers_update_command is called.
    Then:
        1. It should call client.storage_blob_containers_create_update_request with correct parameters and PATCH method.
        2. It should extract subscription_id, resource_group, and account_name from the response ID.
        3. The CommandResults should have correct outputs, readable_output, and metadata.
    """
    from Azure import storage_blob_containers_update_command

    mock_response = util_load_json("test_data/update_blob_container.json")

    mock_client = mocker.Mock()
    mock_client.storage_blob_containers_create_update_request.return_value = mock_response

    params = {"subscription_id": "subid", "resource_group_name": "rg1"}
    args = {"account_name": "teststorage", "container_name": "testcontainer"}

    result: CommandResults = storage_blob_containers_update_command(mock_client, params, args)

    mock_client.storage_blob_containers_create_update_request.assert_called_once_with(
        subscription_id="subid", resource_group_name="rg1", args=args, method="PATCH"
    )

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.StorageBlobContainer"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response
    assert result.raw_response == mock_response

    assert "Azure Storage Blob Containers Properties" in result.readable_output
    assert "container6185" in result.readable_output
    assert "sto328" in result.readable_output
    assert "subscription-id" in result.readable_output
    assert "res3376" in result.readable_output
    assert "Container" in result.readable_output

    expected_headers = ["Name", "Account Name", "Subscription ID", "Resource Group", "Public Access"]
    for header in expected_headers:
        assert header in result.readable_output


def test_extract_azure_resource_info():
    """
    Given: Various Azure resource ID formats.
    When: The extract_azure_resource_info function is called.
    Then: The function should correctly extract subscription_id, resource_group, and account_name components.
    """

    # Test case 1: Complete Azure storage blob service resource ID
    resource_id = "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage/blobServices/default"  # noqa: E501
    subscription_id, resource_group, account_name = extract_azure_resource_info(resource_id)
    assert subscription_id == "12345678-1234-1234-1234-123456789012"
    assert resource_group == "test-rg"
    assert account_name == "teststorage"

    # Test case 2: Partial resource ID (only subscription and resource group)
    resource_id = "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/test-rg/providers/Microsoft.Compute/virtualMachines/test-vm"  # noqa: E501
    subscription_id, resource_group, account_name = extract_azure_resource_info(resource_id)
    assert subscription_id == "12345678-1234-1234-1234-123456789012"
    assert resource_group == "test-rg"
    assert account_name is None

    # Test case 3: Empty string
    resource_id = ""
    subscription_id, resource_group, account_name = extract_azure_resource_info(resource_id)
    assert subscription_id is None
    assert resource_group is None
    assert account_name is None

    # Test case 4: Invalid format
    resource_id = "invalid-resource-id-format"
    subscription_id, resource_group, account_name = extract_azure_resource_info(resource_id)
    assert subscription_id is None
    assert resource_group is None
    assert account_name is None

    # Test case 5: Only subscription information
    resource_id = "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups"
    subscription_id, resource_group, account_name = extract_azure_resource_info(resource_id)
    assert subscription_id == "12345678-1234-1234-1234-123456789012"
    assert resource_group is None
    assert account_name is None

    # Test case 6: Complex names with hyphens and underscores
    resource_id = "/subscriptions/abcd-efgh-1234-5678-ijkl/resourceGroups/my-resource-group_v2/providers/Microsoft.Storage/storageAccounts/my_storage_account123/blobServices/default"  # noqa: E501
    subscription_id, resource_group, account_name = extract_azure_resource_info(resource_id)
    assert subscription_id == "abcd-efgh-1234-5678-ijkl"
    assert resource_group == "my-resource-group_v2"
    assert account_name == "my_storage_account123"

    # Test case 7: Storage account without blob services suffix
    resource_id = "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage"  # noqa: E501
    subscription_id, resource_group, account_name = extract_azure_resource_info(resource_id)
    assert subscription_id == "12345678-1234-1234-1234-123456789012"
    assert resource_group == "test-rg"
    assert account_name is None


def test_start_vm_command(mocker):
    """
    Given: A subscription, resource group, and VM name.
    When: start_vm_command is called with these parameters.
    Then: It should call validate_provisioning_state and start_vm_request,
          and return correct CommandResults with VM starting state.
    """
    from Azure import start_vm_command

    mock_client = mocker.Mock()
    params = {"subscription_id": "sub-id", "resource_group_name": "rg1"}
    args = {"subscription_id": "sub-id", "resource_group_name": "rg1", "virtual_machine_name": "vm1"}

    result = start_vm_command(mock_client, params, args)

    mock_client.validate_provisioning_state.assert_called_once_with("sub-id", "rg1", "vm1")
    mock_client.start_vm_request.assert_called_once_with("sub-id", "rg1", "vm1")

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.Compute"
    assert result.outputs_key_field == "name"
    assert result.outputs["name"] == "vm1"
    assert result.outputs["resourceGroup"] == "rg1"
    assert result.outputs["powerState"] == "VM starting"
    assert "vm1" in result.readable_output


def test_poweroff_vm_command(mocker):
    """
    Given: A subscription, resource group, VM name, and optional skip_shutdown.
    When: poweroff_vm_command is called.
    Then: It should call validate_provisioning_state and poweroff_vm_request,
          and return correct CommandResults with VM stopping state.
    """
    from Azure import poweroff_vm_command

    mock_client = mocker.Mock()
    params = {"subscription_id": "sub-id", "resource_group_name": "rg1"}
    args = {"subscription_id": "sub-id", "resource_group_name": "rg1", "virtual_machine_name": "vm1", "skip_shutdown": True}

    result = poweroff_vm_command(mock_client, params, args)

    mock_client.validate_provisioning_state.assert_called_once_with("sub-id", "rg1", "vm1")
    mock_client.poweroff_vm_request.assert_called_once_with("sub-id", "rg1", "vm1", True)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.Compute"
    assert result.outputs_key_field == "name"
    assert result.outputs["name"] == "vm1"
    assert result.outputs["resourceGroup"] == "rg1"
    assert result.outputs["powerState"] == "VM stopping"
    assert "vm1" in result.readable_output


def test_get_vm_command(mocker):
    """
    Given: A subscription, resource group, and VM name.
    When: get_vm_command is called.
    Then: It should call get_vm_request and return correct CommandResults
          including OS, size, power state, and network interfaces.
    """
    from Azure import get_vm_command

    mock_client = mocker.Mock()
    params = {"subscription_id": "sub-id", "resource_group_name": "rg1"}
    args = {"subscription_id": "sub-id", "resource_group_name": "rg1", "virtual_machine_name": "vm1", "expand": ""}

    mock_response = {
        "location": "eastus",
        "tags": {"env": "prod"},
        "properties": {
            "vmId": "vm123",
            "provisioningState": "Succeeded",
            "storageProfile": {"osDisk": {"diskSizeGB": 128, "osType": "Linux"}},
            "instanceView": {"statuses": [{"code": "PowerState/running", "displayStatus": "VM running"}]},
            "networkProfile": {"networkInterfaces": [{"id": "nic1"}]},
            "userData": "userdata",
        },
    }

    mocker.patch.object(mock_client, "get_vm_request", return_value=mock_response)

    result = get_vm_command(mock_client, params, args)

    mock_client.get_vm_request.assert_called_once_with("sub-id", "rg1", "vm1", expand="")

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.Compute"
    assert result.outputs_key_field == "name"
    assert result.outputs["properties"]["vmId"] == "vm123"
    assert result.outputs["properties"]["provisioningState"] == "Succeeded"
    assert result.outputs["properties"]["storageProfile"]["osDisk"]["osType"] == "Linux"
    assert result.outputs["properties"]["instanceView"]["statuses"][0]["displayStatus"] == "VM running"
    assert "vm1" in result.readable_output


def test_get_network_interface_command(mocker):
    """
    Given: A subscription, resource group, and network interface name.
    When: get_network_interface_command is called with these parameters.
    Then: It should call get_network_interface_request and return correct CommandResults
          with properly formatted network interface details.
    """
    from Azure import get_network_interface_command

    mock_client = mocker.Mock()
    mock_params = {"subscription_id": "sub-id", "resource_group_name": "rg1"}
    args = {"subscription_id": "sub-id", "resource_group_name": "rg1", "network_interface_name": "nic1"}

    mock_response = {
        "id": "/subscriptions/sub-id/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/nic1",
        "name": "nic1",
        "location": "eastus",
        "properties": {
            "macAddress": "00:11:22:33:44:55",
            "primary": True,
            "networkSecurityGroup": {"id": "nsg-id"},
            "nicType": "Standard",
            "virtualMachine": {"id": "vm-id"},
            "dnsSettings": {"internalDomainNameSuffix": "internal.local"},
            "ipConfigurations": [
                {
                    "name": "ipconfig1",
                    "id": "ipconfig-id",
                    "properties": {"privateIPAddress": "10.0.0.4", "publicIPAddress": {"id": "public-ip-id"}},
                    "etag": 'W/"12345"',
                }
            ],
        },
    }

    mocker.patch.object(mock_client, "get_network_interface_request", return_value=mock_response)

    result = get_network_interface_command(mock_client, mock_params, args)

    mock_client.get_network_interface_request.assert_called_once_with("sub-id", "rg1", "nic1")

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.Network.Interfaces"
    assert result.outputs_key_field == "name"
    assert result.outputs["name"] == "nic1"
    assert result.outputs["properties"]["macAddress"] == "00:11:22:33:44:55"
    assert result.outputs["properties"]["ipConfigurations"][0]["properties"]["privateIPAddress"] == "10.0.0.4"
    assert result.outputs["properties"]["ipConfigurations"][0]["properties"]["publicIPAddress"]["id"] == "public-ip-id"
    assert result.outputs["properties"]["ipConfigurations"][0]["etag"] == "12345"  # etag cleaned
    assert "nic1" in result.readable_output


def test_get_single_ip_details_from_list_of_ip_details():
    """
    Given: A subscription, resource group, and public IP name.
    When: get_public_ip_details_command is called with these parameters.
    Then: It should call get_public_ip_details_request and return correct CommandResults.
    """
    from Azure import get_single_ip_details_from_list_of_ip_details

    list_of_ips = [
        {"properties": {"ipAddress": "1.1.1.1"}},
        {"properties": {"ipAddress": "2.2.2.2"}},
        {"properties": {"nested": {"ipAddress": "3.3.3.3"}}},
    ]

    ip1 = get_single_ip_details_from_list_of_ip_details(list_of_ips, "1.1.1.1")
    ip3 = get_single_ip_details_from_list_of_ip_details(list_of_ips, "3.3.3.3")
    ip_missing = get_single_ip_details_from_list_of_ip_details(list_of_ips, "4.4.4.4")

    assert ip1 == {"properties": {"ipAddress": "1.1.1.1"}}
    assert ip3 == {"properties": {"nested": {"ipAddress": "3.3.3.3"}}}
    assert ip_missing is None


def test_get_public_ip_details_command_with_resource_group(mocker):
    """
    Given: A subscription, resource group, and public IP name.
    When: get_public_ip_details_command is called with these parameters.
    Then: It should call get_public_ip_details_request and return correct CommandResults.
    """
    from Azure import get_public_ip_details_command

    mock_client = mocker.Mock()
    mock_params = {"subscription_id": "sub-id", "resource_group_name": "rg1"}
    args = {"subscription_id": "sub-id", "resource_group_name": "rg1", "address_name": "ip1"}

    mock_response = {
        "id": "/subscriptions/sub-id/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/ip1",
        "name": "ip1",
        "location": "eastus",
        "etag": 'W/"12345"',
        "properties": {
            "ipAddress": "1.2.3.4",
            "publicIPAddressVersion": "IPv4",
            "publicIPAllocationMethod": "Static",
            "ipConfiguration": {"id": "config-id"},
            "dnsSettings": {"domainNameLabel": "label1", "fqdn": "ip1.eastus.cloudapp.azure.com"},
        },
    }

    mocker.patch.object(mock_client, "get_public_ip_details_request", return_value=mock_response)

    result = get_public_ip_details_command(mock_client, mock_params, args)

    mock_client.get_public_ip_details_request.assert_called_once_with("sub-id", "rg1", "ip1")

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Azure.Network.IPConfigurations"
    assert result.outputs_key_field == "id"
    assert result.outputs["properties"]["ipAddress"] == "1.2.3.4"
    assert result.outputs["properties"]["publicIPAddressVersion"] == "IPv4"
    assert result.outputs["properties"]["publicIPAllocationMethod"] == "Static"
    assert result.outputs["etag"] == "12345"
    assert "ip1" in result.readable_output


def test_get_public_ip_details_command_without_resource_group(mocker):
    """
    Given: A subscription and public IP name, but no resource group.
    When: get_public_ip_details_command is called.
    Then: It should call get_all_public_ip_details_request, find the matching IP, and return details.
    """
    from Azure import get_public_ip_details_command

    mock_client = mocker.Mock()
    mock_params = {"subscription_id": "sub-id"}
    args = {"subscription_id": "sub-id", "address_name": "ip1"}

    mock_all_ips = {
        "value": [
            {
                "id": "/subscriptions/sub-id/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/ip1",
                "name": "ip1",
                "location": "eastus",
                "etag": 'W/"999"',
                "properties": {
                    "ipAddress": "5.6.7.8",
                    "publicIPAddressVersion": "IPv4",
                    "publicIPAllocationMethod": "Dynamic",
                },
            },
            {
                "id": "/subscriptions/sub-id/resourceGroups/rg2/providers/Microsoft.Network/publicIPAddresses/ip2",
                "name": "ip2",
                "location": "westus",
                "etag": 'W/"888"',
                "properties": {
                    "ipAddress": "9.9.9.9",
                    "publicIPAddressVersion": "IPv6",
                    "publicIPAllocationMethod": "Static",
                },
            },
        ]
    }

    # Mock the client and helper functions
    mocker.patch.object(mock_client, "get_all_public_ip_details_request", return_value=mock_all_ips)
    mocker.patch("Azure.get_single_ip_details_from_list_of_ip_details", return_value=mock_all_ips["value"][0])

    result = get_public_ip_details_command(mock_client, mock_params, args)

    mock_client.get_all_public_ip_details_request.assert_called_once_with("sub-id")

    assert isinstance(result, CommandResults)
    assert result.outputs["properties"]["ipAddress"] == "5.6.7.8"
    assert result.outputs["etag"] == "999"
    assert "ip1" in result.readable_output
    assert "rg1" in result.readable_output


def test_azure_billing_usage_list_command_success(mocker, client, mock_params):
    """
    Given: An Azure client and valid billing usage arguments.
    When: azure_billing_usage_list_command is called successfully.
    Then: It should return CommandResults with usage data and proper outputs.
    """
    from Azure import azure_billing_usage_list_command

    mock_response = {
        "value": [
            {
                "name": "usage-item-1",
                "properties": {
                    "product": "Virtual Machines",
                    "meterName": "D2s v3",
                    "paygCost": {"amount": 125.75},
                    "quantity": 24.5,
                    "billingPeriodStartDate": "2025-10-01T00:00:00.0000000Z",
                    "billingPeriodEndDate": "2025-10-01T23:59:59.0000000Z",
                },
            }
        ],
        "nextLink": "https://management.azure.com/subscriptions/test/providers/Microsoft.Consumption/usageDetails?$skiptoken=abc123",
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    args = {"subscription_id": "test-subscription-id", "max_results": "50", "filter": "properties/usageStart ge '2023-10-01'"}
    params = mock_params

    result = azure_billing_usage_list_command(client, params, args)

    assert isinstance(result, CommandResults)
    assert "Azure Billing Usage" in result.readable_output
    assert "Azure.Billing.Usage(val.name && val.name == obj.name)" in result.outputs
    assert "Azure.Billing(true)" in result.outputs
    assert (
        "https://management.azure.com/subscriptions/test/providers/Microsoft.Consumption/usageDetails?$skiptoken=abc123"
        in result.outputs["Azure.Billing(true)"]["UsageNextToken"]
    )
    assert len(result.outputs["Azure.Billing.Usage(val.name && val.name == obj.name)"]) == 1
    assert (
        result.outputs["Azure.Billing.Usage(val.name && val.name == obj.name)"][0]["properties"]["product"] == "Virtual Machines"
    )
    assert result.raw_response == mock_response


def test_azure_billing_forecast_list_command_success(mocker, client, mock_params):
    """
    Given: An Azure client and valid billing forecast arguments.
    When: azure_billing_forecast_list_command is called successfully.
    Then: It should return CommandResults with forecast data and proper outputs.
    """
    from Azure import azure_billing_forecast_list_command

    # The current implementation expects a table-like response under properties with columns and rows,
    # and it calls client.billing_forecast_list (not http_request) directly.
    mock_response = {
        "properties": {
            "columns": [
                {"name": "UsageDate"},
                {"name": "CostStatus"},
                {"name": "Currency"},
                {"name": "Pre Tax Cost USD"},
            ],
            "rows": [
                [20231015, "Forecast", "USD", 250.50],
            ],
        }
    }
    mocker.patch.object(client, "billing_forecast_list", return_value=mock_response)

    args = {
        "subscription_id": "test-subscription-id",
        "type": "Usage",
        "aggregation_function_name": "Pre Tax Cost USD",
        "filter": "properties/UsageDate ge '2023-10-15'",
    }
    params = mock_params

    result = azure_billing_forecast_list_command(client, params, args)

    assert isinstance(result, CommandResults)
    assert "Azure Billing Forecast" in result.readable_output

    # Validate context structure and parsed forecasts
    assert "Azure.Billing.Forecast" in result.outputs
    forecast_ctx = result.outputs["Azure.Billing.Forecast"]
    assert isinstance(forecast_ctx, list)
    assert len(forecast_ctx) == 1

    row = forecast_ctx[0]
    # The command uses aggregation_function_name as a key in the result rows
    assert row["Pre Tax Cost USD"] == 250.50
    assert row["CostStatus"] == "Forecast"
    assert row["Currency"] == "USD"
    # UsageDate should be formatted as YYYY-MM-DD from 20231015
    assert row["UsageDate"] == "2023-10-15"

    # Raw response should be the original mock response
    assert result.raw_response == mock_response


def test_azure_billing_budgets_list_command_success(mocker, client, mock_params):
    """
    Given: An Azure client and valid billing budgets arguments.
    When: azure_billing_budgets_list_command is called successfully.
    Then: It should return CommandResults with budget data and proper outputs.
    """
    from Azure import azure_billing_budgets_list_command

    mock_response = {
        "value": [
            {
                "name": "test-budget",
                "type": "Microsoft.Consumption/budgets",
                "properties": {
                    "timePeriod": {"startDate": "2023-10-01T00:00:00Z", "endDate": "2023-10-31T23:59:59Z"},
                    "amount": 1000.0,
                    "currentSpend": {"amount": 750.25},
                },
            }
        ]
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    args = {"subscription_id": "test-subscription-id"}
    params = mock_params

    result = azure_billing_budgets_list_command(client, params, args)

    assert isinstance(result, CommandResults)
    assert "Azure Budgets" in result.readable_output
    assert "Azure.Billing.Budget" in result.outputs
    assert len(result.outputs["Azure.Billing.Budget"]) == 1
    assert result.outputs["Azure.Billing.Budget"][0]["name"] == "test-budget"
    assert result.outputs["Azure.Billing.Budget"][0]["properties"]["amount"] == 1000.0
    assert result.outputs["Azure.Billing.Budget"][0]["properties"]["currentSpend"]["amount"] == 750.25
    assert result.raw_response == mock_response


def test_azure_billing_budgets_list_command_single_budget(mocker, client, mock_params):
    """
    Given: An Azure client and arguments for retrieving a single budget by name.
    When: azure_billing_budgets_list_command is called with budget_name parameter.
    Then: It should return CommandResults with single budget data.
    """
    from Azure import azure_billing_budgets_list_command

    mock_response = {
        "name": "specific-budget",
        "type": "Microsoft.Consumption/budgets",
        "properties": {
            "timePeriod": {"startDate": "2023-11-01T00:00:00Z", "endDate": "2023-11-30T23:59:59Z"},
            "amount": 500.0,
            "currentSpend": {"amount": 200.75},
        },
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    args = {"subscription_id": "test-subscription-id", "budget_name": "specific-budget"}
    params = mock_params

    result = azure_billing_budgets_list_command(client, params, args)

    assert isinstance(result, CommandResults)
    assert "Azure Budgets" in result.readable_output
    assert "Azure.Billing.Budget" in result.outputs
    assert len(result.outputs["Azure.Billing.Budget"]) == 1
    assert result.outputs["Azure.Billing.Budget"][0]["name"] == "specific-budget"
    assert result.outputs["Azure.Billing.Budget"][0]["properties"]["amount"] == 500.0
    assert result.raw_response == mock_response


def test_azure_billing_usage_list_command_no_next_token(mocker, client, mock_params):
    """
    Given: An Azure client with response containing no next token.
    When: azure_billing_usage_list_command is called successfully.
    Then: It should return CommandResults without next token in outputs.
    """
    from Azure import azure_billing_usage_list_command

    mock_response = {
        "value": [
            {
                "name": "usage-item-2",
                "properties": {
                    "product": "Storage",
                    "paygCost": {"amount": 15.25},
                    "quantity": 100.0,
                    "billingPeriodStartDate": "2025-10-01T00:00:00.0000000Z",
                    "billingPeriodEndDate": "2025-10-02T23:59:59.0000000Z",
                },
            }
        ]
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    args = {"subscription_id": "test-subscription-id", "max_results": "10"}
    params = mock_params

    result = azure_billing_usage_list_command(client, params, args)

    assert isinstance(result, CommandResults)
    assert result.outputs["Azure.Billing(true)"]["UsageNextToken"] == ""
    assert "Next Page Token" not in result.readable_output
    assert result.outputs["Azure.Billing.Usage(val.name && val.name == obj.name)"][0]["properties"]["product"] == "Storage"


def test_azure_billing_usage_list_command_with_pagination_token(mocker, client, mock_params):
    """
    Given: An Azure client and arguments with next page token.
    When: azure_billing_usage_list_command is called with pagination token.
    Then: It should include the token in the request parameters.
    """
    from Azure import azure_billing_usage_list_command

    mock_response = {
        "value": [
            {
                "name": "usage-item-page-2",
                "properties": {
                    "product": "Networking",
                    "paygCost": {"amount": 5.50},
                    "quantity": 10.0,
                    "billingPeriodStartDate": "2025-10-04T00:00:00.0000000Z",
                    "billingPeriodEndDate": "2025-10-04T23:59:59.0000000Z",
                },
            }
        ]
    }
    mocker.patch.object(client, "http_request", return_value=mock_response)

    args = {"subscription_id": "test-subscription-id", "next_page_token": "existing-skiptoken"}
    params = mock_params

    result = azure_billing_usage_list_command(client, params, args)

    # Verify the token was passed to the client
    client.http_request.assert_called_once()
    call_args = client.http_request.call_args[1]
    assert call_args["params"].keys() == {"api-version"}

    assert isinstance(result, CommandResults)
    assert result.outputs["Azure.Billing.Usage(val.name && val.name == obj.name)"][0]["properties"]["product"] == "Networking"


def test_parse_forecast_table_to_dict_success():
    """
    Given: A table-like Azure Cost Management response with columns and rows.
    When: parse_forecast_table_to_dict is invoked.
    Then: It should return a list of dict rows mapping column names to values.
    """
    from Azure import parse_forecast_table_to_dict

    response = {
        "properties": {
            "columns": [
                {"name": "UsageDate"},
                {"name": "CostUSD"},
                {"name": "CostStatus"},
            ],
            "rows": [
                ["2025-10-01", 12.34, "Forecast"],
                ["2025-10-02", 56.78, "Actual"],
            ],
        }
    }

    parsed = parse_forecast_table_to_dict(response)
    assert isinstance(parsed, list)
    assert parsed[0]["UsageDate"] == "2025-10-01"
    assert parsed[0]["CostUSD"] == 12.34
    assert parsed[0]["CostStatus"] == "Forecast"
    assert parsed[1]["UsageDate"] == "2025-10-02"


def test_parse_forecast_table_to_dict_mismatch_row_length(mocker):
    """
    Given: Response where one row length doesn't match columns length.
    When: parse_forecast_table_to_dict runs.
    Then: It should skip the mismatched row and parse the valid one.
    """
    from Azure import parse_forecast_table_to_dict

    mocker.patch.object(demisto, "debug")

    response = {
        "properties": {
            "columns": [{"name": "A"}, {"name": "B"}],
            "rows": [
                [1],  # mismatched (len 1 vs 2 columns) -> should be skipped
                [2, 3],  # valid
            ],
        }
    }

    parsed = parse_forecast_table_to_dict(response)
    assert parsed == [{"A": 2, "B": 3}]


def test_parse_forecast_table_to_dict_malformed_raises():
    """
    Given: Malformed response (columns missing 'name').
    When: parse_forecast_table_to_dict runs.
    Then: It should raise DemistoException.
    """
    from Azure import parse_forecast_table_to_dict, DemistoException

    bad_response = {
        "properties": {
            "columns": [{"wrong": "UsageDate"}],  # will cause KeyError in parsing
            "rows": [["2025-10-01"]],
        }
    }

    with pytest.raises(DemistoException):
        parse_forecast_table_to_dict(bad_response)


def test_remove_query_param_from_url_basic():
    """
    Given: A URL with multiple query parameters including duplicates for a key.
    When: remove_query_param_from_url is used to remove that key.
    Then: The resulting URL should not contain the removed parameter and others remain.
    """
    from Azure import remove_query_param_from_url
    from urllib.parse import urlparse, parse_qs

    url = "https://example.com/path?a=1&b=2&b=3&c=x"
    out = remove_query_param_from_url(url, "b")
    parsed = urlparse(out)
    qs = parse_qs(parsed.query)
    assert "b" not in qs
    assert qs == {"a": ["1"], "c": ["x"]}


def test_remove_query_param_from_url_param_absent():
    """
    Given: A URL without the specified parameter.
    When: remove_query_param_from_url is called.
    Then: The URL query mapping remains logically the same.
    """
    from Azure import remove_query_param_from_url
    from urllib.parse import urlparse, parse_qs

    url = "https://example.com/path?a=1&c=x"
    out = remove_query_param_from_url(url, "b")
    assert parse_qs(urlparse(out).query) == {"a": ["1"], "c": ["x"]}


def test_remove_query_param_from_url_no_query():
    """
    Given: A URL without any query string.
    When: remove_query_param_from_url is called.
    Then: The URL remains unchanged.
    """
    from Azure import remove_query_param_from_url

    url = "https://example.com/path"
    out = remove_query_param_from_url(url, "b")
    assert out == url
