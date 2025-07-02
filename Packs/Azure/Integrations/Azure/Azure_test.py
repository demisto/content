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
    CommandResults,
    DemistoException,
    CloudTypes,
    SCOPE_BY_CONNECTION,
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
    mocker.patch.object(client, "create_rule", return_value=rule_response)

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
    from Azure import postgres_server_update_command

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
    Azure.get_cloud_credentials.assert_called_once_with(CloudTypes.AZURE.value, "test_subscription_id", ["DEFAULT", "GRAPH"])

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
        client.handle_azure_error(error, resource_name, resource_type, subscription_id, resource_group_name)

    assert 'Storage Account "test-resource"' in str(excinfo.value)
    assert 'subscription ID "test-subscription"' in str(excinfo.value)
    assert 'resource group "test-rg"' in str(excinfo.value)
    assert "was not found" in str(excinfo.value)


def test_azure_client_handle_azure_error_403(mocker, client):
    """
    Given: An Azure client and a 403 error.
    When: The handle_azure_error method is called.
    Then: The function should raise a DemistoException with permission error message.
    """
    # Prepare test data
    error = Exception("403 - Forbidden")
    resource_name = "test-resource"
    resource_type = "Key Vault"

    # Verify DemistoException is raised for 403 errors
    with pytest.raises(DemistoException) as excinfo:
        client.handle_azure_error(error, resource_name, resource_type)

    assert 'Insufficient permissions to access Key Vault "test-resource"' in str(excinfo.value)


def test_azure_client_handle_azure_error_401(mocker, client):
    """
    Given: An Azure client and a 401 error.
    When: The handle_azure_error method is called.
    Then: The function should raise a DemistoException with authentication error message.
    """
    # Prepare test data
    error = Exception("401 - Unauthorized")
    resource_name = "test-resource"
    resource_type = "Web App"

    # Verify DemistoException is raised for 401 errors
    with pytest.raises(DemistoException) as excinfo:
        client.handle_azure_error(error, resource_name, resource_type)

    assert 'Authentication failed when accessing Web App "test-resource"' in str(excinfo.value)


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
        client.handle_azure_error(error, resource_name, resource_type)

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
        client.handle_azure_error(error, resource_name, resource_type)

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
