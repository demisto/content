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
    When: The create_rule method is called.
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
    result = client.create_rule(
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
    When: The create_rule method is called.
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
    result = client.create_rule(
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
        client.handle_azure_error(e=error, resource_name="test-resource", resource_type="SQL Database")

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
        resource_type="Monitor Log Profile",
        subscription_id=subscription_id,
        resource_group_name=None,
    )
