import json
import demistomock as demisto
import pytest
from Azure import (
    AzureClient,
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
    test_module
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
        connection_type=mock_params.get("auth_type", "Device Code"),
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
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-sg/securityRules/test-rule",
        "properties": {
            "protocol": "Tcp",
            "sourcePortRange": "*",
            "destinationPortRange": "443",
            "sourceAddressPrefix": "Internet",
            "destinationAddressPrefix": "10.0.0.0/24",
            "access": "Allow",
            "priority": 100,
            "direction": "Inbound",
            "description": "Test rule"
        }
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
        "access": "Allow"
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
            "networkAcls": {
                "bypass": "AzureServices",
                "defaultAction": "Deny"
            },
            "allowCrossTenantReplication": False,
            "supportsHttpsTrafficOnly": True
        }
    }
    
    mock_response = mocker.MagicMock()
    mock_response.json.return_value = storage_response
    mock_response.text = json.dumps(storage_response)
    
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
        "supports_https_traffic_only": "true"
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
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage/blobServices/default",
        "properties": {
            "deleteRetentionPolicy": {
                "enabled": True,
                "days": 7
            }
        }
    }
    
    mocker.patch.object(client, "storage_blob_service_properties_set_request", return_value=properties_response)
    
    # Call the function
    args = {
        "account_name": "teststorage",
        "delete_rentention_policy_enabled": "true",
        "delete_rentention_policy_days": "7"
    }
    
    result = storage_blob_service_properties_set_command(client, mock_params, args)
    
    # Verify results
    assert result.outputs_prefix == "Azure.StorageAccount.BlobServiceProperties"
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
            "parameters": {}
        }
    }
    
    mocker.patch.object(client, "create_policy_assignment", return_value=policy_response)
    
    # Call the function
    args = {
        "name": "test-policy",
        "scope": "sub-id",
        "policy_definition_id": "/providers/Microsoft.Authorization/policyDefinitions/policy-def-id",
        "display_name": "Test Policy",
        "description": "Test policy description",
        "parameters": "{}"
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
    args = {
        "server_name": "test-postgres",
        "configuration_name": "log_checkpoints",
        "source": "user-override",
        "value": "on"
    }
    
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
        "properties": {
            "http20Enabled": True,
            "remoteDebuggingEnabled": False,
            "minTlsVersion": "1.2"
        }
    }
    
    mocker.patch.object(client, "set_webapp_config", return_value=webapp_response)
    
    # Call the function
    args = {
        "name": "test-webapp",
        "http20_enabled": "true",
        "remote_debugging_enabled": "false",
        "min_tls_version": "1.2"
    }
    
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
        "properties": {
            "enabled": False
        }
    }
    
    updated_auth = {
        "name": "authsettings",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-webapp/config/authsettings",
        "properties": {
            "enabled": True
        }
    }
    
    mocker.patch.object(client, "get_webapp_auth", return_value=current_auth)
    mocker.patch.object(client, "update_webapp_auth", return_value=updated_auth)
    
    # Call the function
    args = {
        "name": "test-webapp",
        "enabled": "true"
    }
    
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
        "value": "ON"
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
        "properties": {
            "retentionPolicy": {
                "enabled": False,
                "days": 0
                }
            }
        }
    updated_profile = {
        "name": "test-profile",
        "id": "/subscriptions/sub-id/providers/Microsoft.Insights/logprofiles/test-profile",
        "location": "westus",
        "properties": {
            "retentionPolicy": {
                "enabled": True,
                "days": 30
            }
        }
    }
    
    mocker.patch.object(client, "get_monitor_log_profile", return_value=current_profile)
    mocker.patch.object(client, "monitor_log_profile_update", return_value=updated_profile)
    
    # Call the function
    args = {
        "log_profile_name": "test-profile",
        "location": "westus",
        "subscription_id": "sub-id",
        "retention_policy_days": "30",
        "retention_policy_enabled": "true"
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
            "dataAccessAuthMode": "AzureActiveDirectory"
        }
    }
    
    mocker.patch.object(client, "disk_update", return_value=disk_response)
    
    # Call the function
    args = {
        "disk_name": "test-disk",
        "public_network_access": "Disabled",
        "network_access_policy": "DenyAll",
        "data_access_auth_mode": "AzureActiveDirectory"
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
        "identity": {
            "type": "SystemAssigned"
        },
        "properties": {
            "httpsOnly": True,
            "clientCertEnabled": True
        }
    }
    
    mocker.patch.object(client, "webapp_update", return_value=webapp_response)
    
    # Call the function
    args = {
        "name": "test-webapp",
        "identity_type": "SystemAssigned",
        "https_only": "true",
        "client_cert_enabled": "true"
    }
    
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
            "policies": {
                "exportPolicy": {
                    "status": "disabled"
                },
                "azureADAuthenticationAsArmPolicy": {
                    "status": "enabled"
                }
            }
        }
    }
    
    mocker.patch.object(client, "acr_update", return_value=acr_response)
    
    # Call the function
    args = {
        "registry_name": "testregistry",
        "allow_exports": "disabled",
        "public_network_access": "Disabled",
        "anonymous_pull_enabled": "false",
        "authentication_as_arm_policy": "enabled"
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
        "properties": {
            "sslEnforcement": "Enabled"
        }
    }
    
    mocker.patch.object(client, "postgres_server_update", return_value=postgres_response)
    
    # Call the function
    args = {
        "server_name": "test-postgres",
        "ssl_enforcement": "Enabled"
    }
    
    # This command doesn't have a return value to test, just ensure it calls the client method
    postgres_server_update_command(client, mock_params, args)
    
    # Verify the client's method was called with the correct parameters
    client.postgres_server_update.assert_called_once_with(
        mock_params.get("subscription_id"),
        mock_params.get("resource_group_name"),
        "test-postgres",
        "Enabled"
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
        "properties": {
            "enableSoftDelete": True,
            "enablePurgeProtection": True
        }
    }
    
    mocker.patch.object(client, "update_key_vault_request", return_value=keyvault_response)
    
    # Call the function
    args = {
        "vault_name": "test-keyvault",
        "enable_soft_delete": "true",
        "enable_purge_protection": "true"
    }
    
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
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-db/securityAlertPolicies/default",
        "properties": {
            "emailAccountAdmins": False
        }
    }
    
    updated_policy = {
        "name": "default",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/databases/test-db/securityAlertPolicies/default",
        "properties": {
            "emailAccountAdmins": True
        }
    }
    
    mocker.patch.object(client, "sql_db_threat_policy_get", return_value=current_policy)
    mocker.patch.object(client, "sql_db_threat_policy_update", return_value=updated_policy)
    
    # Call the function
    args = {
        "server_name": "test-server",
        "db_name": "test-db",
        "email_account_admins_enabled": "true"
    }
    
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
    
    # Mock a 404 error case where the database is not found
    not_found_message = "Database 'test-db' not found"
    mocker.patch.object(client, "sql_db_threat_policy_get", return_value=not_found_message)
    
    # Call the function
    args = {
        "server_name": "test-server",
        "db_name": "test-db",
        "email_account_admins_enabled": "true"
    }
    
    result = sql_db_threat_policy_update_command(client, mock_params, args)
    
    # Verify that it returns the error message
    assert result.readable_output == not_found_message


def test_sql_db_tde_set_command(mocker, client, mock_params):
    """
    Given: An Azure client and a request to set transparent data encryption for a SQL database.
    When: The sql_db_tde_set_command function is called with valid parameters.
    Then: The function should return a success message.
    """
    
    # Prepare mock
    mocker.patch.object(client, "sql_db_tde_set", return_value=None)
    
    # Call the function
    args = {
        "server_name": "test-server",
        "db_name": "test-db",
        "state": "Enabled"
    }
    
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
        "properties": {
            "disableKeyBasedMetadataWriteAccess": True
        }
    }
    
    mocker.patch.object(client, "cosmos_db_update", return_value=cosmos_response)
    
    # Call the function
    args = {
        "account_name": "test-cosmos",
        "disable_key_based_metadata_write_access": "true"
    }
    
    result = cosmosdb_update_command(client, mock_params, args)
    
    # Verify results
    assert result.outputs_prefix == "Azure.CosmosDB"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "test-cosmos"
    assert result.outputs["properties"]["disableKeyBasedMetadataWriteAccess"] is True


def test_test_module_with_device_code(mocker, mock_params):
    """
    Given: A configuration using Device Code authentication method.
    When: The test_module function is called.
    Then: The function should raise an exception with instructions for authentication.
    """
    
    # Create client with Device Code connection type
    device_code_params = mock_params.copy()
    device_code_params["auth_type"] = "Device Code"
    
    client = AzureClient(
        app_id=device_code_params.get("app_id", ""),
        subscription_id=device_code_params.get("subscription_id", ""),
        resource_group_name=device_code_params.get("resource_group_name", ""),
        verify=not device_code_params.get("insecure", False),
        proxy=device_code_params.get("proxy", False),
        connection_type=device_code_params.get("auth_type", "Device Code"),
        tenant_id=device_code_params.get("tenant_id"),
        enc_key=device_code_params.get("credentials", {}).get("password"),
    )
    
    # Test that it raises the expected exception
    with pytest.raises(Exception) as e:
        test_module(client)
    
    assert "Please enable the integration and run `!azure-nsg-auth-start`" in str(e.value)


def test_test_module_with_client_credentials(mocker, mock_params):
    """
    Given: A configuration using Client Credentials authentication method.
    When: The test_module function is called.
    Then: The function should return 'ok' if the authentication is successful.
    """
    
    # Create client with Client Credentials connection type
    client_credentials_params = mock_params.copy()
    client_credentials_params["auth_type"] = "Client Credentials"
    
    client = AzureClient(
        app_id=client_credentials_params.get("app_id", ""),
        subscription_id=client_credentials_params.get("subscription_id", ""),
        resource_group_name=client_credentials_params.get("resource_group_name", ""),
        verify=not client_credentials_params.get("insecure", False),
        proxy=client_credentials_params.get("proxy", False),
        connection_type=client_credentials_params.get("auth_type", "Device Code"),
        tenant_id=client_credentials_params.get("tenant_id"),
        enc_key=client_credentials_params.get("credentials", {}).get("password"),
    )
    
    # Mock the get_access_token method
    mocker.patch.object(client.ms_client, "get_access_token", return_value="test_token")
    
    # Test that it returns 'ok'
    result = test_module(client)
    assert result == "ok"


def test_test_module_with_unknown_auth_type(mocker, mock_params):
    """
    Given: A configuration using an unknown authentication method.
    When: The test_module function is called.
    Then: The function should raise an exception with appropriate message.
    """
    
    # Create client with an unknown connection type
    unknown_auth_params = mock_params.copy()
    unknown_auth_params["auth_type"] = "Unknown Auth Type"
    
    client = AzureClient(
        app_id=unknown_auth_params.get("app_id", ""),
        subscription_id=unknown_auth_params.get("subscription_id", ""),
        resource_group_name=unknown_auth_params.get("resource_group_name", ""),
        verify=not unknown_auth_params.get("insecure", False),
        proxy=unknown_auth_params.get("proxy", False),
        connection_type=unknown_auth_params.get("auth_type"),
        tenant_id=unknown_auth_params.get("tenant_id"),
        enc_key=unknown_auth_params.get("credentials", {}).get("password"),
    )
    
    # Test that it raises the expected exception
    with pytest.raises(Exception) as e:
        test_module(client)
    
    assert "When using user auth flow configuration" in str(e.value)


def test_storage_account_update_command_empty_response(mocker, client, mock_params):
    """
    Given: An Azure client and a request to update a storage account that returns an empty response.
    When: The storage_account_update_command function is called with valid parameters.
    Then: The function should return a message indicating the account will be created shortly.
    """
    
    # Prepare mock response with empty text
    mock_response = mocker.MagicMock()
    mock_response.text = ""
    
    mocker.patch.object(client, "storage_account_update_request", return_value=mock_response)
    
    # Call the function
    args = {
        "account_name": "teststorage",
        "sku": "Standard_LRS",
        "kind": "StorageV2",
        "location": "eastus"
    }
    
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
    error_message = 'Rule test-rule under subscription ID "test_subscription_id" and resource group "test_resource_group" was not found.'
    mocker.patch.object(client, "get_rule", side_effect=ValueError(error_message))
    
    # Call the function and expect it to raise the ValueError
    args = {
        "security_group_name": "test-sg",
        "security_rule_name": "test-rule"
    }
    
    with pytest.raises(ValueError) as e:
        update_security_rule_command(client, mock_params, args)
    
    # Verify the error message
    assert error_message in str(e.value)


def test_client_initialization_with_app_id_containing_refresh_token(mocker):
    """
    Given: App ID containing a refresh token.
    When: AzureClient is initialized.
    Then: The client should extract and store the refresh token in the integration context.
    """
    from Azure import AzureClient
    
    # Mock set_integration_context
    mocker.patch("Azure.get_integration_context", return_value={})
    mock_set_integration_context = mocker.patch("Azure.set_integration_context")
    mocker.patch("MicrosoftApiModule.MicrosoftClient")
    
    # Initialize client with app_id containing refresh token
    app_id_with_token = "test_app_id@refresh_token_123"
    
    client = AzureClient(
        app_id=app_id_with_token,
        subscription_id="test_subscription_id",
        resource_group_name="test_resource_group",
        verify=True,
        proxy=False,
        connection_type="Client Credentials",
        tenant_id="test_tenant_id",
        enc_key="test_enc_key"
    )
    
    # Verify that set_integration_context was called with the expected arguments
    expected_context = {"current_refresh_token": "refresh_token_123"}
    mock_set_integration_context.assert_called_once_with(expected_context)
    
    # Verify app_id was properly split
    assert client.app_id == "test_app_id"


def test_main_function_success(mocker):
    """
    Given: A command and valid parameters.
    When: The main function is called.
    Then: The appropriate command function should be called and results returned.
    """
    from Azure import main
    
    # Mock demisto functions
    mocker.patch.object(demisto, "command", return_value="azure-storage-account-update")
    mocker.patch.object(demisto, "params", return_value={
        "app_id": "test_app_id",
        "subscription_id": "test_subscription_id",
        "resource_group_name": "test_resource_group",
        "auth_type": "Client Credentials",
        "tenant_id": "test_tenant_id",
        "credentials": {"password": "test_enc_key"}
    })
    mocker.patch.object(demisto, "args", return_value={
        "account_name": "teststorage",
        "sku": "Standard_LRS",
        "kind": "StorageV2",
        "location": "eastus"
    })
    
    # Mock return_results
    mock_return_results = mocker.patch("Azure.return_results")
    
    # Mock AzureClient and storage_account_update_command
    mocker.patch("Azure.AzureClient")
    mock_cmd_result = mocker.MagicMock()
    mock_storage_account_update = mocker.patch("Azure.storage_account_update_command", return_value=mock_cmd_result)
    
    # Call main function
    main()
    
    # Verify that storage_account_update_command was called and results returned
    mock_storage_account_update.assert_called_once()
    mock_return_results.assert_called_once_with(mock_cmd_result)


def test_main_function_error_handling(mocker):
    """
    Given: A command that raises an exception.
    When: The main function is called.
    Then: The error should be caught and returned using return_error.
    """
    from Azure import main
    
    # Mock demisto functions
    mocker.patch.object(demisto, "command", return_value="azure-storage-account-update")
    mocker.patch.object(demisto, "params", return_value={
        "app_id": "test_app_id",
        "subscription_id": "test_subscription_id",
        "resource_group_name": "test_resource_group",
        "auth_type": "Client Credentials",
        "tenant_id": "test_tenant_id",
        "credentials": {"password": "test_enc_key"}
    })
    mocker.patch.object(demisto, "args", return_value={
        "account_name": "teststorage"
    })
    
    # Mock return_error
    mock_return_error = mocker.patch("Azure.return_error")
    
    # Mock AzureClient but make storage_account_update_command raise an exception
    mocker.patch("Azure.AzureClient")
    error_message = "Some API error occurred"
    mocker.patch("Azure.storage_account_update_command", side_effect=Exception(error_message))
    
    # Call main function
    main()
    
    # Verify that return_error was called with the expected error message
    mock_return_error.assert_called_once()
    call_args = mock_return_error.call_args[0][0]
    assert "Failed to execute azure-storage-account-update command" in call_args
    assert error_message in call_args


def test_main_function_not_implemented_command(mocker):
    """
    Given: A command that is not implemented.
    When: The main function is called.
    Then: A NotImplementedError should be raised and handled.
    """
    from Azure import main
    
    # Mock demisto functions
    mocker.patch.object(demisto, "command", return_value="azure-not-implemented-command")
    mocker.patch.object(demisto, "params", return_value={
        "app_id": "test_app_id",
        "subscription_id": "test_subscription_id",
        "resource_group_name": "test_resource_group",
        "auth_type": "Client Credentials",
        "tenant_id": "test_tenant_id",
        "credentials": {"password": "test_enc_key"}
    })
    mocker.patch.object(demisto, "args", return_value={})
    
    # Mock return_error
    mock_return_error = mocker.patch("Azure.return_error")
    
    # Mock AzureClient
    mocker.patch("Azure.AzureClient")
    
    # Call main function
    main()
    
    # Verify that return_error was called with the expected error message
    mock_return_error.assert_called_once()
    call_args = mock_return_error.call_args[0][0]
    assert "Failed to execute azure-not-implemented-command command" in call_args
    assert "is not implemented" in call_args


def test_storage_blob_service_properties_set_command_empty_values(mocker, client, mock_params):
    """
    Given: An Azure client and a request to set blob service properties with empty values.
    When: The storage_blob_service_properties_set_command function is called with minimal parameters.
    Then: The function should make the API call with only the specified parameters.
    """
    
    # Prepare mock response
    properties_response = {
        "name": "default",
        "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage/blobServices/default",
        "properties": {}
    }
    
    mocker.patch.object(client, "storage_blob_service_properties_set_request", return_value=properties_response)
    
    # Call the function with minimal args
    args = {
        "account_name": "teststorage"
    }
    
    result = storage_blob_service_properties_set_command(client, mock_params, args)
    
    # Verify results
    assert result.outputs_prefix == "Azure.StorageAccount.BlobServiceProperties"
    assert result.outputs_key_field == "id"
    assert result.outputs["name"] == "default"
    
    # Verify client method was called with None values for optional parameters
    client.storage_blob_service_properties_set_request.assert_called_once_with(
        mock_params.get("subscription_id"),
        mock_params.get("resource_group_name"),
        "teststorage",
        None,
        None
    )