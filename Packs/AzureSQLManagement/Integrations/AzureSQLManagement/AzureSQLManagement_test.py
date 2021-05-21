import json
import io
import demistomock as demisto
from AzureSQLManagement import Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def mock_client(mocker, http_request_result=None):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'current_refresh_token': 'refresh_token'})
    client = Client(
        app_id='app_id',
        subscription_id='subscriptionID',
        resource_group_name='resourceGroupName',
        verify=False,
        proxy=False
    )
    if http_request_result:
        mocker.patch.object(client, 'http_request', return_value=http_request_result)
    return client


def test_azure_sql_servers_list_command(mocker):
    """
        When:
            - Retrieving list of all sql servers using azure_sql_servers_list command
        Then
            - Assert the returned markdown and context data are as expected.
        """
    from AzureSQLManagement import azure_sql_servers_list_command
    client = mock_client(mocker, util_load_json('test_data/azure_sql_servers_list_result.json'))
    results = azure_sql_servers_list_command(client, {})
    assert '### Servers List' in results.readable_output
    assert results.outputs[0].get('name') == 'integration'


def test_azure_sql_db_list_command(mocker):
    """
        Given:
            - server_name
        When:
            - Retrieving list of all databases related to the server using the azure_sql_db_list command
        Then
            - Assert the returned markdown and context data are as expected.
        """
    from AzureSQLManagement import azure_sql_db_list_command
    client = mock_client(mocker, util_load_json('test_data/azure_sql_db_list_command_result.json'))
    args = {'server_name': 'integration'}
    results = azure_sql_db_list_command(client, args)
    assert '### Database List' in results.readable_output
    assert results.outputs[0].get('name') == 'integration-db'


def test_azure_sql_db_audit_policy_list_command(mocker):
    """
        Given:
            - server_name
            - db_name
        When:
            - Retrieving list of all audit policies related to the server and database using
            azure_sql_db_audit_policy_list command
        Then
            - Assert the returned markdown and context data are as expected.
        """
    from AzureSQLManagement import azure_sql_db_audit_policy_list_command
    client = mock_client(mocker, util_load_json('test_data/azure_sql_db_audit_policy_list_command_result.json'))
    args = {'server_name': 'integration', 'db_name': 'integration-db'}
    results = azure_sql_db_audit_policy_list_command(client, args)
    assert '### Database Audit Settings' in results.readable_output
    assert results.outputs[0].get('type') == 'Microsoft.Sql/servers/databases/auditingSettings'


def test_azure_sql_db_threat_policy_get_command(mocker):
    """
        Given:
            - server_name
            - db_name
        When:
            - Retrieving a threat detection policies of a database related to the server and database using
            azure_sql_db_threat_policy_get command
        Then
            - Assert the returned markdown and context data are as expected.
        """
    from AzureSQLManagement import azure_sql_db_threat_policy_get_command
    client = mock_client(mocker, util_load_json('test_data/azure_sql_db_threat_policy_get_command_result.json'))
    args = {'server_name': 'integration', 'db_name': 'integration-db'}
    results = azure_sql_db_threat_policy_get_command(client, args)
    assert '### Database Threat Detection Policies' in results.readable_output
    assert results.outputs.get('type') == 'Microsoft.Sql/servers/databases/securityAlertPolicies'


def test_azure_sql_db_audit_policy_create_update_command(mocker):
    """
        Given:
            - server_name
            - db_name
        When:
            - Creating or Updating an audi policies of a database related to the server and database using
            azure_sql_db_audit_policy_create_update command
        Then
            - Assert the returned markdown and context data are as expected.
        """
    from AzureSQLManagement import azure_sql_db_audit_policy_create_update_command
    client = mock_client(mocker,
                         util_load_json('test_data/azure_sql_db_audit_policy_create_update_command_result.json'))
    args = {'server_name': 'integration',
            'db_name': 'integration-db',
            'state': 'Enabled',
            'retention_days': '5',
            'is_azure_monitor_target_enabled': 'true'}
    results = azure_sql_db_audit_policy_create_update_command(client=client, args=args)
    assert '### Create Or Update Database Auditing Settings' in results.readable_output
    assert results.outputs.get('retentionDays') == 5
    assert results.outputs.get('isAzureMonitorTargetEnabled') is True


def test_azure_sql_db_threat_policy_create_update_command(mocker):
    """
        Given:
            - server_name
            - db_name
        When:
            - Creating or Updating a threat detection policies of a database related to the server and database using
            azure_sql_db_threat_policy_create_update command
        Then
            - Assert the returned markdown and context data are as expected.
        """
    from AzureSQLManagement import azure_sql_db_threat_policy_create_update_command
    client = mock_client(mocker,
                         util_load_json('test_data/azure_sql_db_threat_policy_create_update_command_result.json'))
    args = {'server_name': 'integration',
            'db_name': 'integration-db',
            'state': 'Enabled',
            'retention_days': '5',
            'email_addresses': 'test1@test.com'}
    results = azure_sql_db_threat_policy_create_update_command(client=client, args=args)
    assert '### Create Or Update Database Threat Detection Policies' in results.readable_output
    assert results.outputs.get('retentionDays') == 5
    assert results.outputs.get('emailAddresses')[0] == 'test1@test.com'
