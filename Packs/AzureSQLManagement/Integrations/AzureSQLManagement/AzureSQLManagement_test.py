import json
import io
import pytest
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
        proxy=False,
        auth_type='Device'
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


@pytest.mark.parametrize('params, expected_results', [
    ({'auth_type': 'Device Code'}, "When using device code flow configuration"),
    ({'auth_type': 'Authorization Code'}, "When using user auth flow configuration")])
def test_test_module_command(mocker, params, expected_results):
    """
        Given:
            - Case 1: Integration params with 'Device' as auth_type.
            - Case 2: Integration params with 'User Auth' as auth_type.
        When:
            - Calling test-module command.
        Then
            - Assert the right exception was thrown.
            - Case 1: Should throw an exception related to Device-code-flow config and return True.
            - Case 2: Should throw an exception related to User-Auth-flow config and return True.
    """
    from AzureSQLManagement import test_module
    import AzureSQLManagement as sql_management
    mocker.patch.object(sql_management, "test_connection", side_effect=Exception('mocked error'))
    mocker.patch.object(demisto, 'params', return_value=params)
    with pytest.raises(Exception) as e:
        test_module(None)
    assert expected_results in str(e.value)


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """

    from AzureSQLManagement import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import AzureSQLManagement

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {
        'managed_identities_client_id': {'password': client_id},
        'auth_type': 'Azure Managed Identities'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AzureSQLManagement, 'return_results')
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in AzureSQLManagement.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.management_azure]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function azure-sql-generate-login-url
    Then:
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from AzureSQLManagement import main
    import AzureSQLManagement

    redirect_uri = 'redirect_uri'
    tenant_id = 'tenant_id'
    client_id = 'client_id'
    mocked_params = {
        'redirect_uri': redirect_uri,
        'auth_type': 'Authorization Code',
        'tenant_id': tenant_id,
        'app_id': client_id,
        'credentials': {
            'password': 'client_secret'
        }
    }
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value='azure-sql-generate-login-url')
    mocker.patch.object(AzureSQLManagement, 'return_results')

    # call
    main()

    # assert
    expected_url = f'[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?' \
                   'response_type=code&scope=offline_access%20https://management.azure.com/.default' \
                   f'&client_id={client_id}&redirect_uri={redirect_uri})'
    res = AzureSQLManagement.return_results.call_args[0][0].readable_output
    assert expected_url in res
