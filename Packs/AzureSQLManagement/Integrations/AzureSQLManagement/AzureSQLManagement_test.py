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
    results = azure_sql_servers_list_command(client, {}, 'resourceGroupName')
    results_2 = azure_sql_servers_list_command(client, {'list_by_resource_group': 'true'}, 'resourceGroupName')
    assert '### Servers List' in results.readable_output
    assert results.outputs[0].get('name') == 'integration'
    assert '### The list of servers in the resource group: resourceGroupName' in results_2.readable_output
    assert results_2.outputs[0].get('name') == 'integration'


def test_azure_sql_servers_list_command_with_not_found(mocker):
    """
        Given:
            - A wrong resource group name.
        When:
            - Retrieving list of all sql servers using azure_sql_servers_list command.
        Then
            - Assert that we get the failure message.
        """
    from AzureSQLManagement import azure_sql_servers_list_command
    failure_message = 'Resource group \'resource-group\' could not be found.'
    args = {
        'resource_group_name': 'resource-group',
        'list_by_resource_group': 'true'
    }
    client = mock_client(mocker, failure_message)
    result = azure_sql_servers_list_command(client, args, 'resource-group')
    assert result.readable_output == failure_message


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


def test_azure_sql_db_list_command_with_not_found(mocker):
    """
    Given:
        - Wrong server_name
    When:
        - Retrieving list of all databases related to the server using the azure_sql_db_list command
    Then
        - Assert that a failure message is received
    """
    from AzureSQLManagement import azure_sql_db_list_command
    failure_message = 'Can not perform requested operation on nested resource. Parent resource \'sqlintegratio\' not found.'
    client = mock_client(mocker, failure_message)
    args = {'server_name': 'sqlintegratio'}
    result = azure_sql_db_list_command(client, args)
    assert result.readable_output == failure_message


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
    results = azure_sql_db_audit_policy_list_command(client, args, 'resourceGroupName')
    assert "### Database Audit Settings for resource_group_name='resourceGroupName'" in results.readable_output
    assert results.outputs[0].get('type') == 'Microsoft.Sql/servers/databases/auditingSettings'


def test_azure_sql_db_audit_policy_list_command_with_not_found(mocker):
    """
        Given:
            - server_name
            - A wrong db_name
        When:
            - Retrieving list of all audit policies related to the server and database using
            azure_sql_db_audit_policy_list command
        Then
            - Assert a failure message is received
        """
    from AzureSQLManagement import azure_sql_db_audit_policy_list_command
    args = {'server_name': 'server_name', 'db_name': 'db'}
    failure_message = 'Can not perform requested operation on nested resource. Parent resource \'server_name/db\' not found.'
    client = mock_client(mocker, failure_message)
    result = azure_sql_db_audit_policy_list_command(client, args, 'resourceGroupName')
    assert result.readable_output == failure_message


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
            'is_azure_monitor_target_enabled': 'true',
            'is_managed_identity_in_use': 'true'}
    results = azure_sql_db_audit_policy_create_update_command(client=client, args=args,
                                                              resource_group_name='resourceGroupName')
    assert "### Create Or Update Database Auditing Settings for resource_group_name='resourceGroupName'" in \
           results.readable_output
    assert results.outputs.get('retentionDays') == 5
    assert results.outputs.get('isAzureMonitorTargetEnabled') is True
    assert results.outputs.get('isManagedIdentityInUse') is False


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
    results = azure_sql_db_threat_policy_create_update_command(client=client, args=args,
                                                               resource_group_name='resourceGroupName')
    assert "### Create Or Update Database Threat Detection Policies for resource_group_name='resourceGroupName'" in \
           results.readable_output
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


def test_subscriptions_list_command(mocker):
    """
    When:
        - returning a list of the subscriptions id for a tenant using
            azure_sql_db_threat_policy_create_update command
    Then
        - Assert the returned markdown and context data are as expected.
    """

    from AzureSQLManagement import subscriptions_list_command
    client = mock_client(mocker, util_load_json('test_data/azure_aql_subscriptions_list_command_result.json'))
    results = subscriptions_list_command(client=client)
    assert '### Subscription List' in results.readable_output
    assert results.outputs[0].get('id') == 'id'
    assert results.outputs[0].get('displayName') == 'displayName'


def test_resource_group_list_command(mocker):
    """
    Given:
        - A list of subscriptions_id
        - A tag to filter accordingly
    When:
        - returning a list of the resource groups to all the given subscription id using
            resource_group_list_command command
    Then
        - Assert the returned markdown and context data are as expected.
    """
    from AzureSQLManagement import resource_group_list_command
    client = mock_client(mocker, util_load_json('test_data/azure_sql_resource_group_list_command_results.json'))
    args = {
        'tag': 'Name:name'
    }
    subscription_id_list = ['subscriptionID']
    results = resource_group_list_command(client=client, args=args, subscriptions_id=subscription_id_list)
    assert '### Resource Group List for subscriptionID' in results[0].readable_output
    assert results[0].outputs[0].get('id') == 'id'
    assert results[0].outputs[0].get('name') == 'name'
    assert results[0].outputs[0].get('tags', {}).get('Name') == 'name'


def test_resource_group_list_command_called_with(mocker):
    """
    Given:
        - A list of subscriptions_id
        - A tag to filter accordingly
    When:
        - returning a list of the resource groups to all the given subscription id using
            resource_group_list_command command
    Then
        - Assert the returned markdown and context data are as expected.
    """
    from AzureSQLManagement import resource_group_list_command
    client = Client(
        app_id='app_id',
        subscription_id='subscriptionID',
        resource_group_name='resourceGroupName',
        verify=False,
        proxy=False,
        auth_type='Device'
    )
    http_request = mocker.patch.object(client, 'http_request')
    args = {
        'tag': 'Name:name'
    }
    subscription_id_list = ['subscriptionID']
    resource_group_list_command(client=client, args=args, subscriptions_id=subscription_id_list)
    expected_full_url = "https://management.azure.com/subscriptions/subscriptionID/resourcegroups?" \
                        "api-version=2021-04-01&$filter=tagName eq 'Name' and tagValue eq 'name'&$top=50"
    http_request.assert_called_with(method='GET', full_url=expected_full_url)


def test_command_with_multiple_resource_group_name(mocker):
    """
        Given:
            - A mock client
            - The arguments to the command
            - The name of the command
            - A list of 2 resource groups names.
        When:
            - Running one of the 4 commands that allow multiple resource names
        Then
            - Assert the returned List contains 2 CommandResult objects.
        """
    from AzureSQLManagement import command_with_multiple_resource_group_name
    client = mock_client(mocker, util_load_json('test_data/azure_sql_db_audit_policy_list_command_result.json'))
    args = {
        'resource_group_name': 'resourceGroupName, resourceGroupName',
        'server_name': 'integration',
        'db_name': 'integration-db'
    }
    command = 'azure-sql-db-audit-policy-list'
    resource_group_name_list = ['resourceGroupName', 'resourceGroupName']
    results = command_with_multiple_resource_group_name(client, args, command, resource_group_name_list)
    assert len(results) == 2
