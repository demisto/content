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
        Given:
            - azure_sql_servers_list command
        When:
            - Retrieving list of all sql servers
        Then
            - Assert the returned markdown and context data are as expected.
        """
    from AzureSQLManagement import azure_sql_servers_list_command
    client = mock_client(mocker, util_load_json("test_data/azure_sql_servers_list_result.json"))
    results = azure_sql_servers_list_command(client)
    assert '### Servers List' in results.readable_output
    assert results.outputs[0].get('name') == 'sqlintegration'
