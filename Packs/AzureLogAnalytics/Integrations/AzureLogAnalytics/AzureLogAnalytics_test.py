import json
import pytest

from AzureLogAnalytics import Client, execute_query_command, list_saved_searches_command, tags_arg_to_request_format

MOCKED_SAVED_SEARCHES_OUTPUT = {
    'value': [
        {
            'id': 'mocked_id/mocked_saved_search',
            'etag': 'mocked_etag',
            'properties': {
                'displayName': 'mocked saved search',
                'query': 'mocked_query'
            }
        },
        {
            'id': 'MORE_DUMMY_DATA'
        }
    ]
}

MOCKED_EXECUTE_QUERY_OUTPUT = {
    'tables': [
        {
            'name': 'Table 1',
            'columns': [
                {
                    'name': 'column1',
                    'type': 'string'
                },
                {
                    'name': 'column2',
                    'type': 'long'
                }
            ],
            'rows': [
                ['test', 1],
                ['test', 2]
            ]
        },
        {
            'name': 'Table 2',
            'columns': [
                {
                    'name': 'column3',
                    'type': 'string'
                },
                {
                    'name': 'column4',
                    'type': 'int'
                }
            ],
            'rows': [
                ['test', 3],
                ['test', 4]
            ]
        }
    ]
}

BASE_URL = 'https://management.azure.com/subscriptions'
SUBSCRIPTION_ID = 'subscriptionID'
RESOURCE_GROUP_NAME = 'resourceGroupName'


def get_azure_access_token_mock() -> dict:
    """
    Mock Azure access token object.

    Returns:
        dict: Azure access token mock.
    """
    return {
        'access_token': 'my-access-token',
        'expires_in': 3595,
        'refresh_token': 'my-refresh-token',
    }


def authorization_mock(requests_mock):
    """
    Azure authorization API request mock.

    """
    authorization_url = 'https://login.microsoftonline.com/refresh_token/oauth2/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())


def mock_client():
    client = Client(
        self_deployed=True,
        refresh_token='refresh_token',
        auth_and_token_url='auth_id',
        redirect_uri='redirect_uri',
        enc_key='enc_key',
        auth_code='auth_code',
        subscription_id=SUBSCRIPTION_ID,
        resource_group_name=RESOURCE_GROUP_NAME,
        workspace_name='workspaceName',
        verify=False,
        proxy=False,
        certificate_thumbprint=None,
        private_key=None,
        client_credentials=False,
    )
    return client


def load_mock_response(file_path: str) -> dict:
    """
    Load mock file that simulates an API response.
    Args:
        file_path (str): Path of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(file_path, encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


def test_execute_query_command(mocker):
    """
    Given:
        - A LogAnalytics client object
    When:
        - Calling function execute_query_command
    Then:
        - Ensure the readable output's title is correct
        - Ensure the output's structure is as expected
    """
    client = mock_client()
    args = {}
    mocker.patch.object(client, 'http_request', return_value=MOCKED_EXECUTE_QUERY_OUTPUT)

    command_result = execute_query_command(client, args=args)

    assert 'Query Results' in command_result.readable_output
    assert len(command_result.outputs) == 2
    assert command_result.outputs[0].get('TableName') == 'Table 1'
    assert command_result.outputs[1].get('Data')[1].get('column4') == 4


def test_list_saved_searches_command(mocker):
    """
    Given:
        - A LogAnalytics client object
        - Arguments of azure-log-analytics-list-saved-searches command, representing we want
          a single saved search from the first page of the list to be retrieved
    When:
        - Calling function list_saved_searches_command
    Then:
        - Ensure the readable output's title is correct
        - Ensure a single saved search is returned
        - Ensure the output's structure is as expected
    """
    client = mock_client()
    args = {'limit': '1', 'page': '0'}
    mocker.patch.object(client, 'http_request', return_value=MOCKED_SAVED_SEARCHES_OUTPUT)

    command_result = list_saved_searches_command(client, args=args)

    assert 'Saved searches' in command_result.readable_output
    assert len(command_result.outputs) == 1
    assert command_result.outputs[0].get('id') == 'mocked_saved_search'
    assert command_result.outputs[0].get('query') == 'mocked_query'
    assert command_result.outputs[0].get('displayName') == 'mocked saved search'


def test_tags_arg_to_request_format():
    """
    Given:
        - `tags` argument from azure-log-analytics-execute-query command
        - The argument has two tags (a name and a value for each tag)
    When:
        - Calling function tags_arg_to_request_format
    Then:
        - Ensure the argument is parsed correctly to a dict with two tags.
    """
    tags_arg = 'name1=value1;name2=value2'
    parsed_tags = tags_arg_to_request_format(tags_arg)

    assert len(parsed_tags) == 2
    assert parsed_tags[0].get('name') == 'name1'
    assert parsed_tags[1].get('value') == 'value2'


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
    Scenario: run test module when managed identities client id provided.
    Given:
     - User has provided managed identities client oid.
    When:
     - test-module called.
    Then:
     - Ensure the output are as expected
    """
    from AzureLogAnalytics import main, MANAGED_IDENTITIES_TOKEN_URL
    import AzureLogAnalytics
    import demistomock as demisto

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'auth_type': 'Azure Managed Identities',
        'subscription_id': {'password': 'test'},
        'resource_group': 'test_resource_group',
        'credentials_refresh_token': {'password': 'test'}
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AzureLogAnalytics, 'return_results')
    mocker.patch.object(AzureLogAnalytics, 'execute_query_command')

    main()

    assert 'ok' in AzureLogAnalytics.return_results.call_args[0][0]


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function azure-log-analytics-generate-login-url
    Then:
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from AzureLogAnalytics import main
    import AzureLogAnalytics

    redirect_uri = 'redirect_uri'
    tenant_id = 'tenant_id'
    client_id = 'client_id'
    mocked_params = {
        'redirect_uri': redirect_uri,
        'self_deployed': 'True',
        'refresh_token': tenant_id,
        'credentials': {
            'identifier': client_id,
            'password': 'client_secret'
        }
    }
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value='azure-log-analytics-generate-login-url')
    mocker.patch.object(AzureLogAnalytics, 'return_results')

    # call
    main()

    # assert
    expected_url = f'[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?' \
                   'response_type=code&scope=offline_access%20https://api.loganalytics.io/Data.Read' \
                   '%20https://management.azure.com/user_impersonation' \
                   f'&client_id={client_id}&redirect_uri={redirect_uri})'
    res = AzureLogAnalytics.return_results.call_args[0][0].readable_output
    assert expected_url in res


def test_subscriptions_list_command(requests_mock):
    """
    Given:
        - Mock response from API client
    When:
        - Calling subscriptions_list_command
    Then:
        - Validate expected outputs returned
    """
    from AzureLogAnalytics import subscriptions_list_command

    authorization_mock(requests_mock)
    client = mock_client()
    mock_response = load_mock_response('test_data/subscriptions_list.json')
    requests_mock.get(BASE_URL, json=mock_response)

    command_result = subscriptions_list_command(client)

    assert len(command_result.outputs) == 2
    assert command_result.outputs_prefix == 'AzureLogAnalytics.Subscription'
    assert command_result.outputs[0].get('id') == '/subscriptions/1234'


def test_workspace_list_command(requests_mock):
    """
    Given:
        - Mock response from API client
    When:
        - Calling workspace_list_command
    Then:
        - Validate expected outputs returned
    """
    from AzureLogAnalytics import workspace_list_command

    authorization_mock(requests_mock)
    client = mock_client()
    mock_response = load_mock_response('test_data/workspace_list.json')
    url = f'{BASE_URL}/{SUBSCRIPTION_ID}/resourcegroups/{RESOURCE_GROUP_NAME}/providers/Microsoft.OperationalInsights/workspaces'
    requests_mock.get(url, json=mock_response)

    command_result = workspace_list_command(client)

    assert len(command_result.outputs) == 1
    assert command_result.outputs_prefix == 'AzureLogAnalytics.workspace'
    assert command_result.outputs[0].get('name') == 'Test2170'


def test_resource_group_list_command(requests_mock):
    """
    Given:
        - limit argument
        - Mock response from API client
    When:
        - Calling resource_group_list_command
    Then:
        - Validate expected outputs returned
    """
    from AzureLogAnalytics import resource_group_list_command

    authorization_mock(requests_mock)
    client = mock_client()
    url = f'{BASE_URL}/{SUBSCRIPTION_ID}/resourcegroups'
    mock_response = load_mock_response('test_data/resource_group_list.json')
    requests_mock.get(url, json=mock_response)

    command_result = resource_group_list_command(client, {'limit': 50})

    assert len(command_result.outputs) == 1
    assert command_result.outputs_prefix == 'AzureLogAnalytics.ResourceGroup'
    assert command_result.outputs[0].get('id') == 'id'
