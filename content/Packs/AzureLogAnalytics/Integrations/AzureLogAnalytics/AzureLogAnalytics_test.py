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


def mock_client():
    client = Client(
        self_deployed=True,
        refresh_token='refresh_token',
        auth_and_token_url='auth_id',
        redirect_uri='redirect_uri',
        enc_key='enc_key',
        auth_code='auth_code',
        subscription_id='subscriptionID',
        resource_group_name='resourceGroupName',
        workspace_name='workspaceName',
        verify=False,
        proxy=False
    )
    return client


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
