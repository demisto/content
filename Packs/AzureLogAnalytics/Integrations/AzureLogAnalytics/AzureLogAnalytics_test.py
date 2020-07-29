from AzureLogAnalytics import Client, execute_query_command, list_saved_searches_command, parse_tags

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
        'MORE_DUMMY_DATA'
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
    client = mock_client()
    args = {}
    mocker.patch.object(client, 'http_request', return_value=MOCKED_EXECUTE_QUERY_OUTPUT)

    command_result = execute_query_command(client, args=args)

    assert 'Query Results' in command_result.readable_output
    assert len(command_result.outputs) == 2
    assert command_result.outputs[0].get('name') == 'Table 1'
    assert command_result.outputs[1].get('data')[0].get('column4') == 4


def test_list_saved_searches_command(mocker):
    client = mock_client()
    args = {'limit': '1'}
    mocker.patch.object(client, 'http_request', return_value=MOCKED_SAVED_SEARCHES_OUTPUT)

    command_result = list_saved_searches_command(client, args=args)

    assert 'Saved searches' in command_result.readable_output
    assert len(command_result.outputs) == 1
    assert command_result.outputs[0].get('id') == 'mocked_saved_search'
    assert command_result.outputs[0].get('query') == 'mocked_query'
    assert command_result.outputs[0].get('displayName') == 'mocked saved search'


def test_parse_tags():
    tags_arg = 'name1=value1;name2=value2'
    parsed_tags = parse_tags(tags_arg)

    assert len(parse_tags) == 2
    assert parsed_tags[0].get('name1') == 'value1'
    assert parsed_tags[1].get('name2') == 'value2'
