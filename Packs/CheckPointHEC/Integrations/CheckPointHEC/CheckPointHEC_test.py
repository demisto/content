import json

import demistomock as demisto
from CheckPointHEC import (Client, fetch_incidents, checkpointhec_get_entity, checkpointhec_get_email_info,
                           checkpointhec_get_scan_info, checkpointhec_search_emails, checkpointhec_send_action,
                           checkpointhec_get_action_result, checkpointhec_send_notification,
                           test_module as check_module)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_generate_signature_with_request_string():
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )
    assert client._generate_signature(
        f"{'0' * 8}-{'0' * 4}-{'0' * 4}-{'0' * 4}-{'0' * 12}",
        '2023-08-13T19:08:35.263817',
        '/v1.0/soar/test'
    ) == '66968b7de6a44c879eedc2a426ec76c254c203d60ce746236645b52b5b5dcddb'


def test_generate_signature_with_no_request_string():
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )
    assert client._generate_signature(
        f"{'0' * 8}-{'0' * 4}-{'0' * 4}-{'0' * 4}-{'0' * 12}",
        '2023-08-13T19:08:35.263817'
    ) == 'ac07ea6ddd026cbbfad8751d45d6e9e1823bc03e227eeb117976834391b629b8'


def test_token_header(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    get_token = mocker.patch.object(
        Client,
        '_get_token'
    )

    client._get_headers(auth=True)
    get_token.assert_not_called()

    client._get_headers(auth=False)
    get_token.assert_called_once()


def test_get_token_empty(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    _token = 'super token'
    mocker.patch.object(
        Client,
        '_http_request',
        return_value=_token
    )

    token = client._get_token()
    assert token == _token


def test_get_token_existing(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    _token = 'super token'
    mocker.patch.object(
        Client,
        '_http_request',
        return_value=_token
    )

    client.token = 'nice token'
    token = client._get_token()
    assert token != _token


def test_test_module(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-test_api.json')
    test_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = check_module(client)
    test_api.assert_called_once()
    assert result == 'ok'


def test_fetch_incidents(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-query_events.json')
    query_events = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )
    demisto_incidents = mocker.patch.object(demisto, 'incidents')

    fetch_incidents(client, '1 day', 10)
    query_events.assert_called_once()
    demisto_incidents.assert_called_once()


def test_checkpointhec_get_entity_success(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_entity.json')
    get_entity = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_entity(client, '00000000000000000000000000000000')
    get_entity.assert_called_once()
    assert result.outputs == mock_response['responseData'][0]['entityPayload']


def test_checkpointhec_get_entity_fail(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    get_entity = mocker.patch.object(
        Client,
        '_call_api',
        return_value={'responseData': []}
    )

    entity = '00000000000000000000000000000001'
    result = checkpointhec_get_scan_info(client, entity)
    get_entity.assert_called_once()
    assert result.readable_output == f'Entity with id {entity} not found'


def test_checkpointhec_get_email_info_success(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_email_info.json')
    get_entity = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_email_info(client, '00000000000000000000000000000000')
    get_entity.assert_called_once()
    assert result.outputs == mock_response['responseData'][0]['entityPayload']


def test_checkpointhec_get_email_info_fail(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    get_entity = mocker.patch.object(
        Client,
        '_call_api',
        return_value={'responseData': []}
    )

    entity = '00000000000000000000000000000001'
    result = checkpointhec_get_scan_info(client, entity)
    get_entity.assert_called_once()
    assert result.readable_output == f'Entity with id {entity} not found'


def test_checkpointhec_get_scan_info_success(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_entity.json')
    get_entity = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_scan_info(client, '00000000000000000000000000000000')
    get_entity.assert_called_once()
    assert result.outputs == {'av': json.dumps(mock_response['responseData'][0]['entitySecurityResult']['av'])}


def test_checkpointhec_get_scan_info_fail(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    get_entity = mocker.patch.object(
        Client,
        '_call_api',
        return_value={'responseData': []}
    )

    entity = '00000000000000000000000000000001'
    result = checkpointhec_get_scan_info(client, entity)
    get_entity.assert_called_once()
    assert result.readable_output == f'Entity with id {entity} not found'


def test_checkpointhec_search_emails(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-search_emails.json')
    search_emails = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_search_emails(client, '1 day', 'Automation@avtestqa.com')
    search_emails.assert_called_once()
    ids = [entity['entityInfo']['entityId'] for entity in mock_response['responseData']]
    assert result.outputs == {'ids': ids}


def test_checkpointhec_send_action(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-send_action.json')
    send_action = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_send_action(
        client, 'mt-rnd-ng-6', 'avananlab', ['00000000000000000000000000000002'], 'restore'
    )
    send_action.assert_called_once()
    assert result.outputs == {'task': mock_response['responseData'][0]['taskId']}


def test_checkpointhec_get_action_result(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_action_result.json')
    get_task = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_action_result(client, 'mt-rnd-ng-6', 'avananlab', '1691525788820900')
    get_task.assert_called_once()
    assert result.outputs == mock_response['responseData']


def test_send_notification(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-test_api.json')
    get_task = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_send_notification(client, '0000', ['a@b.c', 'd@e.f'])
    get_task.assert_called_once()
    assert result.outputs == mock_response
