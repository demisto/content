import json

import demistomock as demisto
from CheckPointHEC import (Client, fetch_incidents, checkpointhec_get_entity, checkpointhec_get_events,
                           checkpointhec_get_scan_info, checkpointhec_search_emails, checkpointhec_send_action,
                           checkpointhec_get_action_result, checkpointhec_send_notification, test_module as check_module)


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
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = check_module(client)
    call_api.assert_called_once()
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
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )
    demisto_incidents = mocker.patch.object(demisto, 'incidents')

    fetch_incidents(client, '1 day', [], [], [], 10)
    call_api.assert_called_once()
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
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_entity(client, '00000000000000000000000000000000')
    call_api.assert_called_once()
    assert result.outputs == mock_response['responseData'][0]['entityPayload']


def test_checkpointhec_get_entity_fail(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value={'responseData': []}
    )

    entity = '00000000000000000000000000000001'
    result = checkpointhec_get_entity(client, entity)
    call_api.assert_called_once()
    assert result.readable_output == f'Entity with id {entity} not found'


def test_checkpointhec_get_events_success(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-query_events.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_events(client, '2023-11-01 00:00:00')
    call_api.assert_called_once()
    assert result.outputs == mock_response['responseData']


def test_checkpointhec_get_events_fail(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value={'responseData': []}
    )

    result = checkpointhec_get_events(client, '2023-11-01 00:00:00')
    call_api.assert_called_once()
    assert result.readable_output == 'Events not found with the given criteria'


def test_checkpointhec_get_scan_info_success(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_entity.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_scan_info(client, '00000000000000000000000000000000')
    call_api.assert_called_once()
    assert result.outputs == {'av': json.dumps(mock_response['responseData'][0]['entitySecurityResult']['av'])}


def test_checkpointhec_get_scan_info_fail(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value={'responseData': []}
    )

    entity = '00000000000000000000000000000001'
    result = checkpointhec_get_scan_info(client, entity)
    call_api.assert_called_once()
    assert result.readable_output == f'Entity with id {entity} not found'


def test_checkpointhec_search_emails_success(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-search_emails.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    emails = []
    for entity in mock_response['responseData']:
        email = entity['entityPayload']
        email['entityId'] = entity['entityInfo']['entityId']
        emails.append(email)

    result = checkpointhec_search_emails(client, '1 day')
    call_api.assert_called()
    assert result.outputs == emails

    checkpointhec_search_emails(client, date_from='2023-11-01 00:00:00', date_to='2023-11-02 00:00:00')
    call_api.assert_called()
    assert result.outputs == emails


def test_checkpointhec_search_emails_fail(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    call_api = mocker.patch.object(
        Client,
        '_call_api'
    )

    date_last, date_from, date_to = '1 day', '2023-11-01 00:00:00', None
    result = checkpointhec_search_emails(client, date_last, date_from=date_from)
    call_api.assert_not_called()
    assert result.readable_output == f'Argument {date_last=} cannot be used with {date_from=} or {date_to=}'

    date_last = 'uno week'
    result = checkpointhec_search_emails(client, date_last)
    call_api.assert_not_called()
    assert result.readable_output == f'Could not establish start date with {date_last=}'

    result = checkpointhec_search_emails(client)
    call_api.assert_not_called()
    assert result.readable_output == 'Argument date_last and date_from cannot be both empty'

    subject_contains, subject_match = 'Any subject, ...', 'This subject'
    result = checkpointhec_search_emails(client, '1 day', subject_contains=subject_contains, subject_match=subject_match)
    call_api.assert_not_called()
    assert result.readable_output == f'Argument {subject_contains=} and {subject_match=} cannot be both set'

    sender_contains, sender_match = 'a@b.c', 'd@e.f'
    result = checkpointhec_search_emails(client, '1 day', sender_contains=sender_contains, sender_match=sender_match)
    call_api.assert_not_called()
    assert result.readable_output == f'Argument {sender_contains=} and {sender_match=} cannot be both set'

    recipients_contains, recipients_match = 'a@b.c', 'd@e.f'
    result = checkpointhec_search_emails(client, '1 day', recipients_contains=recipients_contains,
                                         recipients_match=recipients_match)
    call_api.assert_not_called()
    assert result.readable_output == f'Argument {recipients_contains=} and {recipients_match=} cannot be both set'

    name_contains, name_match = 'My Nam', 'My Name'
    result = checkpointhec_search_emails(client, '1 day', name_contains=name_contains, name_match=name_match)
    call_api.assert_not_called()
    assert result.readable_output == f'Argument {name_contains=} and {name_match=} cannot be both set'


def test_checkpointhec_send_action(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-send_action.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_send_action(
        client, ['00000000000000000000000000000002'], 'restore'
    )
    call_api.assert_called_once()
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
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_action_result(client, '1691525788820900')
    call_api.assert_called_once()
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
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_send_notification(client, '0000', ['a@b.c', 'd@e.f'])
    call_api.assert_called_once()
    assert result.outputs == mock_response
