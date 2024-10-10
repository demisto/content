import json

import demistomock as demisto
from CheckPointHEC import (
    Client, fetch_incidents, checkpointhec_get_entity, checkpointhec_get_events, checkpointhec_get_scan_info,
    checkpointhec_search_emails, checkpointhec_send_action, checkpointhec_get_action_result, checkpointhec_send_notification,
    checkpointhec_get_ap_exceptions, checkpointhec_create_ap_exception, checkpointhec_update_ap_exception,
    checkpointhec_delete_ap_exception, checkpointhec_get_cp2_exception, checkpointhec_create_cp2_exception,
    checkpointhec_update_cp2_exception, checkpointhec_delete_cp2_exception, checkpointhec_get_cp2_exceptions,
    checkpointhec_delete_cp2_exceptions, checkpointhec_get_anomaly_exceptions, checkpointhec_create_anomaly_exception,
    checkpointhec_delete_anomaly_exceptions, checkpointhec_get_ctp_lists, checkpointhec_get_ctp_list,
    checkpointhec_get_ctp_list_items, checkpointhec_get_ctp_list_item, checkpointhec_create_ctp_list_item,
    checkpointhec_update_ctp_list_item, checkpointhec_delete_ctp_list_item, checkpointhec_delete_ctp_list_items,
    checkpointhec_delete_ctp_lists, checkpointhec_create_avurl_exception, checkpointhec_update_avurl_exception,
    checkpointhec_delete_avurl_exception, checkpointhec_create_avdlp_exception, checkpointhec_update_avdlp_exception,
    checkpointhec_delete_avdlp_exception, test_module as check_module
)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_generate_infinity_token(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    _token = 'infinity token'
    _inf_token = {
        'data': {
            'token': _token,
            'expiresIn': 1000
        }
    }
    mocker.patch.object(
        Client,
        '_http_request',
        return_value=_inf_token
    )

    assert client._generate_infinity_token() == _token
    assert client.token == _token


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


def test_infinity_token_header(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    get_token = mocker.patch.object(
        Client,
        '_generate_infinity_token'
    )

    client._get_headers()
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


def test_call_smart_api(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    get_headers = mocker.patch.object(
        Client,
        '_get_headers',
        return_value={}
    )

    http_request = mocker.patch.object(
        Client,
        '_http_request'
    )

    method = 'GET'
    url_suffix = 'soar/test'
    path = '/'.join([client.api_version, url_suffix])
    request_string = f'/{path}'

    client._call_api(method, url_suffix)
    get_headers.assert_called_with(request_string)
    http_request.assert_called_with(method, url_suffix=path, headers={}, params=None, json_data=None)

    params = {'param1': 'value1'}
    request_string += '?param1=value1'
    client._call_api(method, url_suffix, params=params)
    get_headers.assert_called_with(request_string)
    http_request.assert_called_with(method, url_suffix=path, headers={}, params=params, json_data=None)


def test_call_infinity_api(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    get_headers = mocker.patch.object(
        Client,
        '_get_headers',
        return_value={}
    )

    http_request = mocker.patch.object(
        Client,
        '_http_request'
    )

    method = 'GET'
    url_suffix = 'soar/test'
    path = '/'.join(['app', 'hec-api', client.api_version, url_suffix])

    client._call_api(method, url_suffix)
    get_headers.assert_called_with(None)
    http_request.assert_called_with(method, url_suffix=path, headers={}, params=None, json_data=None)


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

    mocker.patch.object(demisto, 'getLastRun', return_value={'last_fetch': '2023-06-30T00:00:00'})
    demisto_incidents = mocker.patch.object(demisto, 'incidents')

    fetch_incidents(client, '1 day', ['office365_emails'], [], [], [], 10, 1)
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

    result = checkpointhec_get_events(client, '2023-11-01 00:00:00', None, ['office365_emails'], ['New'], [5], ['DLP'])
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
        client, ['00000000000000000000000000000002'], 'office365_emails_email', 'restore'
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

    mock_response = util_load_json('./test_data/checkpointhec-send_notification.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_send_notification(client, '0000', ['a@b.c', 'd@e.f'])
    call_api.assert_called_once()
    assert result.outputs == mock_response


def test_get_ap_exceptions_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_ap_exceptions(client, 'whitelist')
    call_api.assert_called_once()
    assert result.readable_output == 'No Anti-Phishing exceptions found'


def test_get_ap_exceptions_non_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_ap_exceptions.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_ap_exceptions(client, 'whitelist')
    call_api.assert_called_once()
    assert result.outputs == mock_response['responseData']


def test_create_ap_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_create_ap_exception(client, 'whitelist', comment='From Unit Tests')
    call_api.assert_called()
    assert result.readable_output == 'Anti-Phishing exception created successfully'


def test_create_ap_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_create_ap_exception(client, 'not_whitelist', comment='From Unit Tests')
    call_api.assert_called()
    assert result.readable_output == 'Error creating Anti-Phishing exception'


def test_update_ap_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_update_ap_exception(client, 'whitelist', '0000', comment='New comment')
    call_api.assert_called()
    assert result.readable_output == 'Anti-Phishing exception updated successfully'


def test_update_ap_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_update_ap_exception(client, 'not_whitelist', '0000', comment='New comment')
    call_api.assert_called()
    assert result.readable_output == 'Error updating Anti-Phishing exception'


def test_delete_ap_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 204
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_ap_exception(client, 'whitelist', '0000')
    call_api.assert_called()
    assert result.readable_output == 'Anti-Phishing exception deleted successfully'


def test_delete_ap_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_ap_exception(client, 'not_whitelist', '0000')
    call_api.assert_called()
    assert result.readable_output == 'Error deleting Anti-Phishing exception'


def test_get_cp2_exception_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_cp2_exception(client, 'hash', '00000000000000000000000000000000')
    call_api.assert_called_once()
    assert result.readable_output == 'No Anti-Malware exception found'


def test_get_cp2_exception_not_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_cp2_exception.json')
    mock_response['responseData'] = mock_response['responseData'][0]
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_cp2_exception(client, 'hash', '00000000000000000000000000000000')
    call_api.assert_called_once()
    assert result.outputs == mock_response['responseData']


def test_create_cp2_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 201
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_create_cp2_exception(client, 'file_type', '.pdf', comment='From Unit Tests')
    call_api.assert_called()
    assert result.readable_output == 'Anti-Malware exception created successfully'


def test_create_cp2_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_create_cp2_exception(client, 'not_file_type', '.pdf', comment='From Unit Tests')
    call_api.assert_called()
    assert result.readable_output == 'Error creating Anti-Malware exception'


def test_update_cp2_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_update_cp2_exception(client, 'file_type', '.pdf', comment='New comment')
    call_api.assert_called()
    assert result.readable_output == 'Anti-Malware exception updated successfully'


def test_update_cp2_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_update_cp2_exception(client, 'not_file_type', '.pdf', comment='New comment')
    call_api.assert_called()
    assert result.readable_output == 'Error updating Anti-Malware exception'


def test_delete_cp2_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 204
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_cp2_exception(client, 'file_type', '.pdf')
    call_api.assert_called()
    assert result.readable_output == 'Anti-Malware exception deleted successfully'


def test_delete_cp2_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_cp2_exception(client, 'not_file_type', '.pdf')
    call_api.assert_called()
    assert result.readable_output == 'Error deleting Anti-Malware exception'


def test_get_cp2_exceptions_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_cp2_exceptions(client, 'hash')
    call_api.assert_called_once()
    assert result.readable_output == 'No Anti-Malware exceptions found'


def test_get_cp2_exceptions_not_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_cp2_exception.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_cp2_exceptions(client, 'hash')
    call_api.assert_called_once()
    assert result.outputs == mock_response['responseData']


def test_delete_cp2_exceptions_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 204
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_cp2_exceptions(client, 'file_type', ['.pdf'])
    call_api.assert_called()
    assert result.readable_output == 'Anti-Malware exceptions deleted successfully'


def test_delete_cp2_exceptions_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_cp2_exceptions(client, 'not_file_type', ['.pdf'])
    call_api.assert_called()
    assert result.readable_output == 'Error deleting Anti-Malware exceptions'


def test_get_anomaly_exceptions_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_anomaly_exceptions(client)
    call_api.assert_called_once()
    assert result.readable_output == 'No Anomaly exceptions found'


def test_get_anomaly_exceptions_not_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_anomaly_exceptions.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_anomaly_exceptions(client)
    call_api.assert_called_once()
    assert result.outputs == mock_response['responseData']


def test_create_anomaly_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 201
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    request_json = {
        "whitelist-option:superman_anomaly": "0" * 32,
        "apply-to-past": "Yes",
        "anomaly-comment": "Test for XSOAR",
        "event_id": "0" * 32
    }
    result = checkpointhec_create_anomaly_exception(client, request_json, 'a@b.test')
    call_api.assert_called()
    assert result.readable_output == 'Anomaly exception created successfully'


def test_create_anomaly_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    request_json = {
        "whitelist-option:superman_anomaly": "0" * 32,
        "apply-to-past": "Yes",
        "anomaly-comment": "Test for XSOAR",
        "event_id": "0" * 32
    }
    result = checkpointhec_create_anomaly_exception(client, request_json, 'a@b.test')
    call_api.assert_called()
    assert result.readable_output == 'Error creating Anomaly exception'


def test_delete_anomaly_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 204
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_anomaly_exceptions(client, ['00000'])
    call_api.assert_called()
    assert result.readable_output == 'Anomaly exceptions deleted successfully'


def test_delete_anomaly_exceptions_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_anomaly_exceptions(client, ['00000'])
    call_api.assert_called()
    assert result.readable_output == 'Error deleting Anomaly exceptions'


def test_get_ctp_lists_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_ctp_lists(client)
    call_api.assert_called_once()
    assert result.readable_output == 'No CTP lists found'


def test_get_ctp_lists_not_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_ctp_lists.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_ctp_lists(client)
    call_api.assert_called_once()
    assert result.outputs == mock_response['responseData']


def test_get_ctp_list_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_ctp_list(client, '0')
    call_api.assert_called_once()
    assert result.readable_output == 'No CTP list found'


def test_get_ctp_list_not_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_ctp_list.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_ctp_list(client, '0')
    call_api.assert_called_once()
    assert result.outputs == mock_response['responseData']


def test_get_ctp_list_items_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_ctp_list_items(client)
    call_api.assert_called_once()
    assert result.readable_output == 'No CTP list items found'


def test_get_ctp_list_items_not_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_ctp_list_items.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_ctp_list_items(client)
    call_api.assert_called_once()
    assert result.outputs == mock_response['responseData']


def test_get_ctp_list_item_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_ctp_list_item(client, '0000000000000000')
    call_api.assert_called_once()
    assert result.readable_output == 'No CTP list items found'


def test_get_ctp_list_item_not_empty(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_ctp_list_item.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_get_ctp_list_item(client, '0000000000000000')
    call_api.assert_called_once()
    assert result.outputs == mock_response['responseData']


def test_create_ctp_list_item_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 201
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_create_ctp_list_item(client, '0', 'example.com', created_by='a@b.test')
    call_api.assert_called()
    assert result.readable_output == 'CTP list item created successfully'


def test_create_ctp_list_item_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_create_ctp_list_item(client, '-1', 'example.com', created_by='a@b.test')
    call_api.assert_called()
    assert result.readable_output == 'Error creating CTP list item'


def test_update_ctp_list_item_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_update_ctp_list_item(client, '00000000000', '0', 'new.example.com', created_by='a@b.test')
    call_api.assert_called()
    assert result.readable_output == 'CTP list item updated successfully'


def test_update_ctp_list_item_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_update_ctp_list_item(client, '00000000000', '-1', 'example.com', created_by='a@b.test')
    call_api.assert_called()
    assert result.readable_output == 'Error updating CTP list item'


def test_delete_ctp_list_item_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 204
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_ctp_list_item(client, '00000000000')
    call_api.assert_called()
    assert result.readable_output == 'CTP list item deleted successfully'


def test_delete_ctp_list_item_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    mock_response['responseEnvelope']['responseCode'] = 404
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_ctp_list_item(client, '00000000000')
    call_api.assert_called()
    assert result.readable_output == 'Error deleting CTP list item'


def test_delete_ctp_list_items_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 204
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_ctp_list_items(client, ['00000000000'])
    call_api.assert_called()
    assert result.readable_output == 'CTP list items deleted successfully'


def test_delete_ctp_list_items_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    mock_response['responseEnvelope']['responseCode'] = 404
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_ctp_list_items(client, ['00000000000'])
    call_api.assert_called()
    assert result.readable_output == 'Error deleting CTP list items'


def test_delete_ctp_lists_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 204
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_ctp_lists(client)
    call_api.assert_called()
    assert result.readable_output == 'CTP lists deleted successfully'


def test_delete_ctp_lists_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    mock_response['responseEnvelope']['responseCode'] = 404
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_ctp_lists(client)
    call_api.assert_called()
    assert result.readable_output == 'Error deleting CTP lists'


def test_create_avurl_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 201
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_create_avurl_exception(client, 'allow-url', 'example.com', comment='From Unit Tests')
    call_api.assert_called()
    assert result.readable_output == 'Avanan URL exception created successfully'


def test_create_avurl_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_create_avurl_exception(client, 'not-allow-url', 'example.com', comment='From Unit Tests')
    call_api.assert_called()
    assert result.readable_output == 'Error creating Avanan URL exception'


def test_update_avurl_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_update_avurl_exception(client, 'allow-url', 'example.com', comment='New comment')
    call_api.assert_called()
    assert result.readable_output == 'Avanan URL exception updated successfully'


def test_update_avurl_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_update_avurl_exception(client, 'not-allow-url', 'example.com', comment='New comment')
    call_api.assert_called()
    assert result.readable_output == 'Error updating Avanan URL exception'


def test_delete_avurl_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 204
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_avurl_exception(client, 'allow-url', 'example.com')
    call_api.assert_called()
    assert result.readable_output == 'Avanan URL exception deleted successfully'


def test_delete_avurl_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_avurl_exception(client, 'not-allow-url', 'example.com')
    call_api.assert_called()
    assert result.readable_output == 'Error deleting Avanan URL exception'


def test_create_avdlp_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 201
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_create_avdlp_exception(client, 'hash', '0' * 32, comment='From Unit Tests')
    call_api.assert_called()
    assert result.readable_output == 'Avanan DLP exception created successfully'


def test_create_avdlp_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_create_avdlp_exception(client, 'not_hash', '0' * 32, comment='From Unit Tests')
    call_api.assert_called()
    assert result.readable_output == 'Error creating Avanan DLP exception'


def test_update_avdlp_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_update_avdlp_exception(client, 'hash', '0' * 32, comment='New comment')
    call_api.assert_called()
    assert result.readable_output == 'Avanan DLP exception updated successfully'


def test_update_avdlp_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_update_avdlp_exception(client, 'not_hash', '0' * 32, comment='New comment')
    call_api.assert_called()
    assert result.readable_output == 'Error updating Avanan DLP exception'


def test_delete_avdlp_exception_success(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-success_response.json')
    mock_response['responseEnvelope']['responseCode'] = 204
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_avdlp_exception(client, 'hash', '0' * 32)
    call_api.assert_called()
    assert result.readable_output == 'Avanan DLP exception deleted successfully'


def test_delete_avdlp_exception_fail(mocker):
    client = Client(
        base_url='https://cloudinfra-gw.example.checkpoint-example.com',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-fail_response.json')
    call_api = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response,
    )

    result = checkpointhec_delete_avdlp_exception(client, 'not_hash', '0' * 32)
    call_api.assert_called()
    assert result.readable_output == 'Error deleting Avanan DLP exception'
