import json
import pytest

import demistomock as demisto
from CheckPointHEC import (Client, fetch_incidents, checkpointhec_get_entity, checkpointhec_get_email_info,
                           checkpointhec_get_scan_info, checkpointhec_search_emails, checkpointhec_send_action,
                           checkpointhec_get_action_result, checkpointhec_send_notification, test_module as check_module)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


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
        'test_api',
        return_value=mock_response,
    )
    demisto_results = mocker.patch.object(demisto, 'results')

    check_module(client)
    test_api.assert_called_once()
    demisto_results.assert_called_once_with('ok')


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
        'query_events',
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
        'get_entity',
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

    mocker.patch.object(
        Client,
        'get_entity',
        return_value={'responseData': []}
    )

    entity = '00000000000000000000000000000001'
    with pytest.raises(Exception, match=f'Entity with id {entity} not found'):
        checkpointhec_get_entity(client, entity)


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
        'get_email',
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

    mocker.patch.object(
        Client,
        'get_email',
        return_value={'responseData': []}
    )

    entity = '00000000000000000000000000000001'
    with pytest.raises(Exception, match=f'Entity with id {entity} not found'):
        checkpointhec_get_email_info(client, entity)


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
        'get_entity',
        return_value=mock_response,
    )

    result = checkpointhec_get_scan_info(client, '00000000000000000000000000000000')
    get_entity.assert_called_once()
    assert result.outputs == {'av': mock_response['responseData'][0]['entitySecurityResult']['av']}


def test_checkpointhec_get_scan_info_fail(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mocker.patch.object(
        Client,
        'get_entity',
        return_value={'responseData': []}
    )

    entity = '00000000000000000000000000000001'
    with pytest.raises(Exception, match=f'Entity with id {entity} not found'):
        checkpointhec_get_scan_info(client, entity)


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
        'search_emails',
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
        'send_action',
        return_value=mock_response,
    )

    result = checkpointhec_send_action(
        client, 'mt-rnd-ng-6', 'avananlab', '00000000000000000000000000000002', 'restore'
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
        'get_task',
        return_value=mock_response,
    )

    result = checkpointhec_get_action_result(client, 'mt-rnd-ng-6', 'avananlab', 1691525788820900)
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
        'send_notification',
        return_value=mock_response,
    )

    result = checkpointhec_send_notification(client, '0000', ['a@b.c', 'd@e.f'])
    get_task.assert_called_once()
    assert result.outputs == mock_response
