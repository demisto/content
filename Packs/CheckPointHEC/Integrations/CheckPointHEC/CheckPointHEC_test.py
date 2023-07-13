import demistomock as demisto
import json

import pytest

from CheckPointHEC import Client, fetch_incidents, checkpointhec_get_entity, test_module as check_module


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

    mock_response = util_load_json('./test_data/checkpointhec-get_scopes.json')
    get_scopes = mocker.patch.object(
        Client,
        'get_scopes',
        return_value=mock_response,
    )
    demisto_results = mocker.patch.object(demisto, 'results')

    check_module(client)
    get_scopes.assert_called_once()
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
