import datetime
import json
import demistomock as demisto
from CheckPointNDR import (Client, fetch_incidents, test_module as check_module)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module(mocker):
    client = Client(
        base_url='https://portal.now.checkpoint.com',
        client_id='****',
        access_key='****',
        domain='test',
        verify=False,
        proxy=False
    )

    login = mocker.patch.object(
        Client,
        '_login',
        return_value=None,
    )
    logout = mocker.patch.object(
        Client,
        '_logout',
        return_value=None,
    )

    result = check_module(client)
    login.assert_called_once()
    logout.assert_called_once()
    assert result == 'ok'


def test_fetch_incidents(mocker):
    client = Client(
        base_url='https://portal.now.checkpoint.com',
        client_id='****',
        access_key='****',
        domain='test',
        verify=False,
        proxy=False
    )

    login = mocker.patch.object(
        Client,
        '_login',
        return_value=None,
    )
    mock_response = util_load_json('./test_data/checkpointndr-get_insights.json')
    query_events = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_response.get('objects'),
    )
    logout = mocker.patch.object(
        Client,
        '_logout',
        return_value=None,
    )
    demisto_incidents = mocker.patch.object(demisto, 'incidents')

    fetch_incidents(client, {}, datetime.datetime(2024, 1, 1), 'test')
    login.assert_called_once()
    query_events.assert_called()
    logout.assert_called_once()
    demisto_incidents.assert_called_once()
