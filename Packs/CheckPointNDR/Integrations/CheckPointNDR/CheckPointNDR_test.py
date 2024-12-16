import datetime
import json
from CheckPointNDR import (Client, fetch_incidents, parse_insights, test_module as check_module)


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

    result = check_module(client, {}, datetime.datetime(2024, 1, 1), 'test')
    login.assert_called_once()
    query_events.assert_called()
    logout.assert_called_once()
    assert result == 'ok'


def test_parse_insights():
    mock_insights = util_load_json('./test_data/checkpointndr-get_insights.json').get('objects')
    mock_insights[0]['events'] = util_load_json('./test_data/checkpointndr-get_insight_event.json').get('objects')

    mock_result = (util_load_json('./test_data/checkpointndr-parse_insights-output.json'),
                   datetime.datetime.fromtimestamp(1703387404.364).isoformat())

    result = parse_insights(mock_insights, 'test', 0, 10, 0)
    assert result == mock_result


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
    mock_insights_response = util_load_json('./test_data/checkpointndr-get_insights.json')
    query_insights = mocker.patch.object(
        Client,
        '_call_api',
        return_value=mock_insights_response.get('objects'),
    )
    logout = mocker.patch.object(
        Client,
        '_logout',
        return_value=None,
    )

    fetch_incidents(client, {}, datetime.datetime(2024, 1, 1), 'test', 10, 0)
    login.assert_called_once()
    query_insights.assert_called()
    logout.assert_called_once()
