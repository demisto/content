import json
import io
from datetime import datetime, timedelta


BASE_URL = 'http://test.com'
API_KEY = '1234'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_indicators(requests_mock):
    from SecneurXThreatFeeds import Client, fetchThreatFeeds

    mock_response = util_load_json('test_data/fetch_indicators.json')
    requests_mock.get(f'{BASE_URL}/getfeeds', json=mock_response)
    client = Client(
        base_url=BASE_URL,
        verify=False,
        headers={'x-api-key': API_KEY},
        proxy=False
    )

    indicators = fetchThreatFeeds(client, None)
    assert len(indicators) == 4
    assert indicators[1]['fields']['indicatoridentification'] == mock_response['objects'][1]['id']
    assert indicators[1]['rawJson']['pattern'] == mock_response['objects'][1]['pattern']


def test_get_list_days():
    from SecneurXThreatFeeds import getListOfDays
    currentDate = datetime.now()
    startDate = currentDate - timedelta(days=2)
    endDate = currentDate.date()
    lastDateList = getListOfDays(currentDate.date(), currentDate.date())
    dateList = getListOfDays(startDate.date(), endDate)
    assert len(lastDateList) == 1
    assert len(dateList) == 2


def test_json_parse():
    from SecneurXThreatFeeds import parseIndicators
    mock_response = util_load_json('test_data/fetch_indicators.json')
    indicatorJson = parseIndicators(mock_response)
    assert len(indicatorJson) == 4
    assert indicatorJson[0]['fields']['indicatoridentification'] == mock_response['objects'][0]['id']
    assert indicatorJson[0]['value'] == mock_response['objects'][0]['name']


def test_module_connection(requests_mock):
    from SecneurXThreatFeeds import Client, test_module

    mock_response = util_load_json('test_data/fetch_indicators.json')
    requests_mock.get(f'{BASE_URL}/getfeeds', json=mock_response)
    client = Client(
        base_url=BASE_URL,
        verify=False,
        headers={'x-api-key': API_KEY},
        proxy=False
    )
    msg = test_module(client)
    assert msg == 'ok'


def test_module_connection_failure(requests_mock):
    from SecneurXThreatFeeds import Client, test_module

    requests_mock.get(f'{BASE_URL}/getfeeds', json=None)
    client = Client(
        base_url=BASE_URL,
        verify=False,
        headers={'x-api-key': API_KEY},
        proxy=False
    )
    try:
        test_module(client)
    except Exception as e:
        assert e.message == 'Configuration Error'


def test_fetch_feed_dates():
    from SecneurXThreatFeeds import fetchFeedDates
    startDate, endDate = fetchFeedDates(None, '2 days')
    startDate_1, endDate_1 = fetchFeedDates('2022-06-29', None)
    assert endDate == datetime.now().date()
    assert endDate_1 == datetime.now().date()


def test_create_indicators(requests_mock):
    from SecneurXThreatFeeds import Client, createIndicatorsInDemisto
    requests_mock.get(f'{BASE_URL}/getfeeds', json=False)
    client = Client(
        base_url=BASE_URL,
        verify=False,
        headers={'x-api-key': API_KEY},
        proxy=False
    )
    dateList = [None]
    result = createIndicatorsInDemisto(client, dateList, True)
    assert result is False
