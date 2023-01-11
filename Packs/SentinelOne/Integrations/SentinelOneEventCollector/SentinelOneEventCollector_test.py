from CommonServerPython import *
import demistomock as demisto
import io
from freezegun import freeze_time
import requests_mock

''' CONSTANTS '''

ACTIVITIES_MOCK_URL = 'https://test.com/web/api/v2.1/activities?updatedAt__gt=2022-01-04+00%3A00%3A00&limit=1000&sortBy=updatedAt&sortOrder=asc'  # noqa: E501
ACTIVITIES_SECOND_MOCK_URL = 'https://test.com/web/api/v2.1/activities?updatedAt__gt=2022-09-06T20%3A37%3A55.912951Z&limit=1000&sortBy=updatedAt&sortOrder=asc'  # noqa: E501
THREATS_MOCK_URL = 'https://test.com/web/api/v2.1/threats?updatedAt__gt=2022-01-04+00%3A00%3A00&limit=1000&sortBy=updatedAt&sortOrder=asc'  # noqa: E501
THREATS_SECOND_MOCK_URL = 'https://test.com/web/api/v2.1/threats?updatedAt__gt=2022-12-20T15%3A51%3A17.514437Z&limit=1000&sortBy=updatedAt&sortOrder=asc'  # noqa: E501
ALERTS_MOCK_URL = 'https://test.com/web/api/v2.1/cloud-detection/alerts?limit=1000&updatedAt__gt=2022-01-04+00%3A00%3A00&sortBy=alertInfoupdatedAt&sortOrder=asc'  # noqa: E501
ALERTS_SECOND_MOCK_URL = 'https://test.com/web/api/v2.1/cloud-detection/alerts?limit=1000&updatedAt__gt=2022-12-20T13%3A54%3A43.027000Z&sortBy=alertInfoupdatedAt&sortOrder=asc'  # noqa: E501

''' HELPER FUNCTIONS '''


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def mock_send_events_to_xsiam(events, vendor, product):
    return events, vendor, product


''' TEST FUNCTIONS '''


@freeze_time('2022-01-07 00:00:00Z')
def test_test_module():
    from SentinelOneEventCollector import Client, test_module
    client = Client('https://test.com/web/api/v2.1')

    with requests_mock.Mocker() as m:
        m.get(ACTIVITIES_MOCK_URL, json={})
        m.get(THREATS_MOCK_URL, json={})
        m.get(ALERTS_MOCK_URL, json={})

        result = test_module(client, ['ACTIVITIES', 'THREATS', 'ALERTS'])

    assert result == 'ok'


@freeze_time('2022-01-07 00:00:00Z')
def test_get_events_command():
    """
    Tests helloworld-say-hello command function.

        Given:
            - No mock is needed here because the say_hello_command does not call any external API.

        When:
            - Running the 'say_hello_command'.

        Then:
            - Checks the output of the command function with the expected output.

    """
    from SentinelOneEventCollector import Client, get_events_command

    client = Client(base_url='https://test.com/web/api/v2.1')

    with requests_mock.Mocker() as m:
        m.get(ACTIVITIES_MOCK_URL, json=util_load_json('test_data/activities.json'))
        m.get(THREATS_MOCK_URL, json=util_load_json('test_data/threats.json'))
        m.get(ALERTS_MOCK_URL, json=util_load_json('test_data/alerts.json'))

        events, _ = get_events_command(client, arg_to_datetime('3 days'), ['ACTIVITIES', 'THREATS', 'ALERTS'])

    assert len(events) == 6


@freeze_time('2022-01-07 00:00:00Z')
def test_fetch_events():
    from SentinelOneEventCollector import Client, fetch_events, first_run
    client = Client(base_url='https://test.com/web/api/v2.1')
    last_run = first_run(arg_to_datetime('3 days'))

    with requests_mock.Mocker() as m:
        m.get(ACTIVITIES_MOCK_URL, json=util_load_json('test_data/activities.json'))
        m.get(THREATS_MOCK_URL, json=util_load_json('test_data/threats.json'))
        m.get(ALERTS_MOCK_URL, json=util_load_json('test_data/alerts.json'))
        m.get(ACTIVITIES_SECOND_MOCK_URL, json=util_load_json('test_data/activities_second_fetch.json'))
        m.get(THREATS_SECOND_MOCK_URL, json={})
        m.get(ALERTS_SECOND_MOCK_URL, json={})

        next_run, events = fetch_events(client, last_run, ['ACTIVITIES', 'THREATS', 'ALERTS'])

        assert next_run.get('last_activity_updated') == '2022-09-06T20:37:55.912951Z'
        assert next_run.get('last_alert_updated') == '2022-12-20T13:54:43.027000Z'
        assert len(events) == 6

        next_run, events = fetch_events(client, last_run, ['ACTIVITIES', 'THREATS', 'ALERTS'])

        assert next_run.get('last_activity_updated') == '2022-09-06T20:39:15.445218Z'
        assert next_run.get('last_alert_updated') == '2022-12-20T13:54:43.027000Z'
        assert len(events) == 2


@freeze_time('2022-01-07 00:00:00Z')
def test_main(mocker):
    """
    Tests helloworld-say-hello command function.

        Given:
            - No mock is needed here because the say_hello_command does not call any external API.

        When:
            - Running the 'say_hello_command'.

        Then:
            - Checks the output of the command function with the expected output.

    """
    from SentinelOneEventCollector import main, VENDOR, PRODUCT
    mocker.patch.object(demisto, 'command', return_value='sentinelone-get-events')
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://test.com', 'fetch_limit': 2})
    mocker.patch.object(demisto, 'args', return_value={'should_push_events': True})
    events = mocker.patch('SentinelOneEventCollector.send_events_to_xsiam', side_effect=mock_send_events_to_xsiam)

    with requests_mock.Mocker() as m:
        m.get(ACTIVITIES_MOCK_URL.replace('limit=1000', 'limit=2'), json=util_load_json('test_data/activities.json'))
        m.get(THREATS_MOCK_URL.replace('limit=1000', 'limit=2'), json=util_load_json('test_data/threats.json'))
        m.get(ALERTS_MOCK_URL.replace('limit=1000', 'limit=2'), json=util_load_json('test_data/alerts.json'))

        main()

    assert len(events.call_args[0][0]) == 6
    assert events.call_args[0][0][0].get('_time') == events.call_args[0][0][0].get('updatedAt')
    assert events.call_args[1].get('vendor') == VENDOR
    assert events.call_args[1].get('product') == PRODUCT
