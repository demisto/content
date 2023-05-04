from CommonServerPython import *
from RecordedFutureEventCollector import BASE_URL, DATE_FORMAT
from freezegun import freeze_time
import io
import requests_mock
import pytest

''' HELPER FUNCTIONS '''


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def mock_set_last_run(last_run):
    return last_run


def mock_send_events_to_xsiam(events, vendor, product):
    return events, vendor, product


''' TEST FUNCTIONS '''


def test_module_succeed(mocker):
    from RecordedFutureEventCollector import Client, test_module
    client = Client(BASE_URL)
    mock_results = mocker.patch('RecordedFutureEventCollector.return_results')

    with requests_mock.Mocker() as m:
        m.get(f'{BASE_URL}/info/whoami', status_code=200, text='{"name": "admin"}')
        test_module(client)

    assert mock_results.call_args[0][0] == 'ok'


def test_module_failed():
    from RecordedFutureEventCollector import Client, test_module
    client = Client(BASE_URL)

    with requests_mock.Mocker() as m:
        m.get(f'{BASE_URL}/info/whoami', status_code=401, text='{"error":{"status":401}}')
        with pytest.raises(DemistoException) as e:
            test_module(client)

    assert e.value.message == 'Failed due to - Error in API call [401] - None\n{"error": {"status": 401}}'


def test_get_events():
    from RecordedFutureEventCollector import Client, get_events
    client = Client(BASE_URL)

    with requests_mock.Mocker() as m:
        m.get(f'{BASE_URL}/alert/search', json=util_load_json('test_data/first_fetch.json'))

        mock_events = get_events(client, {'limit': 2})

    assert len(mock_events) == 2


@freeze_time('2023-02-21T00:00:00.000Z')
def test_fetch_events(mocker):
    from RecordedFutureEventCollector import Client, fetch_events, demisto
    client = Client(BASE_URL)

    with requests_mock.Mocker() as m:
        first_mock_request = m.get(f'{BASE_URL}/alert/search', json=util_load_json('test_data/first_fetch.json'))

        mock_events, next_last_run = fetch_events(client, limit=2, last_run=arg_to_datetime('3 days').strftime(DATE_FORMAT))

    assert len(mock_events) == 2
    assert next_last_run == {'last_run_ids': ['333333'], 'last_run_time': '2023-02-20T05:04:19'}
    assert first_mock_request.last_request.qs.get('triggered')[0].upper() == '[2023-02-18T00:00:00.000000Z,]'

    mocker.patch.object(demisto, 'getLastRun', return_value=next_last_run)
    last_run_time = next_last_run.get('last_run_time')

    with requests_mock.Mocker() as m:
        second_mock_request = m.get(f'{BASE_URL}/alert/search', json=util_load_json('test_data/second_fetch.json'))

        mock_events, next_last_run = fetch_events(client, limit=2, last_run=last_run_time)

    assert len(mock_events) == 1
    assert next_last_run == {'last_run_ids': ['555555'], 'last_run_time': '2023-02-20T05:04:24'}
    assert second_mock_request.last_request.qs.get('triggered')[0].upper() == '[2023-02-20T05:04:19,]'


def test_main(mocker):
    from RecordedFutureEventCollector import main, VENDOR, PRODUCT
    mocker.patch.object(demisto, 'command', return_value='recorded-future-get-events')
    mocker.patch.object(demisto, 'args', return_value={'should_push_events': True, 'limit': 2})
    events = mocker.patch('RecordedFutureEventCollector.send_events_to_xsiam', side_effect=mock_send_events_to_xsiam)

    with requests_mock.Mocker() as m:
        mock_request = m.get(f'{BASE_URL}/alert/search', json=util_load_json('test_data/first_fetch.json'))

        main()

    assert len(events.call_args[0][0]) == 2
    assert events.call_args[0][0][0].get('_time') == events.call_args[0][0][0].get('triggered')
    assert events.call_args[1].get('vendor') == VENDOR
    assert events.call_args[1].get('product') == PRODUCT
    assert mock_request.last_request.query == 'limit=2'
