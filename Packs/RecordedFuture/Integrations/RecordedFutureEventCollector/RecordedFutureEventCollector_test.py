from CommonServerPython import *
import io
import requests_mock
from RecordedFutureEventCollector import BASE_URL, DATE_FORMAT
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


def test_fetch_events(mocker):
    from RecordedFutureEventCollector import Client, fetch_events, demisto
    client = Client(BASE_URL)
    mock_last_run = mocker.patch.object(demisto, 'setLastRun', side_efect=mock_set_last_run)

    with requests_mock.Mocker() as m:
        m.get(f'{BASE_URL}/alert/search', json=util_load_json('test_data/first_fetch.json'))

        mock_events = fetch_events(client, limit=2, last_run=arg_to_datetime('3 days').strftime(DATE_FORMAT))

    assert len(mock_events) == 2
    assert mock_last_run.call_args[0][0] == {'last_run_time': '2023-02-20T05:04:19.601Z', 'last_run_ids': {'333333'}}

    mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run.call_args[0][0])
    mock_last_run = mocker.patch.object(demisto, 'setLastRun', side_efect=mock_set_last_run)

    with requests_mock.Mocker() as m:
        m.get(f'{BASE_URL}/alert/search', json=util_load_json('test_data/second_fetch.json'))

        mock_events = fetch_events(client, limit=2, last_run=arg_to_datetime('3 days'))

    assert len(mock_events) == 1
    assert mock_last_run.call_args[0][0] == {'last_run_time': '2023-02-20T05:04:24.673Z', 'last_run_ids': {'555555'}}


def test_main(mocker):
    from RecordedFutureEventCollector import main, VENDOR, PRODUCT
    mocker.patch.object(demisto, 'command', return_value='recorded-future-get-events')
    mocker.patch.object(demisto, 'params', return_value={'max_fetch': 1000})
    mocker.patch.object(demisto, 'args', return_value={'should_push_events': True, 'limit': 2})
    events = mocker.patch('RecordedFutureEventCollector.send_events_to_xsiam', side_effect=mock_send_events_to_xsiam)

    with requests_mock.Mocker() as m:
        request_mock = m.get(f'{BASE_URL}/alert/search', json=util_load_json('test_data/first_fetch.json'))

        main()

    assert len(events.call_args[0][0]) == 2
    assert events.call_args[0][0][0].get('_time') == events.call_args[0][0][0].get('triggered')
    assert events.call_args[1].get('vendor') == VENDOR
    assert events.call_args[1].get('product') == PRODUCT
    assert request_mock.last_request.query == 'limit=2'  # Verify that the args limit was taken and not the params limit
