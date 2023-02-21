from CommonServerPython import *
import io
import requests_mock
from RecordedFutureEventCollector import BASE_URL, DATE_FORMAT
import pytest

MOCK_LAST_RUN = dict()


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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


def mock_set_last_run(last_run):
    return last_run


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
