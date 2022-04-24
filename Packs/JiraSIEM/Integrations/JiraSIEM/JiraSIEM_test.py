import json
import io
import requests_mock
from freezegun import freeze_time


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def calculate_next_run(time):
    next_time = time.removesuffix('+0000')
    next_time_with_delta = next_time[:-1] + str(int(next_time[-1]) + 1)
    return next_time_with_delta


@freeze_time('2022-04-14T00:00:00Z')
def test_fetch_incidents_default_time(mocker):
    """
    Given
        - raw response of the http request
    When
        - fetching incidents
    Then
        - check the number of incidents that are being created
        check that the time in last_run is the on of the latest incident
    """
    import demistomock as demisto
    params = {
        'method': 'GET',
        'url': 'https://your.domain/rest/api/3/auditing/record',
        'max_fetch': 10,
        'first_fetch': '3 days',
        'credentials': {
            'identifier': 'admin@your.domain',
            'password': '123456',
        }
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={})
    last_run = mocker.patch.object(demisto, 'getLastRun', return_value={})
    results = mocker.patch.object(demisto, 'results')
    incidents = mocker.patch.object(demisto, 'incidents')

    with requests_mock.Mocker() as m:
        m.get(
            'https://your.domain/rest/api/3/auditing/record?from=2022-04-11T00:00:00.000000&limit=1000&offset=0',
            json=util_load_json('test_data/events.json')
        )
        m.get(
            'https://your.domain/rest/api/3/auditing/record?from=2022-04-11T00:00:00.000000&limit=1000&offset=1000',
            json={}
        )

        from JiraSIEM import main
        main()

    events = results.call_args[0][0]['Contents']
    assert last_run.return_value.get('from') == calculate_next_run(events[0].get('created'))
    assert last_run.return_value.get('offset') == 0
    assert incidents.call_args[0][0][0].get('name') == f'JiraSIEM - User Changed - 3'


@freeze_time('2022-04-14T00:00:00Z')
def test_fetch_incidents_one_hour(mocker):
    """
    Given
        - raw response of the http request
    When
        - fetching incidents
    Then
        - check the number of incidents that are being created
        check that the time in last_run is the on of the latest incident
    """
    import demistomock as demisto
    params = {
        'method': 'GET',
        'url': 'https://your.domain/rest/api/3/auditing/record',
        'max_fetch': 10,
        'first_fetch': '1 hour',
        'credentials': {
            'identifier': 'admin@your.domain',
            'password': '123456',
        }
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={})
    last_run = mocker.patch.object(demisto, 'getLastRun', return_value={})

    with requests_mock.Mocker() as m:
        m.get(
            'https://your.domain/rest/api/3/auditing/record?from=2022-04-13T23:00:00.000000&limit=1000&offset=0',
            json={}
        )

        from JiraSIEM import main
        main()

    assert not last_run.return_value.get('from')
    assert last_run.return_value.get('offset') == 0


@freeze_time('2022-04-14T00:00:00Z')
def test_fetch_incidents_with_a_limit_of_one(mocker):
    """
    Given
        - raw response of the http request
    When
        - fetching incidents
    Then
        - check the number of incidents that are being created
        check that the time in last_run is the on of the latest incident
    """
    import demistomock as demisto
    params = {
        'method': 'GET',
        'url': 'https://your.domain/rest/api/3/auditing/record',
        'max_fetch': 1,
        'first_fetch': '4 days',
        'credentials': {
            'identifier': 'admin@your.domain',
            'password': '123456',
        }
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={})
    last_run = mocker.patch.object(demisto, 'getLastRun', return_value={})

    with requests_mock.Mocker() as m:
        m.get(
            'https://your.domain/rest/api/3/auditing/record?from=2022-04-10T00:00:00.000000&limit=1000&offset=0',
            json=util_load_json('test_data/event.json')
        )
        m.get(
            'https://your.domain/rest/api/3/auditing/record?from=2022-04-10T00:00:00.000000&limit=1000&offset=1000',
            json={}
        )

        from JiraSIEM import main
        main()

    assert not last_run.return_value.get('next_time')
    assert last_run.return_value.get('from') == '2022-04-12T18:40:42.968'
    assert last_run.return_value.get('offset') == 0
