import json
import io
import pytest
import requests_mock
from freezegun import freeze_time


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    'params, url',
    [
        (
            {
                'method': 'GET',
                'url': 'https://your.domain/rest/api/3/auditing/record',
                'max_fetch': 10,
                'first_fetch': '4 days',
                'credentials': {
                    'identifier': 'admin@your.domain',
                    'password': '123456',
                }
            },
            'https://your.domain/rest/api/3/auditing/record?from=2022-04-10T00:00:00.000000&limit=1000&offset=0'
        ),
        (
            {
                'method': 'GET',
                'url': 'https://your.domain/rest/api/3/auditing/record',
                'max_fetch': 10,
                'first_fetch': '1 hour',
                'credentials': {
                    'identifier': 'admin@your.domain',
                    'password': '123456',
                }
            },
            'https://your.domain/rest/api/3/auditing/record?from=2022-04-13T23:00:00.000000&limit=1000&offset=0'
        )
    ]
)
@freeze_time('2022-04-14T00:00:00Z')
def test_fetch_incidents(mocker, params, url):
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
    mocker.patch.object(demisto, 'params', return_value=params)
    last_run = mocker.patch.object(demisto, 'getLastRun', return_results={'demo': 0})
    events = mocker.patch.object(demisto, 'results')
    incidents = mocker.patch.object(demisto, 'incidents')

    with requests_mock.Mocker() as m:
        mock_response = util_load_json('test_data/events.json')
        m.get(url, json=mock_response)

        from JiraSIEM import main
        main()

    assert events
    assert incidents
