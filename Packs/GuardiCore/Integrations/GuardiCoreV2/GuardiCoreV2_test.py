import json
import io
import pytest

from dateparser import parse
from pytz import utc

# Only a test key, no worries.
TEST_API_KEY = '1.eyJleHAiOiAxNjI1NjYxMDc3fQ=='


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    'input, output',
    [
        ('', 0),
        (TEST_API_KEY, 1625661077),
    ]
)
def test_get_jwt_expiration(input, output):
    from GuardiCoreV2 import get_jwt_expiration
    assert get_jwt_expiration(input) == output


@pytest.mark.parametrize(
    'input, columns, output',
    [
        ({}, [], {}),
        ({'a': 123, 'b': 321}, [], {}),
        ({'a': 123, 'b': 321}, ['b'], {'b': 321}),
        ({'a': 123, 'b': 321}, ['a', 'b'], {'a': 123, 'b': 321}),
    ]
)
def test_filter_human_readable(input, columns, output):
    from GuardiCoreV2 import filter_human_readable
    assert filter_human_readable(input, human_columns=columns) == output


@pytest.mark.parametrize(
    'last_fetch, first_fetch, output',
    [
        (100000, None, 100000),
        (100000, '1 days', 100000),
    ]
)
def test_calculate_fetch_start_time(last_fetch, first_fetch, output):
    from GuardiCoreV2 import calculate_fetch_start_time
    assert calculate_fetch_start_time(last_fetch, first_fetch) == output


def test_calculate_fetch_start_time_dynamic():
    from GuardiCoreV2 import calculate_fetch_start_time
    out = int(parse('3 days').replace(tzinfo=utc).timestamp()) * 1000
    assert calculate_fetch_start_time(None, None) == out
    out = int(parse('4 days').replace(tzinfo=utc).timestamp()) * 1000
    assert calculate_fetch_start_time(None, '4 days') == out


def test_authenticate(requests_mock):
    from GuardiCoreV2 import Client
    requests_mock.post(
        'https://api.guardicoreexample.com/api/v3.0/authenticate',
        json={'access_token': TEST_API_KEY})
    client = Client(base_url='https://api.guardicoreexample.com/api/v3.0',
                    verify=False, proxy=False, username='test', password='test')

    assert client.access_token == TEST_API_KEY


def test_get_incident(mocker, requests_mock):
    from GuardiCoreV2 import Client, get_indicent
    mock_response = util_load_json('test_data/get_incident_response.json')
    requests_mock.post(
        'https://api.guardicoreexample.com/api/v3.0/authenticate',
        json={'access_token': TEST_API_KEY})
    client = Client(base_url='https://api.guardicoreexample.com/api/v3.0',
                    verify=False, proxy=False, username='test', password='test')
    args = {
        'id': 'c2acca07-e9bf-4d63-9a26-ff6c749d24d2'
    }
    mocker.patch.object(client, '_http_request', return_value=mock_response)
    response = get_indicent(client, args)
    assert response.outputs == mock_response


def test_get_incidents(mocker, requests_mock):
    from GuardiCoreV2 import Client, get_incidents, INCIDENT_COLUMNS, \
        filter_human_readable

    requests_mock.post(
        'https://api.guardicoreexample.com/api/v3.0/authenticate',
        json={'access_token': TEST_API_KEY})
    client = Client(base_url='https://api.guardicoreexample.com/api/v3.0',
                    verify=False, proxy=False, username='test', password='test')
    args = {'from_time': '2021-07-07T15:31:17Z',
            'to_time': '2022-07-07T15:31:17Z', 'limit': 3}
    mock_response = util_load_json('test_data/get_incidents_response.json')
    mocker.patch.object(client, '_http_request', return_value=mock_response)
    response = get_incidents(client, args)
    hr = [filter_human_readable(res, human_columns=INCIDENT_COLUMNS) for
          res in response.raw_response]
    assert response.outputs == hr
    assert response.raw_response == mock_response.get('objects')


def test_fetch_incidents_no_first(mocker, requests_mock):
    from dateparser import parse
    from pytz import utc
    from GuardiCoreV2 import Client, fetch_incidents

    incidents_data = util_load_json('test_data/fetch_incidents_response.json')
    requests_mock.post(
        'https://api.guardicoreexample.com/api/v3.0/authenticate',
        json={'access_token': TEST_API_KEY})
    requests_mock.get('https://api.guardicoreexample.com/api/v3.0/incidents',
                      json=incidents_data.get('first'))

    client = Client(base_url='https://api.guardicoreexample.com/api/v3.0',
                    verify=False, proxy=False, username='test', password='test')
    incidents, last_fetch = fetch_incidents(client, {})
    # Fetch first time, then change last fetch
    last_three = int(parse('3 days').replace(tzinfo=utc).timestamp()) * 1000
    assert last_fetch == last_three


def test_fetch_incidents(mocker, requests_mock):
    from GuardiCoreV2 import Client, fetch_incidents
    from CommonServerPython import \
        demisto  # noqa # pylint: disable=unused-wildcard-importcommon
    incidents_data = util_load_json(
        'test_data/fetch_incidents_response.json')
    requests_mock.post(
        'https://api.guardicoreexample.com/api/v3.0/authenticate',
        json={'access_token': TEST_API_KEY})
    requests_mock.get('https://api.guardicoreexample.com/api/v3.0/incidents',
                      json=incidents_data.get('first'))

    client = Client(base_url='https://api.guardicoreexample.com/api/v3.0',
                    verify=False, proxy=False, username='test', password='test')
    incidents, last_fetch = fetch_incidents(client, {
        'first_fetch': '40 years'})  # if xsoar is still here when this is a bug then we have a good problem on our hands :)
    # Fetch first time, then change last fetch
    assert last_fetch == 1611322222222
    assert incidents[0].get('name') == 'INC-ADB636B7'
    assert len(incidents) == 2

    mocker.patch.object(demisto, 'getLastRun',
                        return_value={
                            'last_fetch': last_fetch})
    requests_mock.get('https://api.guardicoreexample.com/api/v3.0/incidents',
                      json=incidents_data.get('second'))

    incidents, last_fetch = fetch_incidents(client, {})
    # Now we should see the last fetch changed
    assert last_fetch == 1611322333333
    assert len(incidents) == 1
