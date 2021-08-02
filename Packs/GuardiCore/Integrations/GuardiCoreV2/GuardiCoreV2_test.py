from CommonServerPython import *

import json
import io
import pytest
from pytest import raises


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
    """Unit test
    Given
    - empty jwt token
    - a valid jwt token
    When
    - we mock the token generation.
    - we mock the token generation.
    Then
    - return an empty expiration
    - extract the jwt token expiration
    Validate that the expiration is correct.
    """
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
    """Unit test
    Given
    - an empty results dict
    - a valid result dict
    - a valid result dict and a filter column
    - a valid result dict and two filter columns
    When
    - we filter the relevant columns.
    Then
    - return an empty filtered result dict
    - return an empty filtered result dict
    - return a filtered result dict with one column
    - return a filtered result dict with two columns
    Validate that the filter human readable returns correct values.
    """
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
    """Unit test
    Given
    - a last_fetch time and no first_fetch
    - a last_fetch time and a first_fetch
    When
    - we try to calcualte the current fetch time for fetch incidents.
    Then
    - return the last_fetch
    - return the last_fetch
    Validate that the calculation is correct.
    """
    from GuardiCoreV2 import calculate_fetch_start_time
    assert calculate_fetch_start_time(last_fetch, first_fetch) == output


def test_calculate_fetch_start_time_dynamic():
    """Unit test
    Given
    - no last_fetch time no first_fetch
    - no last_fetch time and a first_fetch (4 days)
    When
    - we try to calcualte the current fetch time for fetch incidents.
    Then
    - return the a last_fetch of 3 days ago approx (default)
    - return the a last_fetch of 4 days ago approx
    Validate that the calculation is correct.
    """
    from GuardiCoreV2 import calculate_fetch_start_time
    out = int(parse('3 days').replace(tzinfo=utc).timestamp()) * 1000
    assert calculate_fetch_start_time(None, None) - out < 1000
    out = int(parse('4 days').replace(tzinfo=utc).timestamp()) * 1000
    assert calculate_fetch_start_time(None, '4 days') - out < 1000


def test_authenticate(requests_mock):
    """Unit test
    Given
    - a username and password
    When
    - we mock the authentication to the integration api endpoint.
    Then
    - Validate that the access_token is returned correctly.
    """
    from GuardiCoreV2 import Client
    requests_mock.post(
        'https://api.guardicoreexample.com/api/v3.0/authenticate',
        json={'access_token': TEST_API_KEY})
    client = Client(base_url='https://api.guardicoreexample.com/api/v3.0',
                    verify=False, proxy=False, username='test', password='test')

    assert client.access_token == TEST_API_KEY


def test_get_incident(mocker, requests_mock):
    """Unit test
    Given
    - an incident id
    When
    - we mock the incident get api call
    Then
    - Validate that the correct response is returned
    """
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


def test_get_assets(mocker, requests_mock):
    """Unit test
    Given
    - an ip
    When
    - we mock the endpoint asset get api call
    Then
    - Validate that there is one result
    - Validate that the correct output is returned
    """
    from GuardiCoreV2 import Client, get_assets
    mock_response = util_load_json('test_data/get_assets_response.json')
    requests_mock.post(
        'https://api.guardicoreexample.com/api/v3.0/authenticate',
        json={'access_token': TEST_API_KEY})
    client = Client(base_url='https://api.guardicoreexample.com/api/v3.0',
                    verify=False, proxy=False, username='test', password='test')
    args = {
        'ip_address': '1.1.1.1'
    }
    mocker.patch.object(client, '_http_request', return_value=mock_response)
    response = get_assets(client, args)
    assert len(response) == 1
    response = response[0]
    assert response.outputs == {
        'asset_id': '920b9a05-889e-429e-97d0-94a92ccbe376',
        'ip_addresses': ['1.1.1.1', 'fe80::250:56ff:fe84:da1e'],
        'last_seen': 1627910241995,
        'name': 'Accounting-web-1',
        'status': 'on',
        'tenant_name': 'esx10/lab_a/Apps/Accounting'}


def test_endpoint_command_fails(mocker, requests_mock):
    """Unit test
    Given
    - no parameters
    When
    - we mock the endpoint command
    Then
    - Validate that there is a correct error
    """
    from GuardiCoreV2 import Client, endpoint_command
    mock_response = util_load_json('test_data/get_endpoint_response.json')
    requests_mock.post(
        'https://api.guardicoreexample.com/api/v3.0/authenticate',
        json={'access_token': TEST_API_KEY})
    client = Client(base_url='https://api.guardicoreexample.com/api/v3.0',
                    verify=False, proxy=False, username='test', password='test')
    args = {}
    mocker.patch.object(client, '_http_request', return_value=mock_response)
    with raises(DemistoException):
        endpoint_command(client, args)


def test_endpoint_command(mocker, requests_mock):
    """Unit test
    Given
    - a hostname
    When
    - we mock the endpoint command
    Then
    - Validate that there is one result
    - Validate that the correct readable output is returned
    """
    from GuardiCoreV2 import Client, endpoint_command
    mock_response = util_load_json('test_data/get_endpoint_response.json')
    requests_mock.post(
        'https://api.guardicoreexample.com/api/v3.0/authenticate',
        json={'access_token': TEST_API_KEY})
    client = Client(base_url='https://api.guardicoreexample.com/api/v3.0',
                    verify=False, proxy=False, username='test', password='test')
    args = {
        'hostname': 'Accounting-web-1'
    }
    mocker.patch.object(client, '_http_request', return_value=mock_response)
    response = endpoint_command(client, args)
    assert len(response) == 1
    assert response[0].readable_output == '''### GuardiCoreV2 - Endpoint: Accounting-web-1
|Hostname|ID|IPAddress|MACAddress|OS|OSVersion|Vendor|
|---|---|---|---|---|---|---|
| Accounting-web-1 | 920b9a05-889e-429e-97d0-94a92ccbe376 | 1.1.1.1, fe80::250:56ff:fe84:da1e | 00:50:56:84:da:1e | 2 | Ubuntu 16.04.6 LTS | GuardiCore Response |
'''


def test_get_incidents(mocker, requests_mock):
    """Unit test
    Given
    - an incident from and to time, with a limit of 3
    When
    - we mock the incidents get api call
    Then
    - Validate that the correct responses are returned
    """
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
    """Unit test
    Given
    - na
    When
    - we mock the fetch incidents flow
    Then
    - Validate that the last_fetch is correct (deafult of 3 past days)
    """
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
    """Unit test
    Given
    - a first_fetch time (of 40 days)
    When
    - we mock the fetch incidents flow
    - we mock the fetch incidents flow is called twice
    Then
    - Validate that the last_fetch is correct (unix time of 40 days)
    - Validate that the first incident returned has a correct id
    - Validate that the length of the incidents is correct
    - Validate that the last_fetch is the last incident fetched
    - Validate that the incidents are all fetched (only 1 new one)
    """
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
