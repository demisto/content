from CommonServerPython import *

import json
import pytest
from pytest import raises

from freezegun import freeze_time
from dateparser import parse
from pytz import utc

# Only a test key, no worries.
TEST_API_KEY = '1.eyJleHAiOiAxNjI1NjYxMDc3fQ=='


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
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


@freeze_time("2021-01-15")
def test_calculate_fetch_start_time_dynamic(mocker):
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


@pytest.mark.parametrize(
    'guardicore_severity, dbot_score',
    [
        (0, 1),
        (None, 0),
        (-1, 1),
        (121, 3),
        (50, 3),
        (40, 2),
        (30, 1),
    ]
)
def test_incident_severity_to_dbot_score(guardicore_severity, dbot_score):
    """Unit test
    Given
    - zero number
    - None
    - minus 1
    - A number that is big
    - High severity
    - Medium severity
    - Low severity
    When
    - we try to map the guardicore severity to dbot score
    Then
    - return Low (1)
    - return Unkown (0)
    - return Low (1)
    - return High (3)
    - return High (3)
    - return Medium (2)
    - return Low (1)
    """
    from GuardiCoreV2 import incident_severity_to_dbot_score
    assert incident_severity_to_dbot_score(guardicore_severity) == dbot_score


@pytest.mark.parametrize(
    'guardicore_os, os_string',
    [
        (-1, 'Unknown'),
        (None, 'Unknown'),
        (0, 'Unknown'),
        (1, 'Windows'),
        (2, 'Linux'),
    ]
)
def test_map_guardicore_os(guardicore_os, os_string):
    """Unit test
       Given
       - minus one
       - None
       - zero
       - one
       - two
       When
       - trying to map the guardicore os number to string
       Then
       - should return Unknown
       - should return Unknown
       - should return Unknown
       - should return Windows
       - should return Linux
   """
    from GuardiCoreV2 import map_guardicore_os
    assert map_guardicore_os(guardicore_os) == os_string


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
    assert response[0].readable_output == open(
        'test_data/endpoint_command_human.md').read()


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

    # Transform the raw results to be more readable
    hr = []
    for res in response.raw_response:
        row = filter_human_readable(res, human_columns=INCIDENT_COLUMNS)
        row['start_time'] = timestamp_to_datestring(row['start_time'])
        row['end_time'] = timestamp_to_datestring(row['end_time'])
        hr.append(row)

    assert response.outputs == hr
    assert response.raw_response == mock_response.get('objects')


@freeze_time("2021-10-26 10:12:03")
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
    incidents, last_fetch, _ = fetch_incidents(client, {})
    # Fetch first time, then change last fetch
    last_three = int(parse('3 days').replace(tzinfo=utc).timestamp()) * 1000
    assert last_fetch == last_three


@freeze_time("2021-01-22 15:30:22.222")
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
    incidents, last_fetch, _ = fetch_incidents(client, {
        'first_fetch': '40 years'})  # if xsoar is still here when this is a bug then we have a good problem on our hands :)
    # Fetch first time, then change last fetch
    assert last_fetch == 1611322222222
    assert incidents[0].get('name') == 'Guardicore Incident (INC-ADB636B7)'
    assert len(incidents) == 2

    mocker.patch.object(demisto, 'getLastRun',
                        return_value={
                            'last_fetch': last_fetch})
    requests_mock.get('https://api.guardicoreexample.com/api/v3.0/incidents',
                      json=incidents_data.get('second'))

    incidents, last_fetch, _ = fetch_incidents(client, {})
    # Now we should see the last fetch changed
    assert last_fetch == 1611322333333
    assert len(incidents) == 1


@freeze_time("2021-01-22 15:30:22.222")
def test_fetch_incidents_no_duplicates(mocker, requests_mock):
    """
    Given:
    - Two sequential fetch runs
    When:
    - API in first fetch returns two (unsorted) incidents:
      1. id=aa02280b-3f49-403e-b232-a263ee822d52, start_time=1611322222222
      2. id=adb636b7-f941-438f-82ce-c0f44ddb5324, start_time=1611322111111
    - API in second fetch returns two incidents:
      1. id=aa02280b-3f49-403e-b232-a263ee822d52, start_time=1611322222222 (already fetched)
      2. id=79bb091f-0b87-43cf-a383-03badd9ff546, start_time=1611322333333
    Then:
    - Verify the incidents in the first fetch run are sorted by occurrence
    - Verify that the 2nd fetch returns only the latest incident
    - Verify last_fetch is increased and last_ids contains the ID of the latest incident
    """
    from GuardiCoreV2 import Client, fetch_incidents
    fetch_params = {'first_fetch': '3 days'}
    incidents_data = util_load_json('test_data/fetch_incidents_no_duplicates.json')
    requests_mock.post(
        'https://api.guardicoreexample.com/api/v3.0/authenticate',
        json={'access_token': TEST_API_KEY},
    )
    client = Client(base_url='https://api.guardicoreexample.com/api/v3.0',
                    verify=False, proxy=False, username='test', password='test')

    # fetch first
    requests_mock.get(
        'https://api.guardicoreexample.com/api/v3.0/incidents',
        json=incidents_data.get('first'),
    )
    incidents, last_fetch, last_ids = fetch_incidents(client, fetch_params)
    assert len(incidents) == 2
    assert "adb636b7" in incidents[0]["name"].lower()
    assert "aa02280b" in incidents[1]["name"].lower()

    # second fetch
    mocker.patch.object(
        demisto,
        'getLastRun',
        return_value={'last_fetch': last_fetch, 'last_ids': last_ids},
    )
    requests_mock.get(
        'https://api.guardicoreexample.com/api/v3.0/incidents',
        json=incidents_data.get('second'),
    )
    incidents, second_run_last_fetch, last_ids = fetch_incidents(client, fetch_params)
    assert len(incidents) == 1
    assert "aa02280b" not in incidents[0]["name"].lower()
    assert last_fetch < second_run_last_fetch
    assert last_ids == ["79bb091f-0b87-43cf-a383-03badd9ff546"]
