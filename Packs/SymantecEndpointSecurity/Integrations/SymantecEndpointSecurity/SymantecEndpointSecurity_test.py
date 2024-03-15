"""Symantec Endpoint Security Thret Intel- Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"
"""

import json
import pytest
from datetime import datetime, timedelta, timezone
from SymantecEndpointSecurity import Client, icdm_fetch_incidents_command, fetch_incidents_command, \
    ensure_max_age

DATE_TIME = datetime.now(tz=timezone.utc).replace(second=0, microsecond=0)
AN_HOUR_AGO = DATE_TIME - timedelta(hours=1)
TWO_MONTHS_AGO = DATE_TIME - timedelta(days=60)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('value, output', [(AN_HOUR_AGO, AN_HOUR_AGO),
                                           (TWO_MONTHS_AGO,
                                            DATE_TIME - timedelta(days=29, hours=23, minutes=59))])
def test_ensure_max_age(value: datetime, output: datetime):
    """
    Given:
        - Mocked date
    When:
        - sent to ensure_max_age
    Then:
        - ensure the age matches the expected output
    """
    value = value.replace(second=0, microsecond=0)
    result = ensure_max_age(value)
    result = result.replace(second=0, microsecond=0)
    assert result == output


def test_icdm_fetch_incidents_command(mocker):
    client = Client('', '')
    incidents = util_load_json('test_data/icdm_incidents_without_events.json')
    mocker.patch.object(Client, '_http_request', return_value=incidents)
    result = icdm_fetch_incidents_command(client, 100, datetime(2023, 4, 26, 0, 0, 0, tzinfo=timezone.utc))

    assert result.outputs == incidents.get('incidents')

    expected_hr = (
        '### Symantec Endpoint Security EDR Incidents\n'
        '|ref_incident_uid|type|conclusion|created|modified|\n'
        '|---|---|---|---|---|\n'
        '| 102106 | INCIDENT_UPDATE | Suspicious Activity | 2023-04-26T15:44:19.345+00:00 | 2023-04-26T23:38:48.634+00:00 |\n'
        '| 102109 | INCIDENT_CREATION | Suspicious Activity | 2023-04-26T21:28:00.467+00:00 | 2023-04-26T21:52:51.550+00:00 |\n'
        '| 102110 | INCIDENT_CREATION | Suspicious Activity | 2023-04-26T21:46:10.400+00:00 | 2023-04-26T22:01:58.648+00:00 |\n')

    assert result.readable_output == expected_hr


def test_fetch_incidents_command(mocker):
    client = Client('', '')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/icdm_incidents_without_events.json'))

    last_run, incidents = fetch_incidents_command(client, 100, datetime(2023, 4, 26, 0, 0, 0, tzinfo=timezone.utc))
    expected_incidents = util_load_json('test_data/outputs/icdm_incidents_output.json')
    assert last_run == {'last_fetch': 1682545570.4}
    assert incidents == expected_incidents


@pytest.mark.parametrize('response, result', [({'access_token': 'YXNhbXBsZWFjY2Vzc3Rva2VudGNvZGU='}, True)])
def test_client_authenticate(response, result, mocker):
    client = Client('', '')
    mocker.patch.object(Client, '_http_request', return_value=response)
    assert client.authenticate() == result
    assert client._session_token == response.get('access_token')
