"""Qintel QWatch Integration for Cortex XSOAR - Unit Tests file"""

import json
import io

MOCK_URL = 'https://this-is-only-a-test.local'
MOCK_CLIENT_ID = 'client-id'
MOCK_CLIENT_SECRET = 'client-secret'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_make_timestamp():

    from QintelQWatch import _make_timestamp
    from datetime import datetime

    res = _make_timestamp(None)
    assert res is None

    res = _make_timestamp(1626211855)
    assert isinstance(res, datetime)
    assert res.isoformat() == '2021-07-13T21:30:55'

    res = _make_timestamp('2021-07-13T21:30:55')
    assert isinstance(res, datetime)
    assert int(res.timestamp()) == 1626211855


def test_test_module(mocker):
    """Tests test-module command function with valid response.

    Checks the output of the command function with the expected output.
    """

    from QintelQWatch import Client, test_module

    client = Client(base_url=MOCK_URL, verify=False, client_id=MOCK_CLIENT_ID,
                    client_secret=MOCK_CLIENT_SECRET)

    mock_response = util_load_json('test_data/test_module.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    response = test_module(client)

    assert response == 'ok'


def test_fetch_incidents_command(mocker):
    """Tests fetch-incidents command function with valid response.

    Checks the output of the command function with the expected output when
    plaintext passwords ARE requested.
    """

    from QintelQWatch import Client, fetch_incidents

    client = Client(base_url=MOCK_URL, verify=False, client_id=MOCK_CLIENT_ID,
                    client_secret=MOCK_CLIENT_SECRET)

    mock_response = util_load_json('test_data/qwatch_data.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    params = {
        'first_fetch': '90 days',
        'fetch_severity': 'Medium',
        'fetch_passwords': True
    }

    response = fetch_incidents(client, params)

    assert len(response) == 1

    rawJSON = json.loads(response[0]['rawJSON'])

    assert len(rawJSON['QWatch']['Exposures']) == 3

    record = rawJSON['QWatch']['Exposures'][0]

    assert record['email'] == 'test@example.local'
    assert record['password'] == 'SuperSecretPassword'
    assert record['source'] == 'combo-BigComboList'
    assert record['loaded'] == '2021-02-05 04:35:33'


def test_fetch_incidents_command_no_password(mocker):
    """Tests fetch-incidents command function with valid response.

    Checks the output of the command function with the expected output when
    plaintext passwords are NOT requested.
    """

    from QintelQWatch import Client, fetch_incidents

    client = Client(base_url=MOCK_URL, verify=False, client_id=MOCK_CLIENT_ID,
                    client_secret=MOCK_CLIENT_SECRET)

    mock_response = util_load_json('test_data/qwatch_data.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    params = {
        'first_fetch': '90 days',
        'fetch_severity': 'Medium'
    }

    response = fetch_incidents(client, params)

    assert len(response) == 1

    rawJSON = json.loads(response[0]['rawJSON'])

    assert len(rawJSON['QWatch']['Exposures']) == 3

    record = rawJSON['QWatch']['Exposures'][0]

    assert record['email'] == 'test@example.local'
    assert record['password'] is None
    assert record['source'] == 'combo-BigComboList'
    assert record['loaded'] == '2021-02-05 04:35:33'


def test_fetch_incidents_command_no_results(mocker):
    """Tests fetch-incidents command function with valid response.

    Checks the output of the command function with the expected output when
    no results are returned.
    """

    from QintelQWatch import Client, fetch_incidents

    client = Client(base_url=MOCK_URL, verify=False, client_id=MOCK_CLIENT_ID,
                    client_secret=MOCK_CLIENT_SECRET)

    mock_response = util_load_json('test_data/qwatch_data_empty.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    params = {
        'first_fetch': '90 days',
        'fetch_severity': 'Medium'
    }

    response = fetch_incidents(client, params)

    assert len(response) == 0


def test_search_exposures(mocker):
    """Tests qintel-qwatch-exposures command function with valid response.

    Checks the output of the command function with the expected output
    """

    from QintelQWatch import Client, search_exposures

    client = Client(base_url=MOCK_URL, verify=False, client_id=MOCK_CLIENT_ID,
                    client_secret=MOCK_CLIENT_SECRET)

    mock_response = util_load_json('test_data/qwatch_data.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    args = {
        'email': 'test@example.local',
    }

    params = {
        'fetch_passwords': True
    }

    response = search_exposures(client, args, params)

    assert len(response) == 1

    outputs = response[0].outputs
    hr = response[0].readable_output
    prefix = response[0].outputs_prefix

    assert prefix == 'Qintel'

    assert 'Qintel QWatch exposures for: test@example.local' in hr
    assert '|Email|Password|Source|Loaded|First Seen|Last Seen|' in hr
    assert 'test@example.local | SuperSecretPassword | ' \
           'malware-evilbot_March_22_2020 | 2020-03-25 09:38:40 |' in hr

    record = outputs['QWatch']['Exposures'][0]

    assert record['email'] == 'test@example.local'
    assert record['password'] == 'SuperSecretPassword'
    assert record['source'] == 'combo-BigComboList'
    assert record['loaded'] == '2021-02-05 04:35:33'
