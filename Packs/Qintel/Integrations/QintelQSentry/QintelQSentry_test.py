"""Qintel QSentry Integration for Cortex XSOAR - Unit Tests file"""

import json

MOCK_URL = 'https://this-is-only-a-test.local'
MOCK_CLIENT_ID = 'client-id'
MOCK_CLIENT_SECRET = 'client-secret'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_make_timestamp():

    from QintelQSentry import _make_timestamp
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

    from QintelQSentry import Client, test_module

    client = Client(base_url=MOCK_URL, verify=False, client_id=MOCK_CLIENT_ID,
                    client_secret=MOCK_CLIENT_SECRET)

    mock_response = util_load_json('test_data/test_module.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    response = test_module(client)

    assert response == 'ok'


def test_ip_command(mocker):
    """Tests ip reputation command function with valid response.

    Checks the output of the command function with the expected output.
    """

    from QintelQSentry import Client, ip_command

    client = Client(base_url=MOCK_URL, verify=False, client_id=MOCK_CLIENT_ID,
                    client_secret=MOCK_CLIENT_SECRET)

    mock_response = util_load_json('test_data/ip_command.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    args = {
        'ip': '192.168.35.100',
    }

    response = ip_command(client, args)

    assert len(response) == 1

    outputs = response[0].outputs
    hr = response[0].readable_output
    prefix = response[0].outputs_prefix

    assert prefix == 'Qintel.IP'

    assert 'Qintel results for IP: 192.168.35.100' in hr
    assert '|ASN|AS Owner|Tags|Description|Last Observed|' in hr
    assert '| 65000 | Some Service Provider | Criminal,<br>Proxy,<br>Vpn |' \
           in hr

    assert outputs['Address'] == '192.168.35.100'
    assert outputs['Tags'] == ['Criminal', 'Proxy', 'Vpn']
    assert len(outputs['Description']) == 4
    assert outputs['LastObserved'] == '2021-07-29 11:00:00'
