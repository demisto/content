"""Qintel QSentryFeed Integration for Cortex XSOAR - Unit Tests file"""

import json
import io

MOCK_URL = 'https://this-is-only-a-test.local'
MOCK_TOKEN = 'my-token'


def util_load_json(path):

    with io.open(path, mode='r', encoding='utf-8') as f:
        lines = f.readlines()
        lines = [json.loads(line.rstrip('\n')) for line in lines]
        return lines


def test_make_timestamp():

    from QintelQSentryFeed import _make_timestamp
    from datetime import datetime

    res = _make_timestamp(None)
    assert res is None

    res = _make_timestamp(1626211855)
    assert isinstance(res, datetime)
    assert res.isoformat() == '2021-07-13T21:30:55'

    res = _make_timestamp('2021-07-13T21:30:55')
    assert isinstance(res, datetime)
    assert int(res.timestamp()) == 1626211855


def test_dbot_score():
    """Tests dbot score generation
    """

    from QintelQSentryFeed import _make_dbot_score

    assert _make_dbot_score(['test'], {}) == 2
    assert _make_dbot_score(['test', 'Cdn'], {}) == 0
    assert _make_dbot_score(['test', 'Criminal'], {}) == 3

    params = {'feedReputation': 'Unknown'}
    assert _make_dbot_score(['test', 'Criminal'], params) == 0

    params = {'feedReputation': 'Good'}
    assert _make_dbot_score(['test', 'Criminal'], params) == 1


def test_test_module(mocker):
    """Tests test-module command function with valid response.

    Checks the output of the command function with the expected output.
    """

    from QintelQSentryFeed import Client, test_module

    client = Client(base_url=MOCK_URL, verify=False, token=MOCK_TOKEN)

    mock_response = util_load_json('test_data/test_module.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_response)

    response = test_module(client)

    assert response == 'ok'


def test_fetch_indicators_anon(mocker):
    """Tests fetch-indicators command function with valid response.

    Checks the output of the command function with the expected output for an
    anon feed
    """

    from QintelQSentryFeed import Client, fetch_indicators_command

    client = Client(base_url=MOCK_URL, verify=False, token=MOCK_TOKEN)

    mock_response = util_load_json('test_data/anon_feed.jsonl')
    mocker.patch.object(Client, 'fetch', return_value=mock_response)

    params = {
        'feeds': ['Anonymization'],
        'tlp_color': 'AMBER'
    }

    response = fetch_indicators_command(client, params)

    assert len(response) == 5

    i = response[0]

    assert i['value'] == '101.100.146.147'
    assert i['type'] == 'IP'
    assert i['fields']['service'] == 'QSentry Anonymization'
    assert i['fields']['tags'] == ['Tor', 'Tor_exitnodes', 'Cdn']
    assert i['fields']['trafficlightprotocol'] == 'AMBER'
    assert i['fields']['description'] == 'This IP address has been ' \
                                         'associated with the TOR network.'
    assert i['score'] == 0
    assert i['rawJSON'] == mock_response[0]

    i = response[1]
    assert i['value'] == '101.99.90.171'
    assert i['fields']['tags'] == ['Tor', 'Tor_exitnodes', 'Criminal']
    assert i['score'] == 3

    i = response[2]
    assert i['value'] == '102.130.113.37'
    assert i['fields']['tags'] == ['Tor', 'Tor_exitnodes']
    assert i['score'] == 2


def test_fetch_indicators_mal_hosting(mocker):
    """Tests fetch-indicators command function with valid response.

    Checks the output of the command function with the expected output for a
    malicious hosting feed
    """

    from QintelQSentryFeed import Client, fetch_indicators_command

    client = Client(base_url=MOCK_URL, verify=False, token=MOCK_TOKEN)

    mock_response = util_load_json('test_data/mal_hosting.jsonl')
    mocker.patch.object(Client, 'fetch', return_value=mock_response)

    params = {
        'feeds': ['Malicious Hosting'],
        'tlp_color': 'AMBER'
    }

    response = fetch_indicators_command(client, params)

    assert len(response) == 2

    i = response[0]

    assert i['value'] == '192.168.1.0/29'
    assert i['type'] == 'CIDR'
    assert i['fields']['service'] == 'QSentry Malicious Hosting'
    assert i['fields']['tags'] == ['Malicious Hosting']
    assert i['fields']['trafficlightprotocol'] == 'AMBER'
    assert i['fields']['description'] == 'This IP address belongs to a network block that has been abused by nation state actors'
    assert i['score'] == 3
    assert i['rawJSON'] == mock_response[0]
