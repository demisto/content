"""Symantec Endpoint Security Threat Intel- Unit Tests file

Pytest Unit Tests: all function names must start with "test_"
"""

import json
import pytest
from CommonServerPython import *
from SymantecThreatIntel import Client, file_reputation_command, url_reputation_command, domain_reputation_command, \
    ip_reputation_command, ensure_argument, is_filtered, symantec_protection_file_command, symantec_protection_cve_command, \
    symantec_protection_network_command, get_indicator_by_type
BASE_RELIABILITY = DBotScoreReliability.B


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('file, output', [('eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d',
                                          {'indicator': 'eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d',
                                           'reputation': 'BAD', 'actors': ['Waterbug']})])
def test_file_reputation_command(file, output, mocker):
    client = Client('', '')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/file_insight_reputation_response.json'))
    response = file_reputation_command(client, {'file': file}, BASE_RELIABILITY)
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize('url, output', [('elblogdeloscachanillas.com.mx%2Fs3sy8rq10%2Fophn.png',
                                          {'indicator': 'elblogdeloscachanillas.com.mx%2Fs3sy8rq10%2Fophn.png',
                                           'reputation': 'BAD', 'risk_level': 10, 'categories': ['Malicious Sources/Malnets'],
                                           'first_seen': None, 'last_seen': None})])
def test_url_reputation_command(url, output, mocker):
    client = Client('', '')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/url_insight_reputation_response.json'))
    response = url_reputation_command(client, {'url': url}, BASE_RELIABILITY)
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize('domain, output', [('elblogdeloscachanillas.com.mx', {'indicator': 'elblogdeloscachanillas.com.mx',
                                                                               'reputation': 'BAD', 'risk_level': 10,
                                                                               'categories': ['Malicious Sources/Malnets'],
                                                                               'first_seen': '2019-08-30',
                                                                               'last_seen': '2024-01-24'})])
def test_domain_reputation_command(domain, output, mocker):
    client = Client('', '')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/domain_insight_reputation_response.json'))

    response = domain_reputation_command(client, {'domain': domain}, BASE_RELIABILITY)
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize('ip, output', [('8.8.8.8', {'indicator': '8.8.8.8', 'reputation': 'GOOD',
                                                     'risk_level': 2, 'categories': ['Web Infrastructure'],
                                                     'first_seen': '2023-07-10', 'last_seen': '2023-12-18'
                                                     })])
def test_ip_reputation_command(ip, output, mocker):
    client = Client('', '')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/ip_insight_reputation_response.json'))
    response = ip_reputation_command(client, {'ip': ip}, BASE_RELIABILITY)
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize('file, output', [('eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d',
                                          util_load_json('test_data/file_protection_response.json'))])
def test_symantec_protection_file_command(file, output, mocker):
    client = Client('', '')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/file_protection_response.json'))
    response = symantec_protection_file_command(client, {'file': file})
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize('network, output', [('eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d',
                                              util_load_json('test_data/network_protection_response.json'))])
def test_symantec_protection_network_command(network, output, mocker):
    client = Client('', '')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/network_protection_response.json'))
    response = symantec_protection_network_command(client, {'network': network})
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize('cve, output', [('eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d',
                                          util_load_json('test_data/cve_protection_response.json'))])
def test_symantec_protection_cve_command(cve, output, mocker):
    client = Client('', '')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/cve_protection_response.json'))
    response = symantec_protection_cve_command(client, {'cve': cve})
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize('args, name, output', [({'ip': '8.8.8.8'}, 'ip', ['8.8.8.8'])])
def test_ensure_argument(args, name, output):
    assert ensure_argument(args, name) == output


@pytest.mark.parametrize('args, name', [({}, 'ip'), ({'ip': ''}, 'ip')])
def test_ensure_argument_exception(args, name):
    with pytest.raises(ValueError):
        ensure_argument(args, name)


@pytest.mark.parametrize('value, filters, output', [('support.paloaltonetworks.com', ['paloaltonetworks.com'], True)])
def test_is_filtered(value: str, filters: list[str], output: bool):
    assert is_filtered(value, filters) == output


@pytest.mark.parametrize('response, result', [({'access_token': 'YXNhbXBsZWFjY2Vzc3Rva2VudGNvZGU='}, True)])
def test_client_authenticate(response, result, mocker):
    client = Client('', '')
    mocker.patch.object(Client, '_http_request', return_value=response)
    assert client.authenticate() == result
    assert client._session_token == response.get('access_token')


@pytest.mark.parametrize('type, indicator, score, result', [('', '', None, None)])
def test_get_indicator_by_type(type: str, indicator: str, score: Common.DBotScore, result: Common.Indicator | None):
    assert get_indicator_by_type(type=type, indicator=indicator, dbot_score=score) == result
