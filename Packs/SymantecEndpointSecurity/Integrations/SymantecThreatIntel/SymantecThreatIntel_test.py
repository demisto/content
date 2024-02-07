"""Symantec Endpoint Security Threat Intel- Unit Tests file

Pytest Unit Tests: all function names must start with "test_"
"""

import json
import pytest

from SymantecThreatIntel import Client, file_reputation_command, url_reputation_command, domain_reputation_command, \
    ip_reputation_command, ensure_argument


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('file, output', [('eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d',
                                          {'indicator': 'eec3f761f7eabe9ed569f39e896be24c9bbb8861b15dbde1b3d539505cd9dd8d',
                                           'reputation': 'BAD', 'actors': ['Waterbug']})])
def test_file_reputation_command(file, output, mocker):
    client = Client('')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/file_insight_reputation_response.json'))
    response = file_reputation_command(client, {'file': file})
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize('url, output', [('elblogdeloscachanillas.com.mx%2Fs3sy8rq10%2Fophn.png',
                                          {'indicator': 'elblogdeloscachanillas.com.mx%2Fs3sy8rq10%2Fophn.png',
                                           'reputation': 'BAD', 'risk_level': 10, 'categories': ['Malicious Sources/Malnets']})])
def test_url_reputation_command(url, output, mocker):
    client = Client('')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/url_insight_reputation_response.json'))
    response = url_reputation_command(client, {'url': url})
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize('domain, output', [('elblogdeloscachanillas.com.mx', {'indicator': 'elblogdeloscachanillas.com.mx',
                                                                               'reputation': 'BAD', 'risk_level': 10,
                                                                               'categories': ['Malicious Sources/Malnets']})])
def test_domain_reputation_command(domain, output, mocker):
    client = Client('')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/domain_insight_reputation_response.json'))
    response = domain_reputation_command(client, {'domain': domain})
    assert len(response) == 1
    assert response[0].outputs == output


@pytest.mark.parametrize('ip, output', [('8.8.8.8', {'indicator': '8.8.8.8', 'reputation': 'GOOD',
                                                     'risk_level': 2, 'categories': ['Web Infrastructure']})])
def test_ip_reputation_command(ip, output, mocker):
    client = Client('')
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/ip_insight_reputation_response.json'))
    response = ip_reputation_command(client, {'ip': ip})
    assert len(response) == 1
    assert response[0].outputs == output


def test_symantec_protection_file_command():
    pass


def test_symantec_protection_network_command():
    pass


def test_symantec_protection_cve_command():
    pass


@pytest.mark.parametrize('args, name, output', [({'ip': '8.8.8.8'}, 'ip', ['8.8.8.8'])])
def test_ensure_argument(args, name, output):
    assert ensure_argument(args, name) == output


@pytest.mark.parametrize('args, name', [({}, 'ip'), ({'ip': ''}, 'ip')])
def test_ensure_argument_exception(args, name):
    with pytest.raises(ValueError):
        ensure_argument(args, name)
