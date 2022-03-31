
import json
import io
from CensysV2 import Client, censys_view_command, censys_search_command
import pytest

from CommonServerPython import DemistoException

SEARCH_HOST_OUTPUTS = [{
    'ip': '1.0.0.0',
    'services': [
        {'port': 80, 'service_name': 'HTTP', 'transport_protocol': 'TCP'},
        {'port': 443, 'service_name': 'HTTP', 'transport_protocol': 'TCP'}],
    'location': {'continent': 'Oceania', 'country': 'Australia', 'country_code': 'AU', 'timezone': 'Australia/Sydney',
                 'coordinates': {'latitude': -33.494, 'longitude': 143.2104}, 'registered_country': 'Australia',
                 'registered_country_code': 'AU'},
    'autonomous_system': {'asn': 13335, 'description': 'CLOUDFLARENET', 'bgp_prefix': '1.0.0.0/24',
                          'name': 'CLOUDFLARENET', 'country_code': 'US'}}]


SEARCH_CERTS_OUTPUTS = [{
    'parsed':
        {'fingerprint_sha256': 'f3ade17dffcadd9532aeb2514f10d66e22941393725aa65366ac286df9b41234',
         'issuer': {'organization': ["Let's Encrypt"]},
         'issuer_dn': "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
         'names': ['*.45g4rg43g4fr3434g.gb.net', '45g4rg43g4fr3434g.gb.net'],
         'subject_dn': 'CN=45g4rg43g4fr3434g.gb.net',
         'validity': {'end': '2021-01-10T14:46:11Z', 'start': '2020-10-12T14:46:11Z'}}}]


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    client = Client(base_url='https://search.censys.io/api/', auth=('test', '1234'), verify=True, proxy=False)
    return client


def test_censys_host_search(requests_mock, client):
    """
    Given:
        Command arguments: query and limit
    When:
        Running cen_search_command
    Then:
        Validate the output compared to the mock output
    """
    args = {
        'index': 'ipv4',
        'query': 'services.service_name:HTTP',
        'limit': 1
    }

    mock_response = util_load_json('test_data/search_host_response.json')
    requests_mock.get('https://search.censys.io/api/v2/hosts/search', json=mock_response)
    response = censys_search_command(client, args)
    assert "### Search results for query \"services.service_name:HTTP\"" in response.readable_output
    assert response.outputs == SEARCH_HOST_OUTPUTS


def test_censys_certs_search(requests_mock, client):
    """
    Given:
        Command arguments: query and limit
    When:
        Running cen_search_command
    Then:
        Validate the output compared to the mock output
    """
    args = {
        'index': 'certificates',
        'query': "parsed.issuer.common_name: \"Let's Encrypt\"",
        'fields': ['parsed.fingerprint_sha1', 'validation.apple.valid']
    }

    mock_response = util_load_json('test_data/search_certs_response.json')
    requests_mock.post('https://search.censys.io/api/v1/search/certificates', json=mock_response)
    response = censys_search_command(client, args)
    history = requests_mock.request_history[0]
    assert json.loads(history.text)['fields'] == ['parsed.fingerprint_sha256', 'parsed.subject_dn',
                                                  'parsed.issuer_dn', 'parsed.issuer.organization',
                                                  'parsed.validity.start', 'parsed.validity.end', 'parsed.names',
                                                  'parsed.fingerprint_sha1', 'validation.apple.valid']
    assert response.outputs == SEARCH_CERTS_OUTPUTS
    assert "### Search results for query \"parsed.issuer.common_name: \"Let's Encrypt\"" in response.readable_output


def test_censys_view_host(requests_mock, client):
    """
    Given:
        Command arguments: query ip = 8.8.8.8
    When:
        Running cen_view_command
    Then:
        Validate the output compared to the mock output
    """
    args = {
        'index': 'ipv4',
        'query': "8.8.8.8"
    }
    mock_response = util_load_json('test_data/view_host_response.json')
    requests_mock.get('https://search.censys.io/api/v2/hosts/8.8.8.8', json=mock_response)
    response = censys_view_command(client, args)
    assert '### Information for IP 8.8.8.8' in response.readable_output
    assert response.outputs == mock_response.get('result')


def test_censys_view_host_invalid(requests_mock, client):
    """
    Given:
        Command arguments: query ip = test
    When:
        Running cen_view_command
    Then:
        Validate error message returns.
    """
    args = {
        'index': 'ipv4',
        'query': "test"
    }
    mock_response = {
        "code": 422,
        "status": "Unprocessable Entity",
        "error": "ip: value is not a valid IPv4 or IPv6 address"
    }
    requests_mock.get('https://search.censys.io/api/v2/hosts/test', json=mock_response, status_code=422)
    with pytest.raises(DemistoException):
        censys_view_command(client, args)


def test_censys_view_cert(requests_mock, client):
    """
    Given:
        Command arguments: sha-256
    When:
        Running cen_view_command
    Then:
        Validate the output compared to the mock output
    """
    args = {
        'index': 'certificates',
        'query': "9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f661234"
    }
    mock_response = util_load_json('test_data/view_cert_response.json')
    requests_mock.get('https://search.censys.io/api/v1/view/certificates/9d3b51a6b80daf76e07473'
                      '0f19dc01e643ca0c3127d8f48be64cf3302f661234', json=mock_response)
    response = censys_view_command(client, args)
    assert '### Information for certificate' in response.readable_output
    assert response.outputs == mock_response


def test_test_module_valid(requests_mock, client):
    from CensysV2 import test_module
    requests_mock.get(url='https://search.censys.io/api/v2/hosts/8.8.8.8', status_code=200, json="{}")

    assert test_module(client) == 'ok'
