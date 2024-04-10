
import json
from CensysV2 import Client, censys_view_command, censys_search_command
import pytest

from CommonServerPython import DemistoException


SEARCH_CERTS_OUTPUTS = [{
    "names": ["my-house-vtpvbznpmk.dynamic-m.com"],
    "parsed": {
      "validity_period": {
        "not_after": "2024-07-03T13:17:43Z",
        "not_before": "2024-04-04T13:18:43Z"},
      "issuer_dn": "C=US, O=IdenTrust, OU=HydrantID Trusted Certificate Service, CN=HydrantID Server CA O1",
      "subject_dn": "C=US, ST=California, L=San Jose, O=Cisco Systems Inc., CN=my-house-vtpvbznpmk.dynamic-m.com"},
    "fingerprint_sha256": "ba534c45586595844fc527130c71219c8fdccbf9fb1881fb03ebc1f01f5b7013"}]

def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    client = Client(base_url='https://search.censys.io/', auth=('test', '1234'), verify=True, proxy=False)
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
    assert response.outputs == mock_response.get('result', {}).get('hits', [])


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
        'fields': ['parsed.fingerprint_sha1', 'validation.apple.valid'],
        'limit': 1
    }

    mock_response = util_load_json('test_data/search_certs_response.json')
    requests_mock.get('https://search.censys.io/api/v2/certificates/search', json=mock_response)
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
    requests_mock.get('https://search.censys.io/api/v2/certificates/9d3b51a6b80daf76e07473'
                      '0f19dc01e643ca0c3127d8f48be64cf3302f661234', json=mock_response)
    response = censys_view_command(client, args)
    assert '### Information for certificate' in response.readable_output
    assert response.outputs == mock_response


def test_test_module_valid(requests_mock, client):
    from CensysV2 import test_module
    requests_mock.get(url='https://search.censys.io/api/v2/hosts/8.8.8.8', status_code=200, json="{}")

    assert test_module(client, {}) == 'ok'



def test_test_module_invalid(requests_mock, client):
    from CensysV2 import test_module
    requests_mock.get(url='https://search.censys.io/api/v2/hosts/8.8.8.8', status_code=200, json="{}")

    params = {'premium_access':False, 'malicious_labels':True}
    with pytest.raises(DemistoException):
        test_module(client, params)


def test_censys_host_history_command(requests_mock, client):
    from CensysV2 import censys_host_history_command
    mock_response = util_load_json('test_data/host_history_response.json')
    args = {"ip": '8.8.8.8', 'ip_b': '8.8.4.4'}
    requests_mock.get('https://search.censys.io/api/v2/hosts/8.8.8.8/diff?ip_b=8.8.4.4', json=mock_response)
    response = censys_host_history_command(client, args)
    assert response.outputs == mock_response.get('result')


def test_ip_command_multiple_ips(requests_mock, client):
    from CensysV2 import ip_command
    mock_response = util_load_json('test_data/ip_command_response.json')
    args = {'ip': ['8.8.8.8', '8.8.8.8', '0.0.0.0']}
    requests_mock.get("/api/v2/hosts/search?q=ip=8.8.8.8", json=mock_response)
    requests_mock.get("/api/v2/hosts/search?q=ip=8.8.8.8", json=mock_response)
    requests_mock.get("/api/v2/hosts/search?q=ip=0.0.0.0", status_code=404, json={})
    response = ip_command(client, args, {})
    assert response[0].outputs == mock_response.get('result', {}).get('hits')[0]
    assert response[1].outputs == mock_response.get('result', {}).get('hits')[0]
    assert 'An error occurred for item: 0.0.0.0' in response[2].readable_output


def test_ip_command_unauthorized_error(requests_mock, client):
    from CensysV2 import ip_command
    args = {'ip': ['8.8.8.8']}
    requests_mock.get("/api/v2/hosts/search?q=ip=8.8.8.8", status_code=401, json={})
    with pytest.raises(DemistoException):
        ip_command(client, args, {})


def test_ip_command_malicious_ip(requests_mock, client):
    from CensysV2 import ip_command
    mock_response = util_load_json('test_data/ip_command_response.json')
    args = {"ip": ['8.8.8.8']}
    params = {'premium_access':True ,'malicious_labels': ['database','email','file-sharing','iot','login-page'], 'malicious_labels_threshold': 1}
    requests_mock.get("/api/v2/hosts/search?q=ip=8.8.8.8", json=mock_response)
    response = ip_command(client, args, params)
    assert response[0].indicator.dbot_score.score == 3


def test_domain_command_multiple_domains(requests_mock, client):
    from CensysV2 import domain_command
    mock_response = util_load_json('test_data/domain_command_response.json')
    args = {'domain': ['amazon.com', 'amazon.com', 'example.com']}
    requests_mock.get("/api/v2/hosts/search?q=dns.names=amazon.com", json=mock_response)
    requests_mock.get("/api/v2/hosts/search?q=dns.names=amazon.com", json=mock_response)
    requests_mock.get("/api/v2/hosts/search?q=dns.names=example.com", status_code=404, json={})
    response = domain_command(client, args, {})
    assert response[0].outputs == mock_response.get('result', {}).get('hits')
    assert response[1].outputs == mock_response.get('result', {}).get('hits')
    assert 'An error occurred for item: example.com' in response[2].readable_output
