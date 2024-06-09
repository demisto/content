
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
    "fingerprint_sha256": "XXXXXXXXX"}]


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
    assert response.outputs == mock_response.get('result')


def test_test_module_valid(requests_mock, client):
    """
    Given:
        - A valid client
    When:
        - Testing the module
    Then:
        - Ensure the module test is successful and returns 'ok'
    """
    from CensysV2 import test_module
    requests_mock.get(url='https://search.censys.io/api/v2/hosts/search?q=ip=8.8.8.8', status_code=200, json="{}")

    assert test_module(client, {}) == 'ok'


def test_test_module_invalid(requests_mock, client):
    """
    Given:
        - An invalid client with specific parameters
    When:
        - Testing the module
    Then:
        - Ensure a DemistoException is raised
    """
    from CensysV2 import test_module
    requests_mock.get(url='https://search.censys.io/api/v2/hosts/search?q=ip=8.8.8.8', status_code=200, json="{}")

    params = {'premium_access': False, 'malicious_labels': True}
    with pytest.raises(DemistoException):
        test_module(client, params)


def test_ip_command_multiple_ips(requests_mock, client):
    """
    Given:
        - Multiple IP addresses in the arguments
    When:
        - Running the ip_command function
    Then:
        - Validate the responses for each IP, including errors and quota exceeded messages
    """
    from CensysV2 import ip_command
    mock_response = util_load_json('test_data/ip_command_response.json')
    args = {'ip': ['8.8.8.8', '8.8.8.8', '0.0.0.0', '8.8.4.4']}
    requests_mock.get("/api/v2/hosts/search?q=ip=8.8.8.8", json=mock_response)
    requests_mock.get("/api/v2/hosts/search?q=ip=8.8.8.8", json=mock_response)
    requests_mock.get("/api/v2/hosts/search?q=ip=0.0.0.0", status_code=404, json={})
    requests_mock.get("/api/v2/hosts/search?q=ip=8.8.4.4", status_code=403, json={'message': 'quota'})
    response = ip_command(client, args, {})
    assert response[0].outputs == mock_response.get('result', {}).get('hits')[0]
    assert response[1].outputs == mock_response.get('result', {}).get('hits')[0]
    assert 'An error occurred for item: 0.0.0.0' in response[2].readable_output
    assert 'Quota exceeded.' in response[3].readable_output


def test_ip_command_unauthorized_error(requests_mock, client):
    """
    Given:
        - An unauthorized request
    When:
        - Running the ip_command function
    Then:
        - Ensure a DemistoException is raised
    """
    from CensysV2 import ip_command
    args = {'ip': ['8.8.8.8']}
    requests_mock.get("/api/v2/hosts/search?q=ip=8.8.8.8", status_code=401, json={})
    with pytest.raises(DemistoException):
        ip_command(client, args, {})


def test_ip_command_malicious_ip(requests_mock, client):
    """
    Given:
        - An IP address flagged as malicious
    When:
        - Running the ip_command function
    Then:
        - Ensure the correct DBot score is assigned
    """
    from CensysV2 import ip_command
    mock_response = util_load_json('test_data/ip_command_response.json')
    args = {"ip": ['8.8.8.8']}
    params = {
        'premium_access': True,
        'malicious_labels': ['database', 'email', 'file-sharing', 'iot', 'login-page'],
        'malicious_labels_threshold': 1}
    requests_mock.get("/api/v2/hosts/search?q=ip=8.8.8.8", json=mock_response)
    response = ip_command(client, args, params)
    assert response[0].indicator.dbot_score.score == 3


def test_domain_command_multiple_domains(requests_mock, client):
    """
    Given:
        - Multiple domain names in the arguments
    When:
        - Running the domain_command function
    Then:
        - Validate the responses for each domain, including errors
    """
    from CensysV2 import domain_command
    mock_response = util_load_json('test_data/domain_command_response.json')
    args = {'domain': ['amazon.com', 'amazon.com', 'example.com']}
    requests_mock.get("/api/v2/hosts/search?q=dns.names=amazon.com", json=mock_response)
    requests_mock.get("/api/v2/hosts/search?q=dns.names=amazon.com", json=mock_response)
    requests_mock.get("/api/v2/hosts/search?q=dns.names=example.com", status_code=404, json={})
    response = domain_command(client, args)
    assert response[0].outputs == mock_response.get('result', {}).get('hits')
    assert response[1].outputs == mock_response.get('result', {}).get('hits')
    assert 'An error occurred for item: example.com' in response[2].readable_output
