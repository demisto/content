
import json
import io


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
        {'fingerprint_sha256': 'f3ade17dffcadd9532aeb2514f10d66e22941393725aa65366ac286df9b442ec',
         'issuer': {'organization': ["Let's Encrypt"]},
         'issuer_dn': "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
         'names': ['*.45g4rg43g4fr3434g.gb.net', '45g4rg43g4fr3434g.gb.net'],
         'subject_dn': 'CN=45g4rg43g4fr3434g.gb.net',
         'validity': {'end': '2021-01-10T14:46:11Z', 'start': '2020-10-12T14:46:11Z'}}}]


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_censys_host_search(mocker):
    """
    Given:
        Command arguments: query and limit
    When:
        Running censys_search_hosts_command
    Then:
        Validate the output compared to the mock output
    """
    from CensysV2 import Client, censys_search_hosts_command

    client = Client(base_url='https://search.censys.io/api/', auth=('test', '1234'), verify=True, proxy=False)

    args = {
        'query': 'services.service_name:HTTP',
        'limit': 1
    }

    mock_response = util_load_json('test_data/search_host_response.json')
    mocker.patch.object(client, 'censys_search_ip_request', return_value=mock_response)
    response = censys_search_hosts_command(client, args)
    assert "### Search results for query \"services.service_name:HTTP\"" in response.readable_output
    assert response.outputs == SEARCH_HOST_OUTPUTS


def test_censys_certs_search(mocker):
    """
    Given:
        Command arguments: query and limit
    When:
        Running censys_search_certs_command
    Then:
        Validate the output compared to the mock output
    """
    from CensysV2 import Client, censys_search_certs_command

    client = Client(base_url='https://search.censys.io/api/', auth=('test', '1234'), verify=True, proxy=False)

    args = {
        'query': "parsed.issuer.common_name: \"Let's Encrypt\"",
        'limit': 1
    }

    mock_response = util_load_json('test_data/search_certs_response.json')
    mocker.patch.object(client, 'censys_search_certs_request', return_value=mock_response)
    response = censys_search_certs_command(client, args)
    assert "### Search results for query \"parsed.issuer.common_name: \"Let's Encrypt\"" in response.readable_output
    assert response.outputs == SEARCH_CERTS_OUTPUTS


def test_censys_view_host(mocker):
    """
    Given:
        Command arguments: query ip = 8.8.8.8
    When:
        Running censys_view_host_command
    Then:
        Validate the output compared to the mock output
    """
    from CensysV2 import Client, censys_view_host_command

    client = Client(base_url='https://search.censys.io/api/', auth=('test', '1234'), verify=True, proxy=False)

    args = {
        'query': "8.8.8.8"
    }
    mock_response = util_load_json('test_data/view_host_response.json')
    mocker.patch.object(client, 'censys_view_host_request', return_value=mock_response)
    response = censys_view_host_command(client, args)
    assert '### Information for IP 8.8.8.8' in response.readable_output
    assert response.outputs == mock_response.get('result')
