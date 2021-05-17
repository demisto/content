from Maltiverse import Client, ip_command, url_command, domain_command, file_command
from test_data.response_constants import IP_RESPONSE, URL_RESPONSE, DOMAIN_RESPONSE, FILE_RESPONSE
from test_data.result_constants import EXPECTED_IP_RESULT, EXPECTED_URL_RESULT, EXPECTED_DOMAIN_RESULT, \
    EXPECTED_FILE_RESULT


SERVER_URL = 'https://api.maltiverse.com'
MOCK_IP = '1.1.1.0'
MOCK_URL = 'https://dv-expert.org'
MOCK_URL_SHA256 = 'a70c027c6d76fb703f0d2e5a14526f219bf3b771557e4a36685365b960b98233'
MOCK_DOMAIN = 'google.com'
MOCK_FILE = 'edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f'  # should be given as SHA256


def test_ip(requests_mock):
    requests_mock.get(f'{SERVER_URL}/ip/{MOCK_IP}', json=IP_RESPONSE)

    client = Client(url=SERVER_URL, use_ssl=True, use_proxy=True)
    args = {
        'ip': MOCK_IP
    }
    _, outputs, _ = ip_command(client, args)

    assert outputs == EXPECTED_IP_RESULT


def test_url(requests_mock):
    requests_mock.get(f'{SERVER_URL}/url/{MOCK_URL_SHA256}', json=URL_RESPONSE)

    client = Client(url=SERVER_URL, use_ssl=True, use_proxy=True)
    args = {
        'url': MOCK_URL
    }
    _, outputs, _ = url_command(client, args)

    assert outputs == EXPECTED_URL_RESULT


def test_domain(requests_mock):
    requests_mock.get(f'{SERVER_URL}/hostname/{MOCK_DOMAIN}', json=DOMAIN_RESPONSE)

    client = Client(url=SERVER_URL, use_ssl=True, use_proxy=True)
    args = {
        'domain': MOCK_DOMAIN
    }
    _, outputs, _ = domain_command(client, args)

    assert outputs == EXPECTED_DOMAIN_RESULT


def test_file(requests_mock):
    requests_mock.get(f'{SERVER_URL}/sample/{MOCK_FILE}', json=FILE_RESPONSE)

    client = Client(url=SERVER_URL, use_ssl=True, use_proxy=True)
    args = {
        'file': MOCK_FILE
    }
    _, outputs, _ = file_command(client, args)

    assert outputs == EXPECTED_FILE_RESULT
