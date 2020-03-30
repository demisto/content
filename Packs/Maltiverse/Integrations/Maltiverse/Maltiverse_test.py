from Maltiverse import Client, ip_command
from test_data.response_constants import IP_RESPONSE
from test_data.result_constants import EXPECTED_IP_RESULT

# @pytest.mark.parametrize('command, response, expected_result', [
#     (ip_command, IP_RESPONSE, EXPECTED_IP_RESULT),
#     (url_command, URL_RESPONSE, EXPECTED_URL_RESULT),
#     (domain_command, DOMAIN_RESPONSE, EXPECTED_DOMAIN_RESULT),
#     (file_command, FILE_RESPONSE, EXPECTED_FILE_RESULT)
# ])
# def test_commands(command, response, expected_result, requests_mock):
#     import requests
#     SERVER_URL = 'https://api.maltiverse.com'
#     requests.packages.urllib3.disable_warnings()
#
#     requests_mock.patch.object(Client)
#     client = Client(SERVER_URL, verify=True, proxy=True, headers={'Accept': 'application/json'})
#
#     requests_mock.patch.object(client, '_http_request', return_value=response)
#     result = command(client)
#
#     assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command

SERVER_URL = 'https://api.maltiverse.com'
MOCK_IP = '8.8.8.8'


def test_ip(requests_mock):
    requests_mock.get(f'{SERVER_URL}/ip/{MOCK_IP}', json=IP_RESPONSE)

    client = Client(SERVER_URL, verify=True, proxy=True, headers={'Accept': 'application/json'})
    args = {
        'ip': MOCK_IP
    }
    _, outputs, _ = ip_command(client, args)

    assert outputs == EXPECTED_IP_RESULT
