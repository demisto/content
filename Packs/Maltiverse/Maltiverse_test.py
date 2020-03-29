import pytest
from Maltiverse import Client, ip_command, url_command, domain_command, file_command
from test_data.response_constants import IP_RESPONSE, URL_RESPONSE, DOMAIN_RESPONSE, FILE_RESPONSE
from test_data.result_constants import EXPECTED_IP_RESULT, EXPECTED_URL_RESULT, EXPECTED_FILE_RESULT, \
    EXPECTED_DOMAIN_RESULT


@pytest.mark.parametrize('command, response, expected_result', [
    (ip_command, IP_RESPONSE, EXPECTED_IP_RESULT),
    (url_command, URL_RESPONSE, EXPECTED_URL_RESULT),
    (ip_command, DOMAIN_RESPONSE, EXPECTED_DOMAIN_RESULT),
    (ip_command, FILE_RESPONSE, EXPECTED_FILE_RESULT)
])
def test_commands(command, response, expected_result, requests_mock):
    import requests
    requests.packages.urllib3.disable_warnings()

    requests_mock.patch.object(Client)
    client = Client('https://api.maltiverse.com', verify=True, proxy=True, headers={'Accept': 'application/json'})  #
    # disable-secrets-detection

    requests_mock.patch.object(client, '_http_request', return_value=response)
    result = command(client)

    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
