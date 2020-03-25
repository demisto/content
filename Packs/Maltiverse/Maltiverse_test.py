import pytest
from Maltiverse import Client, ip_command, url_command, domain_command, file_command
from test_data.response_constants import IP_RESPONSE
from test_data.result_constants import EXPECTED_IP_RESULT
import requests_mock

@pytest.mark.parametrize('command, response, expected_result', [
    (ip_command, IP_RESPONSE, EXPECTED_IP_RESULT)
])
# @requests_mock.Mocker()
def test_commands(command, response, expected_result, requests_mock):
    import requests
    requests.packages.urllib3.disable_warnings()

    requests_mock.patch.object(Client)
    client = Client('https://api.maltiverse.com', verify=True, proxy=True, headers={'Accept': 'application/json'})

    requests_mock.patch.object(client, '_http_request', return_value=response)
    result = command(client)

    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
