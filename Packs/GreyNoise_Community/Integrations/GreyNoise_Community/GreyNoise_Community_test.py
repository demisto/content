import pytest
import json
import copy
import GreyNoise_Community

# api_key, api_response, status_code, expected_output
TEST_MODULE_DATA = [
    ("true_key", {"message": "pong"}, 200, "ok"),
    ("dummy_key", "forbidden", 401, "Unauthenticated. Check the configured API Key."),
    ("dummy_key", "", 429, "API Rate limit hit. Try after sometime."),
    ("dummy_key", "Dummy message", 405, "Failed to execute  command.\n Error: Dummy message"),
    ("dummy_key", "Dummy message", 505,
     "The server encountered an internal error for GreyNoise and was unable to complete your request.")
]

VALID_IP_RESPONSE = {
    'ip': '8.8.8.8',
    'noise': False,
    'riot': True,
    'classification': 'benign',
    'name': 'Google Public DNS',
    'link': 'https://viz.greynoise.io/riot/8.8.8.8',
    'last_seen': '2021-04-22',
    'message': 'Success'}

VALID_IP_RESPONSE_EXPECTED = copy.deepcopy(VALID_IP_RESPONSE)
VALID_IP_RESPONSE_EXPECTED['address'] = VALID_IP_RESPONSE['ip']
VALID_IP_RESPONSE_EXPECTED.pop('ip')

VALID_IP_NOT_FOUND_RESPONSE = {
    'ip': '1.2.3.4',
    'noise': False,
    'riot': False,
    'message': 'IP not observed scanning the internet or contained in RIOT data set.'
}

VALID_IP_NOT_FOUND_RESPONSE_EXPECTED = copy.deepcopy(VALID_IP_NOT_FOUND_RESPONSE)
VALID_IP_NOT_FOUND_RESPONSE_EXPECTED['address'] = VALID_IP_NOT_FOUND_RESPONSE['ip']
VALID_IP_NOT_FOUND_RESPONSE_EXPECTED.pop('ip')


# args, test_scenario, api_response, status_code, expected_output
ip_community_command_data = [
    ({"ips": "8.8.8.8"}, "positive", VALID_IP_RESPONSE, 200, VALID_IP_RESPONSE_EXPECTED),  # NOSONAR
    ({"ips": "1.2.3.4"}, "positive", VALID_IP_NOT_FOUND_RESPONSE, 200, VALID_IP_NOT_FOUND_RESPONSE_EXPECTED),  # NOSONAR
    ({"ips": "71.6.135.131"}, "negative", "invalid ip response", 404,  # NOSONAR
     "Invalid response from GreyNoise. Response: invalid ip response"),  # NOSONAR
    ({"ips": "71.6.135.131"}, "negative", "forbidden", 401, "Unauthenticated. Check the configured API Key."),  # NOSONAR
    ({"ips": "71.6.135.131"}, "negative", {}, 429, "API Rate limit hit. Try after sometime."),  # NOSONAR
    ({"ips": "71.6.135.131"}, "negative", "Dummy message", 405,  # NOSONAR
     "Failed to execute  command.\n Error: Dummy message"),  # NOSONAR
    ({"ips": "71.6.135.131"}, "negative", {}, 505,  # NOSONAR
     "The server encountered an internal error for GreyNoise and was unable to complete your request."),  # NOSONAR
    ({"ips": "5844.2204.2191.2471"}, "negative", {}, 200, "Invalid IP address: '5844.2204.2191.2471'")  # NOSONAR
]

get_ip_reputation_score_data = [
    ("unknown", (0, "Unknown")),
    ("", (0, "Unknown")),
    ("benign", (1, "Good")),
    ("malicious", (3, "Bad")),
    ("dummy", (0, "Unknown")),
]

VALID_IP_RESPONSE_DATA = [{
    'IP': '8.8.8.8',
    'Noise': False,
    'Riot': True,
    'Classification': 'benign',
    'Name': 'Google Public DNS',
    'Link': 'https://viz.greynoise.io/riot/8.8.8.8',
    'Last Seen': '2021-04-22',
    'Message': 'Success'}]

get_community_ip_data_data = [
    ([VALID_IP_RESPONSE], VALID_IP_RESPONSE_DATA)
]


class DummyResponse:
    """
    Dummy Response object of requests.response for unit testing.
    """

    def __init__(self, headers, text, status_code):
        self.headers = headers
        self.text = text
        self.status_code = status_code

    def json(self):
        """
        Dummy json method.
        """
        return json.loads(self.text)


@pytest.mark.parametrize("args, test_scenario, api_response, status_code, expected_output", ip_community_command_data)
def test_ip_community_command(args, test_scenario, api_response, status_code, expected_output, mocker):
    """
    Tests various combinations of GreyNoise classification data.
    """
    client = GreyNoise_Community.Client("true_api_key", "dummy_server", 10, "proxy", False, "dummy_integration")
    dummy_response = DummyResponse(
        {
            "Content-Type": "application/json"
        },
        json.dumps(api_response),
        status_code
    )
    if test_scenario == "positive":
        mocker.patch('requests.Session.get', return_value=dummy_response)
        response = GreyNoise_Community.ip_community_command(client, args)
        assert response[0].outputs == expected_output
    else:
        mocker.patch('requests.Session.get', return_value=dummy_response)
        with pytest.raises(Exception) as err:
            _ = GreyNoise_Community.ip_community_command(client, args)
        assert str(err.value) == expected_output


@pytest.mark.parametrize("input_data, expected_output", get_community_ip_data_data)
def test_get_community_ip_data(input_data, expected_output: object):
    """
    Tests various combinations of GreyNoise classification data.
    """
    response = GreyNoise_Community.get_community_ip_data(input_data)
    assert response == expected_output


@pytest.mark.parametrize("input_data, expected_output", get_ip_reputation_score_data)
def test_get_ip_reputation_score(input_data, expected_output):
    """
    Tests various combinations of GreyNoise classification data.
    """
    response = GreyNoise_Community.get_ip_reputation_score(input_data)
    assert response == expected_output


@pytest.mark.parametrize("api_key, api_response, status_code, expected_output", TEST_MODULE_DATA)
def test_test_module(api_key, api_response, status_code, expected_output, mocker):
    """
    Tests test_module for GreyNoise integration.
    """
    client = GreyNoise_Community.Client(api_key, "dummy_server", 10, "proxy", False, "dummy_integration")
    if isinstance(api_key, str) and api_key == "true_key":
        mocker.patch('greynoise.GreyNoise._request', return_value=api_response)
        response = GreyNoise_Community.test_module(client)
        assert response == expected_output
    else:
        dummy_response = DummyResponse({}, api_response, status_code)
        mocker.patch('requests.Session.get', return_value=dummy_response)
        with pytest.raises(Exception) as err:
            _ = GreyNoise_Community.test_module(client)
        assert str(err.value) == expected_output
