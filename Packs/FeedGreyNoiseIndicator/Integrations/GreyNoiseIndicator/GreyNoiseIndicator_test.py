import pytest
import json
import GreyNoiseIndicator

TEST_MODULE_DATA = [
    ("true_key", {"message": "pong", "expiration": "2025-12-31", "offering": "enterprise"}, 200, "ok"),
    ("false_key", {"message": "pong", "expiration": "2020-12-31", "offering": "community"}, 200, "Invalid API Offering ("
                                                                                                 "community)or Expiration Date "
                                                                                                 "(2020-12-31 00:00:00)"),
    ("dummy_key", "forbidden", 401, "Unauthenticated. Check the configured API Key."),
    ("dummy_key", "", 429, "API Rate limit hit. Try after sometime."),
    (
        "dummy_key",
        "Dummy message",
        405,
        "Failed to execute  command.\n Error: Dummy message",
    ),
    (
        "dummy_key",
        "Dummy message",
        505,
        "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    ),
]

GET_IP_REPUTATION_SCORE_DATA = [
    ("unknown", 2),
    ("", 0),
    ("benign", 1),
    ("malicious", 3),
    ("dummy", 0),
]

FORMAT_TIMESTAMP_DATA = [
    ("2023-11-23", "2023-11-23T00:00:00Z")
]

FORMAT_INDICATOR_DATA = [
    ({"ip": "1.2.3.4", "last_seen": "2000-01-01", "first_seen": "1911-12-12", "tags": [], "classification": "benign",
      "metadata": {"country_code": "US"}},
     "GREEN",
     {'Type': 'IP', 'Value': '1.2.3.4',
      'fields': {'firstseenbysource': '1911-12-12T00:00:00Z', 'geocountry': 'US', 'lastseenbysource': '2000-01-01T00:00:00Z',
                 'tags': 'INTERNET SCANNER', 'trafficlightprotocol': 'GREEN'},
      'rawJSON': {'classification': 'benign', 'first_seen': '1911-12-12', 'ip': '1.2.3.4', 'last_seen': '2000-01-01',
                  'metadata': {'country_code': 'US'}, 'tags': []}, 'score': 1}),
    ({"ip": "1.2.3.4", "last_seen": "2000-01-01", "first_seen": "1911-12-12", "tags": ['Mirai'], "classification": "benign",
      "metadata": {"country_code": "US"}},
     "GREEN",
     {'Type': 'IP', 'Value': '1.2.3.4',
      'fields': {'firstseenbysource': '1911-12-12T00:00:00Z', 'geocountry': 'US', 'lastseenbysource': '2000-01-01T00:00:00Z',
                 'tags': 'INTERNET SCANNER,Mirai', 'trafficlightprotocol': 'GREEN'},
      'rawJSON': {'classification': 'benign', 'first_seen': '1911-12-12', 'ip': '1.2.3.4', 'last_seen': '2000-01-01',
                  'metadata': {'country_code': 'US'}, 'tags': ['Mirai']}, 'score': 1})
]

BUILD_FEED_QUERY_DATA = [
    ('Malicious', 'last_seen:1d classification:malicious'),
    ('Benign', 'last_seen:1d classification:benign'),
    ('Benign + Malicious', 'last_seen:1d (classification:benign OR classification:malicious)'),
    ('All', 'last_seen:1d'),
    ('', '')
]

VALID_QUERY = {
    "complete": True,
    "count": 1,
    "data": [
        {
            "ip": "1.1.1.1",
            "bot": False,
            "vpn": False,
            "vpn_service": "N/A",
            "spoofable": False,
            "raw_data": {},
            "first_seen": "2024-01-28",
            "last_seen": "2024-01-30",
            "seen": True,
            "tags": [],
            "actor": "unknown",
            "classification": "unknown",
            "cve": []
        }
    ],
    "message": "ok",
    "query": "last_seen:1d",
    "scroll": "scroll_token"
}

COMMAND_OUTPUT = [
    {
        'Type': 'IP',
        'Value': '1.1.1.1',
        'fields':
            {
                'firstseenbysource': '2024-01-28T00:00:00Z',
                'geocountry': '',
                'lastseenbysource': '2024-01-30T00:00:00Z',
                'tags': 'INTERNET SCANNER',
                'trafficlightprotocol': None
            },
        'rawJSON':
            {
                'actor': 'unknown',
                'bot': False,
                'classification': 'unknown',
                'cve': [],
                'first_seen': '2024-01-28',
                'ip': '1.1.1.1',
                'last_seen': '2024-01-30',
                'seen': True,
                'spoofable': False,
                'tags': [],
                'vpn': False,
                'vpn_service': 'N/A'
            },
        'score': 2
    }
]

GET_INDICATORS_COMMAND_DATA = [
    ({}, VALID_QUERY, 200, COMMAND_OUTPUT)
]

FETCH_INDICATORS_DATA = [
    ('success', VALID_QUERY, 200, COMMAND_OUTPUT),
    ('failure', {}, 400, '(400, {})')
]

FETCH_INDICATORS_COMMAND_DATA = [
    ({}, VALID_QUERY, 200, COMMAND_OUTPUT)
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


@pytest.mark.parametrize("api_key, api_response, status_code, expected_output", TEST_MODULE_DATA)
def test_test_module(api_key, api_response, status_code, expected_output, mocker):
    """
    Tests test_module for GreyNoise integration.
    """
    client = GreyNoiseIndicator.Client(
        api_key, "dummy_server", 10, "proxy", False, "dummy_integration"
    )
    if isinstance(api_key, str) and api_key == "true_key":
        mocker.patch("greynoise.GreyNoise._request", return_value=api_response)
        response = GreyNoiseIndicator.test_module(client)
        assert response == expected_output
    else:
        dummy_response = DummyResponse({}, api_response, status_code)
        mocker.patch("requests.Session.get", return_value=dummy_response)
        with pytest.raises(Exception) as err:
            _ = GreyNoiseIndicator.test_module(client)
        assert str(err.value) == expected_output


@pytest.mark.parametrize("input_data, expected_output", GET_IP_REPUTATION_SCORE_DATA)
def test_get_ip_reputation_score(input_data, expected_output):
    """
    Tests various combinations of GreyNoise classification data.
    """
    response = GreyNoiseIndicator.get_ip_reputation_score(input_data)
    assert response == expected_output


@pytest.mark.parametrize("input_data, expected_output", FORMAT_TIMESTAMP_DATA)
def test_format_timestamp(input_data, expected_output):
    """
    Tests various combinations of GreyNoise classification data.
    """
    response = GreyNoiseIndicator.format_timestamp(input_data)
    assert response == expected_output


@pytest.mark.parametrize("input_data, tlp_color, expected_output", FORMAT_INDICATOR_DATA)
def test_format_indicator(input_data, tlp_color, expected_output):
    """
    Tests various combinations of GreyNoise classification data.
    """
    response = GreyNoiseIndicator.format_indicator(input_data, tlp_color)
    assert response == expected_output


@pytest.mark.parametrize("input_data, expected_output", BUILD_FEED_QUERY_DATA)
def test_build_feed_query(input_data, expected_output):
    """
    Tests various combinations of GreyNoise classification data.
    """
    response = GreyNoiseIndicator.build_feed_query(input_data)
    assert response == expected_output


@pytest.mark.parametrize("args, api_response, status_code, expected_output", GET_INDICATORS_COMMAND_DATA)
def test_get_indicators_command(args, api_response, status_code, expected_output, mocker):
    """
    Tests various combinations of valid and invalid responses for query command.
    """
    client = GreyNoiseIndicator.Client("true_api_key", "dummy_server", 10, "proxy", False, "dummy_integration")
    dummy_response = DummyResponse({"Content-Type": "application/json"}, json.dumps(api_response), status_code)
    mocker.patch("requests.Session.get", return_value=dummy_response)
    response = GreyNoiseIndicator.get_indicators_command(client, args)
    assert response.raw_response == expected_output


@pytest.mark.parametrize("args, api_response, status_code, expected_output", FETCH_INDICATORS_COMMAND_DATA)
def test_fetch_indicators_command(args, api_response, status_code, expected_output, mocker):
    """
    Tests various combinations of valid and invalid responses for query command.
    """
    client = GreyNoiseIndicator.Client("true_api_key", "dummy_server", 10, "proxy", False, "dummy_integration")
    dummy_response = DummyResponse({"Content-Type": "application/json"}, json.dumps(api_response), status_code)
    mocker.patch("requests.Session.get", return_value=dummy_response)
    response = GreyNoiseIndicator.fetch_indicators_command(client, args)
    assert response == expected_output


@pytest.mark.parametrize("test_case, api_response, status_code, expected_output", FETCH_INDICATORS_DATA)
def test_fetch_indicators(test_case, api_response, status_code, expected_output, mocker):
    """
    Tests various combinations of valid and invalid responses for query command.
    """
    client = GreyNoiseIndicator.Client("true_api_key", "dummy_server", 10, "proxy", False, "dummy_integration")
    dummy_response = DummyResponse({"Content-Type": "application/json"}, json.dumps(api_response), status_code)
    mocker.patch("requests.Session.get", return_value=dummy_response)
    params = {}
    if test_case == "success":
        response = GreyNoiseIndicator.fetch_indicators(client, params)
        assert response == expected_output
    else:
        with pytest.raises(Exception) as err:
            GreyNoiseIndicator.fetch_indicators(client, params)
        assert str(err.value) == expected_output
