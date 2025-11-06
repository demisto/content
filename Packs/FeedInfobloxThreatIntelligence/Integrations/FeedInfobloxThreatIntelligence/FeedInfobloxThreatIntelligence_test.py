"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
from pathlib import Path

import pytest
from FeedInfobloxThreatIntelligence import *

TEST_PATH = Path(__file__).parent / "test_data"


def util_load_json(file_name: str):
    """Load file in JSON format."""
    file_path = TEST_PATH / file_name
    with open(file_path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_text_data(file_name: str) -> str:
    """Load a text file."""
    file_path = TEST_PATH / file_name
    with open(file_path, encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def client():
    """Create a real client for testing with requests_mock"""
    return Client(api_key="test_api_key", verify=False)


@pytest.fixture
def sample_tide_response():
    """Load sample TIDE response data"""
    return util_load_json("infoblox-cloud-get-indicators-response.json")


@pytest.fixture
def sample_params():
    """Sample integration parameters"""
    return {
        "feedTags": ["test-tag"],
        "tlp_color": "AMBER",
        "indicator_types": ["IP", "HOST", "EMAIL"],
        "dga_threat": "false",
        "threat_classes": ["APT", "MalwareC2"],
        "profiles": ["IID"],
    }


@pytest.fixture
def mock_demisto_methods(mocker):
    """Mock demisto methods used by the integration"""
    mock_debug = mocker.patch.object(demisto, "debug")
    mock_params = mocker.patch.object(demisto, "params")
    return {"debug": mock_debug, "params": mock_params}


class TestFetchIndicatorsCommand:
    """Test cases for fetch_indicators_command function"""

    def test_fetch_indicators_with_last_run(self, client, requests_mock):
        """Test fetch_indicators_command with existing last_run data"""
        # Test with existing last_run
        last_run = {"last_fetch_time": "2023-01-10T00:00:00.000Z"}

        # Mock the API endpoint
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/host/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-host-response.json"),
        )

        indicators, next_run = fetch_indicators_command(client, {"indicator_types": "ip, host"}, last_run)

        # Verify indicators were created
        assert len(indicators) == 2
        assert isinstance(indicators, list)

        # Verify next_run contains updated last_fetch_time
        assert "last_fetch_time" in next_run
        assert isinstance(next_run["last_fetch_time"], str)

    def test_fetch_indicators_with_custom_limit(self, client, requests_mock):
        """Test fetch_indicators_command with custom max_fetch limit"""
        params = {"max_fetch": "51", "feedTags": ["test-tag"], "tlp_color": "GREEN"}
        last_run = {}

        # Mock the API endpoint
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/url/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-url-response.json"),
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/email/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-email-response.json"),
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/hash/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-hash-response.json"),
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/host/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-host-response.json"),
        )

        indicators, next_run = fetch_indicators_command(client, params, last_run)

        # Verify API was called with custom limit
        assert requests_mock.call_count == 5
        assert "rlimit=10" in requests_mock.request_history[0].url
        assert "rlimit=11" in requests_mock.request_history[-1].url
        assert len(indicators) == 5
        assert "last_fetch_time" in next_run

    def test_fetch_indicators_api_error(self, client, requests_mock):
        """Test fetch_indicators_command with API error"""
        # Mock API error
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", status_code=500, text="Internal Server Error")

        # Should raise DemistoException
        with pytest.raises(Exception):
            fetch_indicators_command(client, {}, {})

    def test_fetch_indicators_empty_response(self, client, requests_mock):
        """Test fetch_indicators_command with empty API response"""
        # Mock empty response
        empty_response = []
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=empty_response)
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/url/hourly", json=empty_response)
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/email/hourly", json=empty_response)
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/hash/hourly", json=empty_response)
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/host/hourly", json=empty_response)

        indicators, next_run = fetch_indicators_command(client, {}, {})

        # Should return empty list
        assert len(indicators) == 0
        assert isinstance(indicators, list)

        # Should still have next_run with timestamp
        assert "last_fetch_time" in next_run

    def test_get_indicators_command_invalid_max_fetch(self, client):
        """Test infoblox_get_indicators_command with invalid max_fetch"""
        args = {"max_fetch": "invalid"}

        with pytest.raises(DemistoException) as e:
            fetch_indicators_command(client, args, {})
        assert "Parameter 'max_fetch' must be a valid integer" in str(e.value)

    def test_fetch_indicators_invalid_last_fetch_time(self, client, requests_mock):
        """Test fetch_indicators_command with invalid last_fetch_time format"""
        last_run = {"last_fetch_time": "invalid_date_format"}

        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/url/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-url-response.json"),
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/email/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-email-response.json"),
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/hash/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-hash-response.json"),
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/host/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-host-response.json"),
        )

        indicators, next_run = fetch_indicators_command(client, {"indicator_types": "host,ip,email,url,hash"}, last_run)

        # Should handle invalid date gracefully and use default
        assert len(indicators) == 5
        assert "last_fetch_time" in next_run

    def test_fetch_indicators_with_negative_max_fetch(self, client):
        """Test fetch_indicators_command with invalid max_fetch"""
        params = {"max_fetch": -1, "indicator_types": "host,ip"}

        with pytest.raises(DemistoException):
            fetch_indicators_command(client, params, {})

    def test_fetch_indicators_invalid_indicators_skipped(self, client, requests_mock):
        """Test fetch_indicators_command with missing required fields"""

        invalid_response = util_load_json("infoblox-cloud-fetch-indicators-invalid.json").get("threat", [])
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=invalid_response)

        indicators, next_run = fetch_indicators_command(client, {"indicator_types": "ip"}, {})

        assert len(indicators) == 0

    def test_fetch_indicators_through_main_function(self, mocker, requests_mock):
        """Test fetch_indicators_command through main function"""
        mock_indicators = mocker.patch.object(demisto, "createIndicators")

        mocker.patch.object(demisto, "command", return_value="fetch-indicators")

        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/url/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-url-response.json"),
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/email/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-email-response.json"),
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/hash/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-hash-response.json"),
        )
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/host/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-host-response.json"),
        )
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "api_key": {"password": "test-api-key"},
                "max_fetch": "10",
                "indicator_types": "host,ip,url,email,hash",
                "first_fetch": "1 hour",
            },
        )

        main()

        assert mock_indicators.called
        indicators = mock_indicators.call_args[0][0]
        assert len(indicators) == 5

    def test_get_first_fetch_time_empty_input(self):
        """Test get_first_fetch_time with empty input"""
        result = get_first_fetch_time("")
        # Should use default 1 hour
        assert "T" in result
        assert "Z" in result

    def test_get_first_fetch_time_invalid_parse(self, mocker):
        """Test get_first_fetch_time with invalid parse fallback"""
        # Mock dateparser.parse to return None for first call, valid for second
        mock_parse = mocker.patch("dateparser.parse")
        mock_parse.side_effect = [None, mocker.MagicMock(strftime=mocker.MagicMock(return_value="2023-01-01T00:00:00.000Z"))]

        result = get_first_fetch_time("invalid_date_string")
        assert result == "2023-01-01T00:00:00.000Z"

    def test_extract_indicator_fields_bool_conversion(self):
        """Test extract_indicator_fields with boolean field conversion"""

        indicator_data = {"profile": "True", "class": "false"}

        fields = extract_indicator_fields(indicator_data)

        # Should convert string to boolean
        assert fields["service"] == "True"
        assert fields["category"] == "false"


class TestModuleCommand:
    """Test cases for test_module function"""

    def test_module_success_feed_mode(self, client, mock_demisto_methods, mocker):
        """Test test_module function in feed mode (calls fetch_indicators_command)"""
        # Configure demisto mocks
        mock_demisto_methods["params"].return_value = {"feed": True}

        # Mock fetch_indicators_command
        mock_fetch = mocker.patch("FeedInfobloxThreatIntelligence.fetch_indicators_command")
        mock_fetch.return_value = ([{"type": "IP", "value": "1.2.3.4"}], {"last_fetch_time": "2023-01-01T00:00:00.000Z"})

        result = command_test_module(client)

        # Should return "ok" for successful fetch
        assert result == "ok"

        # Verify fetch_indicators_command was called
        mock_fetch.assert_called_once()

    def test_module_api_error_non_feed_mode(self, client, requests_mock, mock_demisto_methods):
        """Test test_module function with API error in non-feed mode"""
        # Mock empty API response
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=None)

        # Configure demisto mocks
        mock_demisto_methods["params"].return_value = {"feed": False}

        # Should raise exception for invalid response
        with pytest.raises(Exception):
            command_test_module(client)

    def test_module_feed_mode_error(self, client, mock_demisto_methods, mocker):
        """Test test_module function in feed mode when fetch_indicators_command raises error"""
        from CommonServerPython import DemistoException

        # Configure demisto mocks
        mock_demisto_methods["params"].return_value = {"feed": True}

        # Mock fetch_indicators_command
        mock_fetch = mocker.patch("FeedInfobloxThreatIntelligence.fetch_indicators_command")
        mock_fetch.side_effect = DemistoException("API Error")

        # Should raise DemistoException from fetch_indicators_command
        with pytest.raises(DemistoException):
            command_test_module(client)

    def test_fetch_indicators_test_mode(self, client, requests_mock):
        """Test fetch_indicators_command in test mode"""
        last_run = {}

        # Mock the API endpoint
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )

        indicators, next_run = fetch_indicators_command(client, {"indicator_types": "ip"}, last_run, is_test=True)

        # In test mode, should return empty results
        assert indicators == []
        assert next_run == {}

        # Verify API was called with limit=1 for test
        assert requests_mock.called
        request = requests_mock.request_history[0]
        assert "rlimit=1" in request.url

    def test_module_authentication_error_401(self, client, requests_mock, mock_demisto_methods):
        """Test test_module with 401 authentication error"""
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", status_code=401)
        mock_demisto_methods["params"].return_value = {"feed": False}

        with pytest.raises(DemistoException) as e:
            command_test_module(client)
        assert "Authentication failed" in str(e.value)

    def test_module_not_found_error_404(self, client, requests_mock, mock_demisto_methods):
        """Test test_module with 404 not found error"""
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", status_code=404)
        mock_demisto_methods["params"].return_value = {"feed": False}

        with pytest.raises(DemistoException) as e:
            command_test_module(client)
        assert "API endpoint not found" in str(e.value)

    def test_module_failure(self, client, requests_mock, mock_demisto_methods):
        """Test test_module with failure"""
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", exc=requests.ConnectionError)
        mock_demisto_methods["params"].return_value = {"feed": False}

        with pytest.raises(DemistoException) as e:
            command_test_module(client)
        assert "Failed to execute test-module." in str(e.value)

    def test_main_missing_api_key(self, mocker):
        """Test main function with missing API key"""
        mocker.patch.object(demisto, "params", return_value={"api_key": {}})

        with pytest.raises(DemistoException) as e:
            main()
        assert "API Key must be provided." in str(e.value)

    def test_main_unknown_command_exception(self, mocker):
        """Test main function with unknown command"""
        mocker.patch.object(demisto, "params", return_value={"api_key": {"password": "test-key"}})
        mocker.patch.object(demisto, "command", return_value="unknown-command")
        mock_error = mocker.patch.object(demisto, "error")
        mock_return_error = mocker.patch("FeedInfobloxThreatIntelligence.return_error")

        # The main function catches all exceptions, so we expect it to handle the NotImplementedError
        main()

        # Should log error and call return_error due to exception handling
        mock_error.assert_called_with("Error in unknown-command command: Command unknown-command is not implemented")
        mock_return_error.assert_called_with(
            "Failed to execute unknown-command command.\nError:\nCommand unknown-command is not implemented"
        )

    def test_main_exception_logging(self, mocker):
        """Test main function exception logging"""
        mocker.patch.object(demisto, "params", return_value={"api_key": {"password": "test-key"}})
        mocker.patch.object(demisto, "command", return_value="test-module")
        # Mock command_test_module to raise an exception
        mocker.patch("FeedInfobloxThreatIntelligence.command_test_module", side_effect=Exception("Test error"))
        mock_error = mocker.patch.object(demisto, "error")
        mock_return_error = mocker.patch("FeedInfobloxThreatIntelligence.return_error")

        main()

        # Should log error and call return_error
        mock_error.assert_called_with("Error in test-module command: Test error")
        mock_return_error.assert_called_with("Failed to execute test-module command.\nError:\nTest error")

    def test_module_feed_fetch_interval_too_large(self, client, mock_demisto_methods):
        """Test test_module with feed fetch interval greater than 4 hours"""
        # Configure demisto mocks with feed fetch interval > 240 minutes
        mock_demisto_methods["params"].return_value = {
            "feed": True,
            "feedFetchInterval": 300,  # 5 hours > 4 hours limit
            "first_fetch": "1 hour",
        }

        # Should raise DemistoException for feed fetch interval > 4 hours
        with pytest.raises(DemistoException) as e:
            command_test_module(client)
        assert "Feed fetch interval cannot be greater than 4 hours." in str(e.value)

    def test_module_first_fetch_time_too_old(self, client, mock_demisto_methods, mocker):
        """Test test_module with first fetch time older than 4 hours"""

        # Configure demisto mocks with old first_fetch time
        mock_demisto_methods["params"].return_value = {
            "feed": True,
            "feedFetchInterval": 60,  # Valid interval
            "first_fetch": "10 hours",  # Older than 4 hours
        }

        # Should raise DemistoException for first fetch time older than 4 hours
        with pytest.raises(DemistoException) as e:
            command_test_module(client)
        assert "First fetch time cannot be older than 4 hours." in str(e.value)


class TestInfobloxGetIndicatorsCommand:
    """Test cases for infoblox_get_indicators_command function"""

    def test_get_indicators_command_success(self, client, requests_mock):
        """Test infoblox_get_indicators_command successful execution"""
        args = {
            "limit": "10",
            "indicator_types": ["IP"],
            "from_date": "2023-11-01T00:00:00.000Z",
            "to_date": "2023-11-02T00:00:00.000Z",
        }

        # Mock the API endpoint
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )

        result = infoblox_get_indicators_command(client, args, {})

        # Verify command result structure
        assert result.outputs_prefix == "Infoblox.FeedIndicator"
        assert result.outputs_key_field == "id"
        assert result.readable_output == util_load_text_data("infoblox-cloud-get-indicators-readable.md")

        # Verify indicators were processed
        assert len(result.outputs) == 1

        # Verify API was called with correct parameters
        assert requests_mock.called
        request = requests_mock.request_history[0]
        assert "rlimit=10" in request.url
        assert "from_date=2023-11-01T00%3A00%3A00.000" in request.url
        assert "to_date=2023-11-02T00%3A00%3A00.000" in request.url
        assert "include_ipv6=True" in request.url

    def test_get_indicators_limit_exceed(self, client, requests_mock):
        """Test infoblox_get_indicators_command successful execution"""
        args = {
            "limit": "100000",
            "indicator_types": ["IP"],
        }

        # Mock the API endpoint
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )

        infoblox_get_indicators_command(client, args, {})

        # Verify API was called with correct parameters
        assert requests_mock.called
        request = requests_mock.request_history[0]
        assert "rlimit=50000" in request.url

    def test_get_indicators_limit_less_than_indicator_types(self, client):
        """Test infoblox_get_indicators_command with limit less than indicator types"""
        args = {
            "limit": "1",
            "indicator_types": ["IP", "Domain"],
        }

        with pytest.raises(ValueError) as e:
            infoblox_get_indicators_command(client, args, {})
        assert "Limit must be greater than or equal to the number of indicator types." in str(e.value)

    def test_get_indicators_limit_less_than_5(self, client):
        """Test infoblox_get_indicators_command with limit less than 5"""
        args = {
            "limit": "1",
        }

        with pytest.raises(ValueError) as e:
            infoblox_get_indicators_command(client, args, {})
        assert "Please provide indicator types when limit is less than 5." in str(e.value)

    def test_get_indicators_command_with_filters(self, client, requests_mock):
        """Test infoblox_get_indicators_command with various filters"""
        args = {"limit": "5", "indicator_types": ["IP"], "dga_threat": "true", "threat_classes": ["APT", "MalwareC2"]}

        # Mock the API endpoint
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )

        infoblox_get_indicators_command(client, args, {})

        # Verify API was called with filters
        assert requests_mock.called
        request = requests_mock.request_history[0]
        assert "rlimit=5" in request.url
        assert "dga=True" in request.url
        assert "class=APT%2CMalwareC2" in request.url

    def test_get_indicators_command_auto_limit_distribution(self, client, requests_mock):
        """Test infoblox_get_indicators_command with automatic limit distribution"""
        # Test with no limit parameters - should auto-populate
        args = {"indicator_types": "ip, host"}

        # Mock the API endpoint
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )

        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/host/hourly",
            json=util_load_json("infoblox-cloud-fetch-indicators-host-response.json"),
        )

        infoblox_get_indicators_command(client, args, {})

        # Verify API was called with auto-populated dates
        assert requests_mock.called
        request_ip = requests_mock.request_history[0]
        assert "rlimit=5" in request_ip.url
        request_host = requests_mock.request_history[1]
        assert "rlimit=5" in request_host.url

    def test_get_indicators_command_with_date_range(self, client, requests_mock):
        """Test infoblox_get_indicators_command with date range"""
        args = {"from_date": "2023-01-01T00:00:00.000Z", "to_date": "2023-01-31T23:59:59.999Z", "indicator_types": "ip"}

        # Mock the API endpoint
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )

        infoblox_get_indicators_command(client, args, {})

        # Verify API was called with date parameters
        assert requests_mock.called
        request = requests_mock.request_history[0]
        assert "from_date=2023-01-01T00%3A00%3A00.000" in request.url
        assert "to_date=2023-01-31T23%3A59%3A59.999" in request.url

    def test_get_indicators_command_no_args(self, client, requests_mock):
        """Test infoblox_get_indicators_command with no arguments"""

        # Mock the API endpoint
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )

        result = infoblox_get_indicators_command(client, {"indicator_types": "ip"}, {})

        # Verify command executed successfully with defaults
        assert len(result.outputs) == 1

        # Verify API was called
        assert requests_mock.called

    def test_get_indicators_command_empty_response(self, client, requests_mock):
        """Test infoblox_get_indicators_command with empty API response"""
        args = {"limit": "10", "indicator_types": "ip"}

        # Mock empty response
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", json={"threat": []})

        result = infoblox_get_indicators_command(client, args, {})

        assert "No indicators found." in result.readable_output
        assert requests_mock.called

    def test_get_indicators_command_invalid_limit(self, client):
        """Test infoblox_get_indicators_command with invalid limit"""
        args = {"limit": "invalid"}

        with pytest.raises(DemistoException) as e:
            infoblox_get_indicators_command(client, args, {})
        assert "Parameter 'limit' must be a valid integer" in str(e.value)

    def test_get_indicators_only_from_date(self, client, requests_mock):
        """Test infoblox_get_indicators_command with only from_date"""
        args = {"from_date": "2023-01-01T00:00:00.000Z", "indicator_types": "ip"}

        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )

        infoblox_get_indicators_command(client, args, {})

        assert requests_mock.called
        request = requests_mock.request_history[0]
        assert "from_date=2023-01-01T00%3A00%3A00.000" in request.url

    def test_get_indicators_with_data_provider_profiles(self, client, requests_mock):
        """Test infoblox_get_indicators_command with data provider profiles"""
        args = {"data_provider_profiles": ["IID", "OSINT", "Custom"], "indicator_types": "ip"}

        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )

        infoblox_get_indicators_command(client, args, {})

        assert requests_mock.called
        request = requests_mock.request_history[0]
        assert "profile=IID%2COSINT%2CCustom" in request.url

    def test_get_indicators_threat_field_not_list(self, client, requests_mock):
        """Test infoblox_get_indicators_command when threat field is not a list"""
        invalid_response = {"threat": {"not": "a_list"}}
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/host/hourly", json=invalid_response)

        result = infoblox_get_indicators_command(client, {"indicator_types": "host"}, {})

        # Should handle invalid threat field gracefully
        assert "No indicators found." in result.readable_output

    def test_get_indicators_with_all_params(self, client, requests_mock):
        """Test get_indicators with all parameters"""
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", json={"threat": []})

        client.get_indicators(
            limit=100,
            indicator_types=["IP"],
            from_date="2023-01-01T00:00:00.000Z",
            to_date="2023-01-02T00:00:00.000Z",
            dga_flag="true",
            threat_class=["APT", "MalwareC2"],
            profile=["IID", "OSINT"],
        )

        assert requests_mock.called
        request = requests_mock.request_history[0]
        assert "rlimit=100" in request.url
        assert "from_date=2023-01-01T00%3A00%3A00.000Z" in request.url
        assert "to_date=2023-01-02T00%3A00%3A00.000Z" in request.url
        assert "dga=true" in request.url
        assert "class=APT%2CMalwareC2" in request.url
        assert "profile=IID%2COSINT" in request.url

    def test_get_indicators_command_401_authentication_error(self, client, requests_mock):
        """Test infoblox-cloud-get-indicators command with 401 Authentication Error"""
        args = {"limit": "10"}

        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", status_code=401)

        with pytest.raises(DemistoException) as e:
            infoblox_get_indicators_command(client, args, {})
        assert "Authentication Error (401): API key is invalid or expired." in str(e.value)

    def test_get_indicators_command_403_forbidden_error(self, client, requests_mock):
        """Test infoblox-cloud-get-indicators command with 403 Forbidden Error"""
        args = {"limit": "10"}

        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", status_code=403)

        with pytest.raises(DemistoException) as e:
            infoblox_get_indicators_command(client, args, {})
        assert "Forbidden (403): Insufficient permissions to access this resource." in str(e.value)

    def test_get_indicators_command_404_not_found_error(self, client, requests_mock):
        """Test infoblox-cloud-get-indicators command with 404 Not Found Error"""
        args = {"limit": "10"}

        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", status_code=404)

        with pytest.raises(DemistoException) as e:
            infoblox_get_indicators_command(client, args, {})
        assert "Not Found (404): The requested resource was not found." in str(e.value)

    def test_get_indicators_command_429_rate_limit_error(self, client, requests_mock):
        """Test infoblox-cloud-get-indicators command with 429 Rate Limit Error"""
        args = {"limit": "10"}

        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", status_code=429)

        with pytest.raises(DemistoException) as e:
            infoblox_get_indicators_command(client, args, {})
        assert "Rate Limit Exceeded (429): Too many requests. Please try again later." in str(e.value)

    def test_get_indicators_command_500_server_error(self, client, requests_mock):
        """Test infoblox-cloud-get-indicators command with 500 Internal Server Error"""
        args = {"limit": "10"}

        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", status_code=500)

        with pytest.raises(DemistoException) as e:
            infoblox_get_indicators_command(client, args, {})
        assert "Server Error (500): Internal server error occurred. Please try again later." in str(e.value)

    def test_handle_error_response_400_simple(self, client, requests_mock):
        """Test _handle_error_response with 400 status code"""
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", status_code=400)

        with pytest.raises(DemistoException) as e:
            client.get_indicators()
        assert "Bad Request (400): Invalid parameters or request body." in str(e.value)

    def test_handle_error_response_unknown_status(self, client, requests_mock):
        """Test _handle_error_response with unknown status code"""
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", status_code=418)

        with pytest.raises(DemistoException) as e:
            client.get_indicators()
        assert "Error in API call with status code 418" in str(e.value)

    def test_http_request_timeout_error(self, client, requests_mock):
        """Test http_request with timeout error"""
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats/ip/hourly", exc=DemistoException("Read timed out"))

        with pytest.raises(DemistoException) as e:
            client.get_indicators()
        assert "Connection timed out. Check your internet connection" in str(e.value)

    def test_get_indicators_command_through_main_function(self, mocker, requests_mock):
        """Test infoblox_get_indicators_command through main function"""
        # Mock demisto functions
        mock_return_results = mocker.patch("FeedInfobloxThreatIntelligence.return_results")
        mocker.patch.object(demisto, "command", return_value="infoblox-cloud-get-indicators")
        mocker.patch.object(
            demisto,
            "args",
            return_value={
                "limit": "5",
                "indicator_types": "ip",
                "from_date": "2023-01-01T00:00:00.000Z",
                "to_date": "2023-01-02T00:00:00.000Z",
            },
        )
        mocker.patch.object(demisto, "params", return_value={"api_key": {"password": "test-api-key"}})

        # Mock the API endpoint
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats/ip/hourly", json=util_load_json("infoblox-cloud-fetch-indicators-ip-response.json")
        )

        # Call main function
        main()

        # Verify return_results was called
        assert mock_return_results.called
        result = mock_return_results.call_args[0][0]

        # Verify the command result structure
        assert result.outputs_prefix == "Infoblox.FeedIndicator"
        assert result.outputs_key_field == "id"
        assert len(result.outputs) == 1

        # Verify API was called with correct parameters
        assert requests_mock.called
        request = requests_mock.request_history[0]
        assert "rlimit=5" in request.url


class TestHelperFunctions:
    """Test cases for helper functions"""

    def test_map_indicator_type_ip(self):
        """Test map_indicator_type for IP indicators"""
        indicator_data = {"type": "IP", "ip": "1.2.3.4"}
        xsoar_type, value = map_indicator_type(indicator_data)
        assert xsoar_type == "IP"
        assert value == "1.2.3.4"

    def test_map_indicator_type_host(self):
        """Test map_indicator_type for HOST indicators"""
        indicator_data = {"type": "HOST", "host": "example.com"}
        xsoar_type, value = map_indicator_type(indicator_data)
        assert xsoar_type == "Domain"
        assert value == "example.com"

    def test_map_indicator_type_email(self):
        """Test map_indicator_type for EMAIL indicators"""
        indicator_data = {"type": "EMAIL", "email": "test@example.com"}
        xsoar_type, value = map_indicator_type(indicator_data)
        assert xsoar_type == "Email"
        assert value == "test@example.com"

    def test_map_indicator_type_hash(self):
        """Test map_indicator_type for HASH indicators"""
        indicator_data = {"type": "HASH", "hash": "abc123", "hash_type": "SHA256"}
        xsoar_type, value = map_indicator_type(indicator_data)
        assert xsoar_type == "File"
        assert value == "abc123"

    def test_map_indicator_type_url(self):
        """Test map_indicator_type for URL indicators"""
        indicator_data = {"type": "URL", "url": "http://example.com/path"}
        xsoar_type, value = map_indicator_type(indicator_data)
        assert xsoar_type == "URL"
        assert value == "http://example.com/path"

    def test_extract_indicator_fields(self, sample_tide_response):
        """Test extract_indicator_fields function"""
        indicator_data = sample_tide_response["threat"][0]  # EMAIL indicator
        feed_tags = ["test-tag"]
        tlp_color = "AMBER"

        fields = extract_indicator_fields(indicator_data, feed_tags, tlp_color)

        # Verify required fields are present
        assert "tags" in fields
        assert "trafficlightprotocol" in fields
        assert "confidence" in fields
        assert "sourcepriority" in fields

        # Verify values
        assert fields["tags"] == ["test-tag"]
        assert fields["trafficlightprotocol"] == "AMBER"
        assert fields["confidence"] == 100

    def test_calculate_dbot_score_high_threat(self):
        """Test calculate_dbot_score for high threat level"""
        indicator_data = {"threat_level": 100}
        score = calculate_dbot_score(indicator_data)
        assert score == 3  # Bad

    def test_calculate_dbot_score_medium_threat(self):
        """Test calculate_dbot_score for medium threat level"""
        indicator_data = {"threat_level": 60}
        score = calculate_dbot_score(indicator_data)
        assert score == 2  # Suspicious

    def test_calculate_dbot_score_low_threat(self):
        """Test calculate_dbot_score for low threat level"""
        indicator_data = {"threat_level": 10}
        score = calculate_dbot_score(indicator_data)
        assert score == 1  # Good

    def test_calculate_dbot_score_no_threat(self):
        """Test calculate_dbot_score for no threat level"""
        indicator_data = {}
        score = calculate_dbot_score(indicator_data)
        assert score == 0  # Unknown

    def test_calculate_dbot_score_high_confidence(self):
        """Test calculate_dbot_score for high confidence"""
        indicator_data = {"threat_level": 50}
        score = calculate_dbot_score(indicator_data)
        assert score == 2

    def test_calculate_dbot_score_medium_confidence(self):
        """Test calculate_dbot_score for medium confidence"""
        indicator_data = {"threat_level": 30}
        score = calculate_dbot_score(indicator_data)
        assert score == 2  # Suspicious due to medium threat level

    def test_map_indicator_type_invalid_data(self):
        """Test map_indicator_type with invalid data type"""
        indicator_data = "invalid_string"
        xsoar_type, value = map_indicator_type(indicator_data)
        assert xsoar_type == "Domain"  # Default fallback
        assert value is None

    def test_map_indicator_type_unknown_type(self):
        """Test map_indicator_type with unknown indicator type"""
        indicator_data = {"type": "UNKNOWN", "host": "test.com"}
        xsoar_type, value = map_indicator_type(indicator_data)
        assert xsoar_type == "Domain"  # Default fallback
        assert value == "test.com"

    def test_extract_indicator_fields_nested_fields(self):
        """Test extract_indicator_fields with nested field navigation"""
        indicator_data = {
            "extended": {"notes": "Test description"},
            "confidence": 85,
            "threat_level": 75,
            "class": "MalwareC2",
            "property": "TestMalware",
        }
        feed_tags = ["nested-test"]
        tlp_color = "RED"

        fields = extract_indicator_fields(indicator_data, feed_tags, tlp_color)

        assert fields["description"] == "Test description"
        assert fields["confidence"] == 85
        assert fields["sourcepriority"] == 75
        assert fields["category"] == "MalwareC2"
        assert fields["malwarefamily"] == "TestMalware"
        assert fields["tags"] == ["nested-test"]
        assert fields["trafficlightprotocol"] == "RED"

    def test_extract_indicator_fields_type_conversions(self):
        """Test extract_indicator_fields with different type conversions"""
        indicator_data = {
            "threat_level": "90",  # String that should convert to int
            "up": "true",  # String that should convert to bool
            "confidence": 95.5,  # Float that should stay as is
            "received": "2023-01-01T00:00:00Z",  # Date field
        }

        fields = extract_indicator_fields(indicator_data)

        assert fields["sourcepriority"] == 90  # Converted to int
        assert fields["state"] == "true"  # Bool conversion (stored as string in this implementation)
        assert fields["confidence"] == 95.5
        assert fields["lastseenbysource"] == "2023-01-01T00:00:00Z"

    def test_extract_indicator_fields_invalid_int_conversion(self):
        """Test extract_indicator_fields with invalid int conversion"""
        indicator_data = {"threat_level": "invalid_number"}

        fields = extract_indicator_fields(indicator_data)

        # Should not include the field if conversion fails
        assert "sourcepriority" not in fields

    def test_extract_indicator_fields_missing_nested_path(self):
        """Test extract_indicator_fields with missing nested path"""
        indicator_data = {
            "extended": {}  # Missing notes field
        }

        fields = extract_indicator_fields(indicator_data)

        # Should not include description if nested path doesn't exist
        assert "description" not in fields

    def test_extract_indicator_fields_default_values(self):
        """Test extract_indicator_fields with default values"""
        indicator_data = {}

        fields = extract_indicator_fields(indicator_data)

        # Should include default TLP value
        assert fields["trafficlightprotocol"] == "AMBER"

    def test_validate_str_param_none_required(self):
        """Test validate_str_param with None parameter when required"""
        with pytest.raises(DemistoException) as e:
            validate_str_param(None, "test_param", required=True)
        assert "Missing required parameter 'test_param'" in str(e.value)

    def test_validate_str_param_unconvertible_object(self):
        """Test validate_str_param with object that cannot be converted to string"""

        class UnconvertibleObject:
            def __str__(self):
                raise ValueError("Cannot convert to string")

        with pytest.raises(DemistoException) as e:
            validate_str_param(UnconvertibleObject(), "test_param")
        assert "Parameter 'test_param' must be a string or convertible to string" in str(e.value)

    def test_validate_str_param_empty_string_required(self):
        """Test validate_str_param with empty string when required"""
        with pytest.raises(DemistoException) as e:
            validate_str_param("", "test_param", required=True)
        assert "Parameter 'test_param' cannot be empty" in str(e.value)

    def test_validate_int_param_none_required_exception(self):
        """Test validate_int_param with None parameter when required raises exception"""
        with pytest.raises(DemistoException) as e:
            validate_int_param(None, "test_param", required=True)
        assert "Missing required parameter 'test_param'" in str(e.value)

    def test_validate_int_param_empty_string_required_exception(self):
        """Test validate_int_param with empty string when required raises exception"""
        with pytest.raises(DemistoException) as e:
            validate_int_param("", "test_param", required=True)
        assert "Parameter 'test_param' cannot be empty" in str(e.value)

    def test_validate_int_param_list_type_exception(self):
        """Test validate_int_param with list type raises exception"""
        with pytest.raises(DemistoException) as e:
            validate_int_param([1, 2, 3], "test_param")
        assert "Cannot convert list to int" in str(e.value)

    def test_validate_int_param_invalid_string_exception(self):
        """Test validate_int_param with invalid string raises exception"""
        with pytest.raises(DemistoException) as e:
            validate_int_param("not_a_number", "test_param")
        assert "Parameter 'test_param' must be a valid integer" in str(e.value)

    def test_validate_int_param_min_val_exception(self):
        """Test validate_int_param with value below minimum raises exception"""
        with pytest.raises(DemistoException) as e:
            validate_int_param(5, "test_param", min_val=10)
        assert "Parameter 'test_param' must be at least 10" in str(e.value)

    def test_validate_int_param_max_val_exception(self):
        """Test validate_int_param with value above maximum raises exception"""
        with pytest.raises(DemistoException) as e:
            validate_int_param(100, "test_param", max_val=50)
        assert "Parameter 'test_param' must be at most 50" in str(e.value)
