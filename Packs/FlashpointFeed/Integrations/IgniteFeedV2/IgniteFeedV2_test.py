"""Flashpoint Ignite Feed V2 Integration for Cortex XSOAR - Unit Tests file"""

import json
import os
import sys

import pytest
from requests.exceptions import HTTPError

import IgniteFeedV2
from CommonServerPython import DemistoException
from IgniteFeedV2 import (
    HTTP_ERRORS,
    MAX_FETCH,
    MESSAGES,
    URL_SUFFIX,
    Client,
    demisto,
    fetch_indicators_command,
    flashpoint_ignite_v2_get_indicators_command,
    main,
    convert_types_to_ioc_types,
    validate_get_indicators_args,
    validate_fetch_indicators_params,
    prepare_hr_for_indicators,
    remove_space_from_args,
    validate_score_params,
)
from IgniteFeedV2 import test_module as main_test_module

""" CONSTANTS """

API_KEY = "dummy_api_key"
MOCK_URL = "https://mock_dummy.com"

""" UTILITY FUNCTIONS AND FIXTURES """


def util_load_json(path):
    """
    Load json file into dictionary.

    :param path: Takes file path.

    :return: Dictionary.
    """
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def mock_client():
    """Mock a client object with required data to mock."""
    client = Client(url=MOCK_URL, headers={}, proxy=False, verify=False)
    return client


class MockResponse:
    """Creates mock response."""

    def __init__(self, status_code, json_data=None, headers=None):
        """Initialize class object."""
        self.status_code = status_code
        self._json_data = json_data or {}
        self.headers = headers or {}

    def json(self):
        """Return json data."""
        return self._json_data

    def raise_for_status(self):
        """Raise status code error."""
        if self.status_code != 200:
            raise HTTPError("test")


""" TEST CASES """


class TestTestModule:
    """Test cases for test_module function."""

    def test_test_module_with_invalid_apikey(self, requests_mock, mock_client):
        """
        Test case scenario for the execution of test_module with invalid apikey.

        Given:
           - mocked client with invalid apikey.
        When:
           - Calling `test_module` function.
        Then:
           - Returns exception.
        """
        indicator_list_response_401: str = util_load_json(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/invalid_apikey_401.json")
        )
        requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["INDICATORS"]), json=indicator_list_response_401, status_code=401)

        with pytest.raises(DemistoException) as err:
            main_test_module(client=mock_client)

        assert str(err.value) == HTTP_ERRORS[401]

    def test_test_module_with_valid_apikey(self, requests_mock, mock_client):
        """
        Test case scenario for successful execution of test_module.

        Given:
           - mocked client with valid apikey.
        When:
           - Calling `test_module` function.
        Then:
           - Returns an ok message.
        """
        indicator_list_response_200: dict = util_load_json(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/indicator_list_v2_200.json")
        )
        requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["INDICATORS"]), json=indicator_list_response_200, status_code=200)

        assert main_test_module(client=mock_client) == "ok"

    @pytest.mark.parametrize(
        "params, err_msg",
        [
            (
                {"url": "", "credentials": {"password": API_KEY}, "integrationReliability": "B - Usually reliable"},
                MESSAGES["NO_PARAM_PROVIDED"].format("Server URL"),
            ),
            (
                {"url": MOCK_URL, "credentials": "", "integrationReliability": "B - Usually reliable"},
                MESSAGES["NO_PARAM_PROVIDED"].format("API Key"),
            ),
        ],
    )
    def test_test_module_when_invalid_params_provided(self, params, err_msg, mocker, capfd):
        """
        Test case scenario for execution of test_module when invalid argument provided.

        Given:
            - Params for test_module.
        When:
            - Calling `main` function.
        Then:
            - Returns exception.
        """
        mocker.patch.object(demisto, "params", return_value=params)
        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(sys, "exit", return_value=None)

        return_error = mocker.patch.object(IgniteFeedV2, "return_error")
        capfd.close()
        main()

        assert err_msg in return_error.call_args[0][0]

    def test_test_module_with_isfetch(self, requests_mock, mocker, mock_client):
        """
        Test case scenario for successful execution of test_module with feed enabled.

        Given:
           - mocked client with valid apikey and feed enabled.
        When:
           - Calling `test_module` function.
        Then:
           - Returns an ok message.
        """
        requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["INDICATORS"]), json={"items": []}, status_code=200)
        mocker.patch.object(demisto, "params", return_value={"feed": True, "url": MOCK_URL, "credentials": {"password": API_KEY}})

        assert main_test_module(mock_client) == "ok"


class TestHttpRequest:
    """Test cases for http_request method."""

    @pytest.mark.parametrize("status_code", [400, 401, 403, 404, 500])
    def test_http_request_when_error_is_returned(self, requests_mock, mock_client, status_code):
        """
        Tests http_request method of Client class.

        Given:
            - Status codes of requests.
        When:
            - Calling `http_request` function.
        Then:
            - Returns exception.
        """
        requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["INDICATORS"]), status_code=status_code)

        with pytest.raises(DemistoException) as e:
            mock_client.http_request(method="GET", url_suffix=URL_SUFFIX["INDICATORS"], params={})

        assert str(e.value) == HTTP_ERRORS[status_code]

    def test_http_request_when_raise_for_status(self, mock_client):
        """Tests http_request when error raised for status."""
        resp = MockResponse(status_code=503)

        with pytest.raises(HTTPError):
            mock_client.handle_errors(resp)

    def test_http_request_when_422_validation_error(self, mock_client):
        """
        Tests handle_errors method when 422 validation error is returned.

        Given:
            - 422 status code with validation error response.
        When:
            - Calling `handle_errors` function.
        Then:
            - Returns meaningful validation error message.
        """
        validation_error_response = {
            "detail": "Request Validation Error",
            "errors": [
                {
                    "type": "ip_any_network",
                    "loc": ["query", "cidr_range"],
                    "msg": "value is not a valid IPv4 or IPv6 network",
                    "input": "0.0.0.1/24",
                }
            ],
        }
        resp = MockResponse(status_code=422, json_data=validation_error_response)

        with pytest.raises(DemistoException) as e:
            mock_client.handle_errors(resp)

        assert "Validation Error" in str(e.value)
        assert "cidr_range" in str(e.value)
        assert "value is not a valid IPv4 or IPv6 network" in str(e.value)
        assert "0.0.0.1/24" in str(e.value)

    def test_parse_validation_error_multiple_errors(self, mock_client):
        """
        Tests parse_validation_error with multiple validation errors.

        Given:
            - Response with multiple validation errors.
        When:
            - Calling `parse_validation_error` method.
        Then:
            - Returns formatted error message with all errors.
        """

        class MockResp:
            def json(self):
                return {
                    "detail": "Request Validation Error",
                    "errors": [
                        {"loc": ["query", "min_score"], "msg": "invalid value", "input": "bad"},
                        {"loc": ["query", "max_score"], "msg": "invalid value", "input": "worse"},
                    ],
                }

        result = mock_client.parse_validation_error(MockResp())
        assert "Validation Error" in result
        assert "min_score" in result
        assert "max_score" in result


class TestGetIndicatorsCommand:
    """Test cases for flashpoint_ignite_v2_get_indicators_command."""

    def test_get_indicators_command_when_invalid_argument_provided(self, mock_client):
        """
        Test case scenario for execution of flashpoint-ignite-get-indicators command when invalid argument provided.

        Given:
            - command arguments for flashpoint_ignite_v2_get_indicators_command.
        When:
            - Calling `flashpoint_ignite_v2_get_indicators_command` function.
        Then:
            - Returns a valid error message.
        """
        with pytest.raises(ValueError) as err:
            flashpoint_ignite_v2_get_indicators_command(client=mock_client, params={}, args={"limit": -1})

        assert str(err.value) == MESSAGES["LIMIT_ERROR"].format(-1, MAX_FETCH)

    def test_get_indicators_command_when_limit_exceeds_max(self, mock_client):
        """
        Test case scenario when limit exceeds maximum allowed.

        Given:
            - command arguments with limit exceeding MAX_FETCH.
        When:
            - Calling `flashpoint_ignite_v2_get_indicators_command` function.
        Then:
            - Returns a valid error message.
        """
        with pytest.raises(ValueError) as err:
            flashpoint_ignite_v2_get_indicators_command(client=mock_client, params={}, args={"limit": MAX_FETCH + 1})

        assert str(err.value) == MESSAGES["LIMIT_ERROR"].format(MAX_FETCH + 1, MAX_FETCH)

    def test_get_indicators_command_when_valid_response_is_returned(self, requests_mock, mock_client):
        """
        Test case scenario for execution of flashpoint-ignite-get-indicators command when valid response is returned.

        Given:
            - command arguments for flashpoint_ignite_v2_get_indicators_command.
        When:
            - Calling `flashpoint_ignite_v2_get_indicators_command` function.
        Then:
            - Returns a valid output.
        """
        args = {"limit": 2}

        indicator_list_response_200: dict = util_load_json(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/indicator_list_v2_200.json")
        )

        requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["INDICATORS"]), json=indicator_list_response_200, status_code=200)

        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/indicator_list_v2_hr.md")) as file:
            hr_output = file.read()

        indicators: dict = util_load_json(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/indicators_v2.json")
        )

        actual = flashpoint_ignite_v2_get_indicators_command(client=mock_client, params={"tlp_color": "AMBER"}, args=args)

        assert actual.raw_response == indicators
        assert actual.readable_output == hr_output

    def test_get_indicators_command_when_create_relationship_is_true(self, requests_mock, mock_client):
        """
        Test case scenario for execution of flashpoint-ignite-get-indicators command when create relationship is true.

        Given:
            - command arguments for flashpoint_ignite_v2_get_indicators_command.
        When:
            - Calling `flashpoint_ignite_v2_get_indicators_command` function.
        Then:
            - Returns a valid output with relationships.
        """
        args = {"limit": 2}

        indicator_list_response_200: dict = util_load_json(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/indicator_list_v2_200.json")
        )

        requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["INDICATORS"]), json=indicator_list_response_200, status_code=200)

        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/indicator_list_v2_hr.md")) as file:
            hr_output = file.read()

        indicators: dict = util_load_json(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/indicators_v2_with_relationship.json")
        )

        actual = flashpoint_ignite_v2_get_indicators_command(client=mock_client, params={"createRelationship": True}, args=args)

        assert actual.raw_response == indicators
        assert actual.readable_output == hr_output

    def test_get_indicators_command_when_empty_response_is_returned(self, requests_mock, mock_client):
        """
        Test case scenario for execution of flashpoint-ignite-get-indicators command when empty response is returned.

        Given:
            - command arguments for flashpoint_ignite_v2_get_indicators_command.
        When:
            - Calling `flashpoint_ignite_v2_get_indicators_command` function.
        Then:
            - Returns a no indicator message.
        """
        args = {"limit": 2}

        requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["INDICATORS"]), json={"items": []}, status_code=200)

        actual = flashpoint_ignite_v2_get_indicators_command(client=mock_client, params={}, args=args)

        assert actual.readable_output == MESSAGES["NO_INDICATORS_FOUND"]


class TestFetchIndicatorsCommand:
    """Test cases for fetch_indicators_command."""

    def test_fetch_indicators_command_when_valid_response_is_returned(self, requests_mock, mock_client):
        """
        Test case scenario for execution of fetch-indicators command when valid response is returned.

        Given:
            - command arguments for fetch_indicators_command.
        When:
            - Calling `fetch_indicators_command` function.
        Then:
            - Returns a valid output.
        """
        indicator_list_response_200: dict = util_load_json(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/indicator_list_v2_200.json")
        )

        requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["INDICATORS"]), json=indicator_list_response_200, status_code=200)

        indicators: dict = util_load_json(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/indicators_v2.json")
        )

        result = fetch_indicators_command(client=mock_client, params={"tlp_color": "AMBER"}, last_run={})
        assert result[0] == indicators

    def test_fetch_indicators_command_pagination(self, requests_mock, mock_client):
        """
        Test case scenario for fetch-indicators command pagination.

        Given:
            - Previous last_run with offset.
        When:
            - Calling `fetch_indicators_command` function.
        Then:
            - Returns correct next_run with updated offset.
        """
        indicator_list_response_200: dict = util_load_json(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/indicator_list_v2_200.json")
        )

        requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["INDICATORS"]), json=indicator_list_response_200, status_code=200)

        last_run = {"next_modified_after": "2024-04-01T00:00:00Z", "next_modified_before": "2024-04-15T00:00:00Z", "offset": 0}

        _, next_run = fetch_indicators_command(client=mock_client, params={}, last_run=last_run)

        # Since we got less than MAX_FETCH, next_run should update modified_after
        assert "next_modified_after" in next_run

    def test_fetch_indicators_command_empty_response(self, requests_mock, mock_client):
        """
        Test case scenario for fetch-indicators command with empty response.

        Given:
            - Empty response from API.
        When:
            - Calling `fetch_indicators_command` function.
        Then:
            - Returns empty indicators list.
        """
        requests_mock.get(os.path.join(MOCK_URL, URL_SUFFIX["INDICATORS"]), json={"items": []}, status_code=200)

        indicators, _ = fetch_indicators_command(client=mock_client, params={}, last_run={})

        assert indicators == []


class TestHelperFunctions:
    """Test cases for helper functions."""

    def test_convert_types_to_ioc_types(self):
        """
        Test case for convert_types_to_ioc_types function.

        Given:
            - List of indicator types.
        When:
            - Calling `convert_types_to_ioc_types` function.
        Then:
            - Returns correct ioc_types string.
        """
        types_list = ["IPv4", "IPv6", "Domain", "URL"]
        result = convert_types_to_ioc_types(types_list)

        assert "ipv4" in result
        assert "ipv6" in result
        assert "domain" in result
        assert "url" in result

    def test_convert_types_to_ioc_types_empty(self):
        """
        Test case for convert_types_to_ioc_types with empty list.

        Given:
            - Empty list.
        When:
            - Calling `convert_types_to_ioc_types` function.
        Then:
            - Returns empty string.
        """
        result = convert_types_to_ioc_types([])
        assert result == ""

    def test_validate_get_indicators_args(self):
        """
        Test case for validate_get_indicators_args function.

        Given:
            - Valid arguments.
        When:
            - Calling `validate_get_indicators_args` function.
        Then:
            - Returns correctly formatted params for v2 API.
        """
        args = {"limit": 10, "types": "IPv4,Domain", "updated_since": "3 days"}
        result = validate_get_indicators_args(args)

        assert result["size"] == 10
        assert "ioc_types" in result
        assert "modified_after" in result
        assert result["sort"] == "modified_at:asc"
        assert result["embed"] == "all"

    def test_validate_fetch_indicators_params(self):
        """
        Test case for validate_fetch_indicators_params function.

        Given:
            - Parameters and last_run.
        When:
            - Calling `validate_fetch_indicators_params` function.
        Then:
            - Returns correctly formatted params for v2 API.
        """
        params = {"types": ["IPv4", "Domain"], "first_fetch": "3 days"}
        last_run: dict = {}
        result = validate_fetch_indicators_params(params, last_run)

        assert "size" in result
        assert "modified_after" in result
        assert "modified_before" in result
        assert result["sort"] == "modified_at:asc"
        assert result["embed"] == "all"

    def test_remove_space_from_args(self):
        """
        Test case for remove_space_from_args function.

        Given:
            - Arguments with spaces.
        When:
            - Calling `remove_space_from_args` function.
        Then:
            - Returns arguments without leading/trailing spaces.
        """
        args = {"key1": "  value1  ", "key2": "value2", "key3": 123}
        result = remove_space_from_args(args)

        assert result["key1"] == "value1"
        assert result["key2"] == "value2"
        assert result["key3"] == 123

    def test_validate_get_indicators_args_invalid_types(self):
        """
        Test case for validate_get_indicators_args with invalid types.

        Given:
            - Arguments with invalid types.
        When:
            - Calling `validate_get_indicators_args` function.
        Then:
            - Raises ValueError with INVALID_TYPES message.
        """
        args = {"limit": 10, "types": "InvalidType"}
        with pytest.raises(ValueError) as err:
            validate_get_indicators_args(args)

        assert MESSAGES["INVALID_TYPES"].format("['InvalidType']") in str(err.value)

    def test_validate_score_params_valid(self):
        """
        Test case for validate_score_params with valid scores.

        Given:
            - Valid min_score and max_score values.
        When:
            - Calling `validate_score_params` function.
        Then:
            - Returns correct lowercase score values.
        """
        min_val, max_val = validate_score_params("Suspicious", "Malicious")
        assert min_val == "suspicious"
        assert max_val == "malicious"

    def test_validate_score_params_invalid_score(self):
        """
        Test case for validate_score_params with invalid score.

        Given:
            - Invalid score value.
        When:
            - Calling `validate_score_params` function.
        Then:
            - Raises ValueError with INVALID_SCORE message.
        """
        with pytest.raises(ValueError) as err:
            validate_score_params("InvalidScore", None)
        assert MESSAGES["INVALID_SCORE"].format("InvalidScore") in str(err.value)

    def test_validate_score_params_invalid_range(self):
        """
        Test case for validate_score_params with invalid range.

        Given:
            - min_score greater than max_score.
        When:
            - Calling `validate_score_params` function.
        Then:
            - Raises ValueError with INVALID_SCORE_RANGE message.
        """
        with pytest.raises(ValueError) as err:
            validate_score_params("Malicious", "Informational")
        assert MESSAGES["INVALID_SCORE_RANGE"] in str(err.value)

    def test_validate_fetch_indicators_params_with_new_params(self):
        """
        Test case for validate_fetch_indicators_params with new filter params.

        Given:
            - Parameters with new filter options.
        When:
            - Calling `validate_fetch_indicators_params` function.
        Then:
            - Returns params with all new filters applied.
        """
        params = {
            "types": ["IPv4"],
            "first_fetch": "3 days",
            "cidr_range": "0.0.0.1/16",
            "min_score": "Suspicious",
            "max_score": "Malicious",
            "mitre_attack_ids": ["T1001", "T1002"],
            "tags": ["tag1", "tag2"],
            "actor_tags": ["actor1"],
            "malware_tags": ["malware1"],
            "source_tags": ["source1"],
        }
        last_run: dict = {}
        result = validate_fetch_indicators_params(params, last_run)

        assert result["size"] == 500
        assert result["ioc_types"] == "ipv4"
        assert result["cidr_range"] == "0.0.0.1/16"
        assert result["min_score"] == "suspicious"
        assert result["max_score"] == "malicious"
        assert result["mitre_attack_ids"] == "T1001,T1002"
        assert result["tags"] == "tag1,tag2"
        assert result["actors"] == "actor1"
        assert result["malware"] == "malware1"
        assert result["sources"] == "source1"


class TestClientMethods:
    """Test cases for Client class methods."""

    def test_check_indicator_type_auto_detect(self, mock_client):
        """
        Test case for check_indicator_type with auto detection.

        Given:
            - IP address indicator value.
        When:
            - Calling `check_indicator_type` with default_map=False.
        Then:
            - Returns detected IP type.
        """
        result = mock_client.check_indicator_type("0.0.0.1", indicator_type="ipv4", default_map=False)
        assert result == "IP"

    def test_check_indicator_type_default_map(self, mock_client):
        """
        Test case for check_indicator_type with default mapping.

        Given:
            - Any indicator value.
        When:
            - Calling `check_indicator_type` with default_map=True.
        Then:
            - Returns default Ignite Indicator type.
        """
        result = mock_client.check_indicator_type("0.0.0.1", indicator_type="ipv4", default_map=True)
        assert result == "Ignite Indicator"

    def test_get_nested_value(self, mock_client):
        """
        Test case for _get_nested_value method.

        Given:
            - Nested dictionary and path.
        When:
            - Calling `_get_nested_value` method.
        Then:
            - Returns correct nested value.
        """
        data = {"level1": {"level2": {"value": "test_value"}}}
        result = mock_client._get_nested_value(data, "level1.level2.value")
        assert result == "test_value"

    def test_get_nested_value_not_found(self, mock_client):
        """
        Test case for _get_nested_value with non-existent path.

        Given:
            - Dictionary and non-existent path.
        When:
            - Calling `_get_nested_value` method.
        Then:
            - Returns None.
        """
        data = {"level1": {"level2": "value"}}
        result = mock_client._get_nested_value(data, "level1.level3.value")
        assert result is None

    def test_create_indicators_from_response(self, mock_client):
        """
        Test case for create_indicators_from_response method.

        Given:
            - V2 API response items.
        When:
            - Calling `create_indicators_from_response` method.
        Then:
            - Returns correctly formatted indicators.
        """
        api_responses = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/api_responses.json"))
        response = api_responses["ipv4"]

        params = {"feedTags": ["tag1"], "tlp_color": "AMBER"}
        indicators = mock_client.create_indicators_from_response(response, params)

        assert len(indicators) == 1
        assert indicators[0]["value"] == "0.0.0.1"
        assert indicators[0]["type"] == "IP"
        assert indicators[0]["fields"]["trafficlightprotocol"] == "AMBER"
        assert indicators[0]["fields"]["flashpointfeedindicatorid"] == "dummy-id-1"
        assert indicators[0]["fields"]["flashpointfeedindicatortype"] == "ipv4"

    def test_create_indicators_from_response_file_type(self, mock_client):
        """
        Test case for create_indicators_from_response with file type indicator.

        Given:
            - V2 API response with file type indicator.
        When:
            - Calling `create_indicators_from_response` method.
        Then:
            - Returns indicator with value from API response.
        """
        api_responses = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/api_responses.json"))
        response = api_responses["file"]

        params: dict = {}
        indicators = mock_client.create_indicators_from_response(response, params)

        assert len(indicators) == 1
        assert indicators[0]["value"] == "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        assert indicators[0]["fields"]["sha256"] == "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

    def test_map_indicator_fields(self, mock_client):
        """
        Test case for map_indicator_fields method.

        Given:
            - V2 API response item and indicator object.
        When:
            - Calling `map_indicator_fields` method.
        Then:
            - Correctly maps all fields.
        """
        api_responses = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/api_responses.json"))
        resp = api_responses["map_indicator_fields"]

        indicator_obj: dict = {"fields": {"tags": []}}
        mock_client.map_indicator_fields(resp, indicator_obj)

        assert indicator_obj["fields"]["flashpointfeedindicatorid"] == "dummy-id-1"
        assert indicator_obj["fields"]["flashpointfeedindicatortype"] == "ipv4"
        assert indicator_obj["fields"]["flashpointfeedtotalsightings"] == 5
        assert indicator_obj["fields"]["flashpointfeedcreateddate"] == "2026-01-01T00:00:00Z"
        assert indicator_obj["fields"]["flashpointfeedlastseendate"] == "2026-01-01T00:00:00Z"
        assert indicator_obj["fields"]["flashpointfeedapi"] == "https://api.example.com/indicators/dummy-id-1"
        assert indicator_obj["fields"]["flashpointfeedplatformurl"] == "https://app.example.com/iocs/dummy-id-1"
        assert indicator_obj["fields"]["flashpointfeedlastscoredate"] == "2026-01-01T00:00:00Z"
        assert indicator_obj["fields"]["flashpointfeedmodifieddate"] == "2026-01-01T00:00:00Z"


class TestPrepareHrForIndicators:
    """Test cases for prepare_hr_for_indicators function."""

    def test_prepare_hr_for_indicators(self):
        """
        Test case for prepare_hr_for_indicators function.

        Given:
            - List of indicators.
        When:
            - Calling `prepare_hr_for_indicators` function.
        Then:
            - Returns correctly formatted markdown table.
        """
        hr_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/hr_indicators.json"))
        indicators = hr_data["ipv4"]

        result = prepare_hr_for_indicators(indicators)

        assert "### Indicator(s)" in result
        assert "dummy-id-1" in result
        assert "0.0.0.1" in result
        assert "malicious" in result

    def test_prepare_hr_for_indicators_file_type(self):
        """
        Test case for prepare_hr_for_indicators with file type.

        Given:
            - File type indicator with hashes.
        When:
            - Calling `prepare_hr_for_indicators` function.
        Then:
            - Returns File as indicator type and uses SHA256 hash.
        """
        hr_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/hr_indicators.json"))
        indicators = hr_data["file"]

        result = prepare_hr_for_indicators(indicators)

        assert "file" in result
        assert "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" in result

    def test_prepare_hr_for_indicators_with_new_fields(self):
        """
        Test case for prepare_hr_for_indicators with new fields.

        Given:
            - Indicator with APT description, malware description, MITRE IDs, etc.
        When:
            - Calling `prepare_hr_for_indicators` function.
        Then:
            - Returns markdown with all new fields.
        """
        hr_data = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/hr_indicators.json"))
        indicators = hr_data["with_new_fields"]

        result = prepare_hr_for_indicators(indicators)

        assert "### Indicator(s)" in result
        assert "0.0.0.1" in result
        assert "malicious" in result


class TestValidateGetIndicatorsArgsNewParams:
    """Test cases for validate_get_indicators_args with new parameters."""

    def test_validate_get_indicators_args_with_from_parameter(self):
        """
        Test case for validate_get_indicators_args with from parameter.

        Given:
            - Valid from parameter.
        When:
            - Calling `validate_get_indicators_args` function.
        Then:
            - Returns params with correct from value.
        """
        args = {"limit": 10, "from": 100}
        result = validate_get_indicators_args(args)

        assert result["from"] == 100
        assert result["size"] == 10

    def test_validate_get_indicators_args_with_negative_from(self):
        """
        Test case for validate_get_indicators_args with negative from.

        Given:
            - Negative from parameter.
        When:
            - Calling `validate_get_indicators_args` function.
        Then:
            - Raises ValueError with FROM_ERROR message.
        """
        args = {"limit": 10, "from": -5}
        with pytest.raises(ValueError) as err:
            validate_get_indicators_args(args)

        assert MESSAGES["FROM_ERROR"].format(args.get("from")) in str(err.value)

    def test_validate_get_indicators_args_with_all_new_params(self):
        """
        Test case for validate_get_indicators_args with all new filter params.

        Given:
            - Arguments with all new filter parameters.
        When:
            - Calling `validate_get_indicators_args` function.
        Then:
            - Returns params with all filters applied.
        """
        args = {
            "limit": 50,
            "from": 0,
            "cidr_range": "0.0.0.1/8",
            "min_severity_level": "Informational",
            "max_severity_level": "Malicious",
            "mitre_attack_ids": "T1001,T1002",
            "tags": "tag1,tag2",
            "actor_tags": "actor1",
            "malware_tags": "malware1",
            "source_tags": "source1",
        }
        result = validate_get_indicators_args(args)

        assert result["size"] == 50
        assert result["from"] == 0
        assert result["cidr_range"] == "0.0.0.1/8"
        assert result["min_score"] == "informational"
        assert result["max_score"] == "malicious"
        assert result["mitre_attack_ids"] == "T1001,T1002"
        assert result["tags"] == "tag1,tag2"
        assert result["actors"] == "actor1"
        assert result["malware"] == "malware1"
        assert result["sources"] == "source1"
        assert result["embed"] == "all"
        assert result["sort"] == "modified_at:asc"

    def test_validate_get_indicators_args_without_optional_params(self):
        """
        Test case for validate_get_indicators_args without optional params.

        Given:
            - Only required arguments (limit).
        When:
            - Calling `validate_get_indicators_args` function.
        Then:
            - Returns params without optional filter fields.
        """
        args = {"limit": 10}
        result = validate_get_indicators_args(args)

        assert result["size"] == 10
        assert result["from"] == 0
        assert "cidr_range" not in result
        assert "min_score" not in result
        assert "max_score" not in result


class TestParseValidationErrorEdgeCases:
    """Test cases for parse_validation_error edge cases."""

    def test_parse_validation_error_no_errors_array(self, mock_client):
        """
        Test parse_validation_error when errors array is empty.

        Given:
            - Response with empty errors array.
        When:
            - Calling `parse_validation_error` method.
        Then:
            - Returns error with detail message.
        """

        class MockResp:
            def json(self):
                return {"detail": "Request Validation Error", "errors": []}

        result = mock_client.parse_validation_error(MockResp())
        assert "Validation Error" in result

    def test_parse_validation_error_without_input(self, mock_client):
        """
        Test parse_validation_error when input field is missing.

        Given:
            - Response with error missing input field.
        When:
            - Calling `parse_validation_error` method.
        Then:
            - Returns error message without input.
        """

        class MockResp:
            def json(self):
                return {"detail": "Request Validation Error", "errors": [{"loc": ["query", "param"], "msg": "invalid"}]}

        result = mock_client.parse_validation_error(MockResp())
        assert "param: invalid" in result
        assert "input:" not in result

    def test_parse_validation_error_json_exception(self, mock_client):
        """
        Test parse_validation_error when json parsing fails.

        Given:
            - Response that raises exception on json().
        When:
            - Calling `parse_validation_error` method.
        Then:
            - Returns default HTTP error message.
        """

        class MockResp:
            def json(self):
                raise ValueError("Invalid JSON")

        result = mock_client.parse_validation_error(MockResp())
        assert result == HTTP_ERRORS[422]


class TestValidateScoreParamsEdgeCases:
    """Test cases for validate_score_params edge cases."""

    def test_validate_score_params_only_min(self):
        """
        Test validate_score_params with only min_score.

        Given:
            - Only min_score provided.
        When:
            - Calling `validate_score_params` function.
        Then:
            - Returns min_score and None for max_score.
        """
        min_val, max_val = validate_score_params("Informational", None)
        assert min_val == "informational"
        assert max_val is None

    def test_validate_score_params_only_max(self):
        """
        Test validate_score_params with only max_score.

        Given:
            - Only max_score provided.
        When:
            - Calling `validate_score_params` function.
        Then:
            - Returns None for min_score and max_score value.
        """
        min_val, max_val = validate_score_params(None, "Suspicious")
        assert min_val is None
        assert max_val == "suspicious"

    def test_validate_score_params_both_none(self):
        """
        Test validate_score_params with both None.

        Given:
            - Both min_score and max_score are None.
        When:
            - Calling `validate_score_params` function.
        Then:
            - Returns None for both.
        """
        min_val, max_val = validate_score_params(None, None)
        assert min_val is None
        assert max_val is None

    def test_validate_score_params_same_value(self):
        """
        Test validate_score_params with same min and max.

        Given:
            - Same value for min_score and max_score.
        When:
            - Calling `validate_score_params` function.
        Then:
            - Returns same value for both (no error).
        """
        min_val, max_val = validate_score_params("Suspicious", "Suspicious")
        assert min_val == "suspicious"
        assert max_val == "suspicious"

    def test_validate_score_params_case_insensitive(self):
        """
        Test validate_score_params is case insensitive.

        Given:
            - Score values in different cases.
        When:
            - Calling `validate_score_params` function.
        Then:
            - Returns lowercase values.
        """
        min_val, max_val = validate_score_params("INFORMATIONAL", "MALICIOUS")
        assert min_val == "informational"
        assert max_val == "malicious"
