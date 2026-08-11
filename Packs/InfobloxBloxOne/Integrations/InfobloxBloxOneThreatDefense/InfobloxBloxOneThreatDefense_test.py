import json
from pathlib import Path

import pytest
from copy import deepcopy
from freezegun import freeze_time
from unittest.mock import patch, call
from InfobloxBloxOneThreatDefense import *

TEST_PATH = Path(__file__).parent / "test_data"


def load_json_file(file_description):
    file_path = TEST_PATH / f"{file_description}.json"
    with open(file_path) as f:
        return f.read()


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
def blox_client() -> BloxOneTDClient:
    return BloxOneTDClient("")


@pytest.fixture
def mock_results(mocker):
    return mocker.patch.object(demisto, "results")


@pytest.fixture(autouse=True)
def mock_demisto_version(mocker):
    return mocker.patch.object(demisto, "demistoVersion", return_value={"version": "6.5.0", "buildNumber": "12345"})


def patch_command_args_and_params(mocker, command, args):
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "params", return_value={"credentials": {"password": ""}})


class TestE2E:
    def test_dossier_source_list_command(self, requests_mock, mocker, mock_results):
        patch_command_args_and_params(mocker, "bloxone-td-dossier-source-list", {})
        request_call = requests_mock.get(
            f"{BASE_URL}/tide/api/services/intel/lookup/sources",
            text=load_json_file("bloxone-td-dossier-source-list"),
        )
        res_list = ["dns", "geo", "ptr", "whois", "ssl_cert", "urlhaus"]
        main()
        assert mock_results.call_args[0][0]["EntryContext"]["BloxOneTD"]["DossierSource"] == res_list
        assert mock_results.call_args[0][0]["Contents"]["DossierSource"] == res_list
        assert request_call.called_once

    def test_lookalike_domain_list_command(self, requests_mock, mocker, mock_results):
        patch_command_args_and_params(mocker, "bloxone-td-lookalike-domain-list", {"target_domain": "test.com"})
        request_call = requests_mock.get(
            f"{BASE_URL}/api/tdlad/v1/lookalike_domains",
            text=load_json_file("bloxone-td-lookalike-domain-list"),
        )

        main()
        assert request_call.called_once
        assert request_call.request_history[0].qs["_filter"][0].startswith("target_domain")
        raw = mock_results.call_args[0][0]["Contents"]
        assert raw
        assert mock_results.call_args[0][0]["EntryContext"]["BloxOneTD.LookalikeDomain"] == raw

    def test_lookalike_domain_list_command_with_invalid_args(self, mocker, mock_results):
        mocker.patch.object(BloxOneTDClient, "attach_customer_tracking_header")
        patch_command_args_and_params(
            mocker,
            "bloxone-td-lookalike-domain-list",
            {"target_domain": "test.com", "filter": "test"},
        )
        with pytest.raises(SystemExit):
            main()
        assert mock_results.call_args[0][0]["Type"] == 4
        assert "Exactly one of them, more than one is argument is not accepted" in mock_results.call_args[0][0]["Contents"]

    def test_dossier_lookup_get_command(self, requests_mock, mocker, mock_results):
        job_id = "c924d233-ddeb-8877-1234-fedd6a9bb070"
        create_job_request_mock = requests_mock.get(
            f"{BASE_URL}/tide/api/services/intel/lookup/indicator/ip",
            text=load_json_file("bloxone-td-dossier-lookup-get_create-job"),
        )
        results_request_mock = requests_mock.get(
            f"{BASE_URL}/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/results",
            text=load_json_file("bloxone-td-dossier-lookup-get_results"),
        )
        pending_request_mock_data = [
            {"state": "created", "status": "pending"},
            {"state": "created", "status": "pending"},
            {"state": "completed", "status": "success"},
        ]
        pending_request_mock = requests_mock.get(
            f"{BASE_URL}/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/pending",
            text=lambda _x, _y: json.dumps(pending_request_mock_data.pop(0)),
        )

        patch_command_args_and_params(
            mocker,
            "bloxone-td-dossier-lookup-get",
            {
                "indicator_type": "ip",
                "value": "11.22.33.44",
                "sources": "urlhaus,atp,geo",
            },
        )
        # first time the command is running (creating the job + one poll)
        main()
        polling_args = mock_results.call_args[0][0]["PollingArgs"]
        assert mock_results.call_count == 1
        assert isinstance(mock_results.call_args[0][0]["HumanReadable"], str)
        assert polling_args["job_id"] == job_id
        assert polling_args["timeout"] == 590
        assert pending_request_mock.call_count == 1

        patch_command_args_and_params(mocker, "bloxone-td-dossier-lookup-get", polling_args)

        # second time the command is running (second poll)
        main()
        polling_args = mock_results.call_args[0][0]["PollingArgs"]
        assert mock_results.call_count == 2
        assert mock_results.call_args[0][0].get("HumanReadable") is None
        assert polling_args["job_id"] == job_id
        assert polling_args["timeout"] == 580
        assert pending_request_mock.call_count == 2

        # third time the command is running (third poll + get results)
        main()
        assert "PollingArgs" not in mock_results.call_args[0][0]
        assert mock_results.call_count == 3
        assert mock_results.call_args[0][0]["HumanReadable"]
        assert pending_request_mock.call_count == 3

        assert create_job_request_mock.called_once
        assert results_request_mock.called_once

    def test_command_test_module_401(self, requests_mock, mocker, mock_results):
        patch_command_args_and_params(mocker, "test-module", {})
        requests_mock.get(
            f"{BASE_URL}/tide/api/services/intel/lookup/sources",
            status_code=401,
            text="{}",
        )
        with pytest.raises(SystemExit):
            main()

        assert mock_results.call_args[0][0]["Type"] == 4
        assert "an error occurred while executing command test-module" in mock_results.call_args[0][0]["Contents"]
        assert (
            "Error in API call [401] - Encountered error while trying to get information from Infoblox Cloud: "
            "Invalid Service API Key configured." in mock_results.call_args[0][0]["Contents"]
        )

    def test_command_test_module(self, requests_mock, mocker, mock_results):
        patch_command_args_and_params(mocker, "test-module", {})
        request_call = requests_mock.get(f"{BASE_URL}/tide/api/services/intel/lookup/sources", text="{}")
        main()

        assert request_call.called_once
        assert mock_results.call_args[0][0] == "ok"

    def test_command_test_module_with_is_fetch(self, blox_client, requests_mock, mocker):
        """Test command_test_module function with isFetch parameter"""
        # Mock the dossier_source_list API call
        requests_mock.get(f"{BASE_URL}/tide/api/services/intel/lookup/sources", text="{}")

        # Test case 1: isFetch is False (default behavior)
        mock_params = mocker.patch.object(demisto, "params", return_value={"isFetch": False})
        mock_fetch_incidents = mocker.patch("InfobloxBloxOneThreatDefense.fetch_incidents")

        result = command_test_module(blox_client)

        assert result == "ok"
        mock_fetch_incidents.assert_not_called()

        # Test case 2: isFetch is True (should call fetch_incidents with is_test=True)
        mock_params.return_value = {"isFetch": True, "max_fetch": "10", "soc_insight_status": "Active"}

        # Mock the insights API call for fetch_incidents
        requests_mock.get(f"{BASE_URL}/api/v1/insights", json={"insightList": []})

        result = command_test_module(blox_client)

        assert result == "ok"
        mock_fetch_incidents.assert_called_once_with(blox_client, mock_params.return_value, is_test=True)

    def test_command_test_module_with_fetch_validation_error(self, blox_client, requests_mock, mocker):
        """Test command_test_module when fetch_incidents raises validation error"""
        # Mock the dossier_source_list API call
        requests_mock.get(f"{BASE_URL}/tide/api/services/intel/lookup/sources", text="{}")

        # Mock params with invalid max_fetch to trigger validation error
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "isFetch": True,
                "max_fetch": "300",  # Invalid - exceeds 200
            },
        )

        # Mock the insights API call
        requests_mock.get(f"{BASE_URL}/api/v1/insights", json={"insightList": []})
        with pytest.raises(ValueError, match="Invalid Max Fetch: 300"):
            command_test_module(blox_client)

    def test_not_implemented_command(self, mocker):
        mocker.patch.object(BloxOneTDClient, "attach_customer_tracking_header")
        patch_command_args_and_params(mocker, "not-implemented-command", {})
        with pytest.raises(SystemExit):
            main()

    def test_main_dispatches_new_commands_with_args(self, blox_client, requests_mock, mocker, mock_results):
        """Test main() routes a new_commands_with_args command through trim_args/remove_nulls_from_dictionary."""
        ip_address = "0.0.0.1"
        address_response = util_load_json("enrichment_ip_address_response.json")
        threat_response = util_load_json("enrichment_ip_threat_response.json")
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats?ip={ip_address}&rlimit=1", json=threat_response, status_code=200)
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/ipam/address?_filter=address=='{ip_address}'&_limit=1",
            json=address_response,
            status_code=200,
        )

        # Leading/trailing whitespace and a null value confirm main() actually runs trim_args and
        # remove_nulls_from_dictionary on the args before dispatching, rather than passing them through as-is.
        mocker.patch.object(demisto, "args", return_value={"ip": f"  {ip_address}  ", "unused": None})
        mocker.patch.object(demisto, "command", return_value="ip")
        mocker.patch.object(demisto, "params", return_value={"credentials": {"password": ""}})

        main()

        mock_results.assert_called_once()

    def test_main_reports_401_as_authentication_error(self, mocker):
        """A DemistoException whose response carries a 401 status is surfaced as a generic authentication error."""
        mocker.patch.object(BloxOneTDClient, "attach_customer_tracking_header")
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="ip")
        mocker.patch.object(demisto, "params", return_value={"credentials": {"password": ""}})
        mocker.patch(
            "InfobloxBloxOneThreatDefense.ip_command",
            side_effect=DemistoException("unauthorized", res=mocker.Mock(status_code=401)),
        )
        mock_return_error = mocker.patch("InfobloxBloxOneThreatDefense.return_error")

        main()

        mock_return_error.assert_called_once()
        assert mock_return_error.call_args.args[0] == "authentication error"


class TestBloxOneTDClient:
    def test_http_request_success(self, blox_client, requests_mock):
        """Test successful HTTP request with JSON response."""
        # Mock response
        mock_response = {"status": "success", "data": [1, 2, 3]}
        requests_mock.get(f"{BASE_URL}/test/endpoint", json=mock_response, status_code=200)

        # Call the method
        response = blox_client.http_request("GET", "/test/endpoint", params={"key": "value"})

        # Assertions
        assert response == mock_response
        assert requests_mock.last_request.method == "GET"
        assert requests_mock.last_request.path == "/test/endpoint"
        assert requests_mock.last_request.qs == {"key": ["value"]}

    def test_http_request_invalid_json(self, blox_client, requests_mock):
        """Test handling of non-JSON response."""
        # Mock non-JSON response
        requests_mock.get(f"{BASE_URL}/test/endpoint", text="Not a JSON response", status_code=200)

        # Call the method and expect an exception
        with pytest.raises(DemistoException) as excinfo:
            blox_client.http_request("GET", "/test/endpoint")

        # Assert the error message is as expected
        assert "Failed to parse json object from response" in str(excinfo.value)

    @pytest.mark.parametrize(
        "status_code, expected_error_msg",
        [
            (400, "Invalid argument value while trying to get information from Infoblox Cloud"),
            (401, "Invalid Service API Key configured"),
            (404, "No record found for given argument(s): Not Found"),
            (403, "Test connectivity failed. Please provide valid input parameters"),
            (521, "Test connectivity failed. Please provide valid input parameters"),
        ],
    )
    def test_http_request_error_status_codes(self, blox_client, requests_mock, status_code, expected_error_msg):
        """Test error handling for different HTTP status codes."""
        # Mock error response
        error_response = {"detail": "Detailed error message"}
        requests_mock.get(f"{BASE_URL}/test/endpoint", json=error_response, status_code=status_code)

        # Call the method and expect an exception
        with pytest.raises(DemistoException) as excinfo:
            blox_client.http_request("GET", "/test/endpoint")

        # Assert the error message contains the expected text
        assert expected_error_msg in str(excinfo.value)
        assert str(status_code) in str(excinfo.value)

    def test_http_request_no_content_response(self, blox_client, requests_mock):
        """Test that a 204 No Content response returns None without attempting to parse a body."""
        requests_mock.get(f"{BASE_URL}/test/endpoint", status_code=204)

        response = blox_client.http_request("GET", "/test/endpoint")

        assert response is None

    def test_http_request_fallback_error_handler_for_unmapped_status_code(self, blox_client, mocker):
        """Test the client_error_handler fallback for a status code with no dedicated branch.

        BaseClient's own ok_codes check intercepts every status code outside {200-299, 400, 401,
        403, 404, 521} before this method's own status handling would run, so in a real HTTP
        response this fallback line is unreachable. Stubbing _http_request to return a raw
        response object bypasses that gate to directly cover the defensive fallback itself.
        """
        fake_response = mocker.Mock(status_code=418)
        fake_response.json.return_value = {"error": "teapot"}
        mocker.patch.object(blox_client, "_http_request", return_value=fake_response)

        with pytest.raises(DemistoException, match=r"Error in API call \[418\]"):
            blox_client.http_request("GET", "/test/endpoint")

    def test_http_request_with_json_data(self, blox_client, requests_mock):
        """Test HTTP request with JSON data in the body."""
        # Mock response
        test_data = {"key": "value", "nested": {"a": 1}}
        requests_mock.post(f"{BASE_URL}/test/endpoint", json={"status": "success"}, status_code=200)

        # Call the method
        response = blox_client.http_request("POST", "/test/endpoint", json_data=test_data)

        # Assertions
        assert response == {"status": "success"}
        assert requests_mock.last_request.method == "POST"
        assert requests_mock.last_request.json() == test_data

    def test_http_request_timeout_and_retry(self, blox_client, requests_mock, mocker):
        """Test timeout and retry behavior."""
        # Mock is_time_sensitive to control retry behavior
        is_time_sensitive_mock = mocker.patch(
            "InfobloxBloxOneThreatDefense.is_time_sensitive",
            side_effect=lambda: False,  # Always return False for this test
        )

        # Mock response
        requests_mock.get(f"{BASE_URL}/test/endpoint", json={"status": "success"})

        # Call the method
        response = blox_client.http_request("GET", "/test/endpoint")

        # Assert the request was made
        assert requests_mock.last_request is not None
        assert response == {"status": "success"}
        is_time_sensitive_mock.assert_called()

    def test_dossier_source_list(self, blox_client, requests_mock):
        requests_mock.get(
            f"{BASE_URL}/tide/api/services/intel/lookup/sources",
            text=load_json_file("bloxone-td-dossier-source-list"),
        )
        assert blox_client.dossier_source_list() == [
            "dns",
            "geo",
            "ptr",
            "whois",
            "ssl_cert",
            "urlhaus",
        ]
        assert "rlabs" not in blox_client.dossier_source_list()

    def test_lookalike_domain_list_with_filter(self, blox_client, requests_mock):
        lookalike_request_mock = requests_mock.get(
            f"{BASE_URL}/api/tdlad/v1/lookalike_domains",
            text=load_json_file("bloxone-td-lookalike-domain-list"),
        )
        blox_client.lookalike_domain_list(user_filter="test-filter")
        assert lookalike_request_mock.request_history[0].qs["_filter"][0] == "test-filter"

    def test_lookalike_domain_list_with_target_domain(self, blox_client, requests_mock):
        lookalike_request_mock = requests_mock.get(
            f"{BASE_URL}/api/tdlad/v1/lookalike_domains",
            text=load_json_file("bloxone-td-lookalike-domain-list"),
        )
        blox_client.lookalike_domain_list(target_domain="target.domain")
        assert lookalike_request_mock.request_history[0].qs["_filter"][0] == 'target_domain=="target.domain"'

    def test_lookalike_domain_list_with_detected_at(self, blox_client, requests_mock):
        lookalike_request_mock = requests_mock.get(
            f"{BASE_URL}/api/tdlad/v1/lookalike_domains",
            text=load_json_file("bloxone-td-lookalike-domain-list"),
        )
        blox_client.lookalike_domain_list(detected_at="2023-02-21T00:00:00Z")
        assert 'detected_at>="2023-02-21T00:00:00Z"'.lower() == lookalike_request_mock.request_history[0].qs["_filter"][0]

    def test_dossier_lookup_get_create(self, blox_client, requests_mock):
        lookup_get_create_request_mock = requests_mock.get(
            f"{BASE_URL}/tide/api/services/intel/lookup/indicator/ip",
            text=load_json_file("bloxone-td-dossier-lookup-get_create-job"),
        )
        job_id = blox_client.dossier_lookup_get_create(indicator_type="ip", value="11.22.33.44")
        assert "11.22.33.44" in lookup_get_create_request_mock.request_history[0].qs["value"]
        assert job_id == "c924d233-ddeb-8877-1234-fedd6a9bb070"

    def test_dossier_lookup_get_is_done_check_when_not_done(self, blox_client, requests_mock):
        requests_mock.get(
            f"{BASE_URL}/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/pending",
            text=json.dumps({"state": "created", "status": "pending"}),
        )
        is_done = blox_client.dossier_lookup_get_is_done("c924d233-ddeb-8877-1234-fedd6a9bb070")
        assert is_done is False

    def test_dossier_lookup_get_is_done_check_when_job_failed(self, blox_client, requests_mock):
        requests_mock.get(
            f"{BASE_URL}/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/pending",
            text=json.dumps({"state": "completed", "status": "error"}),
        )
        with pytest.raises(DemistoException):
            blox_client.dossier_lookup_get_is_done("c924d233-ddeb-8877-1234-fedd6a9bb070")

    def test_dossier_lookup_get_is_done_check_when_done(self, blox_client, requests_mock):
        requests_mock.get(
            f"{BASE_URL}/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/pending",
            text=json.dumps({"state": "completed", "status": "success"}),
        )
        is_done = blox_client.dossier_lookup_get_is_done("c924d233-ddeb-8877-1234-fedd6a9bb070")
        assert is_done is True

    def test_dossier_lookup_get_results(self, blox_client, requests_mock):
        dossier_lookup_get_results_request_mock = requests_mock.get(
            f"{BASE_URL}/tide/api/services/intel/lookup/jobs/c924d233-ddeb-8877-1234-fedd6a9bb070/results",
            text=load_json_file("bloxone-td-dossier-lookup-get_results"),
        )
        blox_client.dossier_lookup_get_results("c924d233-ddeb-8877-1234-fedd6a9bb070")
        assert dossier_lookup_get_results_request_mock.called_once


class TestUnitTests:
    def test_dossier_lookup_task_output(self):
        task_data = json.loads(load_json_file("bloxone-td-dossier-lookup-get_results"))["results"][0]
        expected_outputs = {
            "Source": "urlhaus",
            "Target": "11.22.33.44",
            "Task Id": "d4e24d99-1f98-4a1f-8434-cbf4c284c7d0",
            "Type": "ip",
        }
        assert dossier_lookup_task_output(task_data) == expected_outputs

    data_test_validate_and_format_lookalike_domain_list_args_with_multiple_filters = [
        {},
        {"filter": "filter", "target_domain": "target_domain"},
        {
            "filter": "filter",
            "target_domain": "target_domain",
            "detected_at": "detected_at",
        },
    ]

    @pytest.mark.parametrize(
        "args",
        data_test_validate_and_format_lookalike_domain_list_args_with_multiple_filters,
    )
    def test_validate_and_format_lookalike_domain_list_args_with_multiple_filters(self, args):
        with pytest.raises(DemistoException):
            validate_and_format_lookalike_domain_list_args(args)

    data_test_validate_and_format_lookalike_domain_list_args_with_a_single_filter = [
        {"filter": "filter"},
        {"target_domain": "target_domain"},
    ]

    @pytest.mark.parametrize(
        "args",
        data_test_validate_and_format_lookalike_domain_list_args_with_a_single_filter,
    )
    def test_validate_and_format_lookalike_domain_list_args_with_a_single_filter(self, args):
        assert validate_and_format_lookalike_domain_list_args(args) == args

    data_test_validate_and_format_lookalike_domain_list_args_with_detected_at_filter = [
        ("2023-02-20T00:00:00.000Z", "2023-02-20T00:00:00.000"),
        ("1 day", "2023-02-19T00:00:00.000"),
        ("1y", "2022-02-20T00:00:00.000"),
    ]

    @freeze_time("2023-02-20T00:00:00.000Z")
    @pytest.mark.parametrize(
        "detected_at, expected",
        data_test_validate_and_format_lookalike_domain_list_args_with_detected_at_filter,
    )
    def test_validate_and_format_lookalike_domain_list_args_with_detected_at_filter(self, detected_at, expected):
        out_args = validate_and_format_lookalike_domain_list_args({"detected_at": detected_at})
        assert out_args["detected_at"] == expected

    def test_validate_and_format_lookalike_domain_list_args_with_invalid_detected_at_filter(
        self,
    ):
        with pytest.raises(DemistoException):
            validate_and_format_lookalike_domain_list_args({"detected_at": "test"})

    def test_dossier_lookup_get_command_results(self):
        data = json.loads(load_json_file("bloxone-td-dossier-lookup-get_results"))
        command_results = dossier_lookup_get_command_results(data)
        assert command_results.outputs == data["results"]
        assert command_results.raw_response == data
        assert command_results.readable_output.count("11.22.33.44") == 4
        assert "\n|Task Id|Type|Target|Source|\n" in command_results.readable_output

    def test_dossier_lookup_get_schedule_polling_result_with_first_time_true(self):
        command_results = dossier_lookup_get_schedule_polling_result({"job_id": "1"}, first_time=True)
        assert command_results.readable_output

    def test_dossier_lookup_get_schedule_polling_result_without_first_time(self):
        command_results = dossier_lookup_get_schedule_polling_result({"job_id": "1"})
        assert command_results.readable_output is None

    def test_dossier_lookup_get_schedule_polling_result_polling_args_default(self):
        command_results = dossier_lookup_get_schedule_polling_result({"job_id": "1"})
        assert command_results.scheduled_command._args["timeout"] == 590
        assert command_results.scheduled_command._command == "bloxone-td-dossier-lookup-get"

    def test_dossier_lookup_get_schedule_polling_result_polling_args(self):
        command_results = dossier_lookup_get_schedule_polling_result({"job_id": "1", "interval_in_seconds": 30, "timeout": 300})
        assert command_results.scheduled_command._args["timeout"] == 270
        assert int(command_results.scheduled_command._next_run) == 30
        assert int(command_results.scheduled_command._timeout) == 300
        assert command_results.scheduled_command._command == "bloxone-td-dossier-lookup-get"


class TestUtilityFunctions:
    def test_trim_args_strips_string_values_only(self):
        args = {"name": "  value  ", "count": 5, "flag": True}
        assert trim_args(args) == {"name": "value", "count": 5, "flag": True}

    def test_validate_key_raises_when_key_missing(self):
        with pytest.raises(ValueError, match="Key id not found in response."):
            validate_key({"other": "value"}, "id")

    def test_validate_key_raises_when_response_empty(self):
        with pytest.raises(ValueError, match="Key id not found in response."):
            validate_key({}, "id")

    @pytest.mark.parametrize(
        "threat_level, expected_score",
        [
            (None, Common.DBotScore.NONE),
            (90, Common.DBotScore.BAD),
            (50, Common.DBotScore.SUSPICIOUS),
            (10, Common.DBotScore.GOOD),
        ],
    )
    def test_get_dbot_score_from_threat_level(self, threat_level, expected_score):
        assert get_dbot_score_from_threat_level(threat_level) == expected_score


class TestIpCommand:
    @patch("InfobloxBloxOneThreatDefense.return_warning")
    def test_ip_command_success(self, mock_return_warning, blox_client, requests_mock, capfd):
        success_ip_address = "0.0.0.1"
        not_found_ip_address = "0001:0000:0000:0000:0000:0000:0000:0000"
        invalid_ip_address = "0.0.0.256"
        list_of_ip_addresses = ", ".join([success_ip_address, not_found_ip_address, invalid_ip_address])
        address_response = util_load_json("enrichment_ip_address_response.json")
        threat_response = util_load_json("enrichment_ip_threat_response.json")
        output = util_load_json("ip_command_context.json")
        ip_hr = util_load_text_data("ip_command_success_hr.md")
        ip_indicator = util_load_json("ip_command_indicator.json")

        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats?ip={success_ip_address}&rlimit=1", json=threat_response, status_code=200
        )
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/ipam/address?_filter=address=='{success_ip_address}'&_limit=1",
            json=address_response,
            status_code=200,
        )

        requests_mock.get(f"{BASE_URL}/tide/api/data/threats?ip={not_found_ip_address}&rlimit=1", json={}, status_code=200)
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/ipam/address?_filter=address=='{not_found_ip_address}'&_limit=1", json={}, status_code=200
        )

        capfd.disabled()
        command_output = ip_command(blox_client, args={"ip": list_of_ip_addresses})

        # Ensure return_warning is called with the expected message
        mock_return_warning.assert_has_calls(
            [
                call(f"The following IP Addresses were found invalid: {invalid_ip_address}", exit=False),
                call(MESSAGES["NO_INFO_FOUND"].format("threat and address", "IP", not_found_ip_address)),
            ]
        )

        # Verify command outputs
        assert output == command_output[0].outputs
        assert command_output[0].raw_response == {"threat_data": threat_response, "address_data": address_response}
        assert ip_hr == command_output[0].readable_output
        assert command_output[0].outputs_key_field == "ip"
        assert OUTPUT_PREFIX["IP"] == command_output[0].outputs_prefix
        assert ip_indicator == command_output[0].indicator.to_context()

    @pytest.mark.parametrize("threat_level,expected_reputation", [(100, 3), (80, 3), (30, 2), (10, 1), (0, 0)])
    def test_ip_command_all_threat(self, blox_client, requests_mock, threat_level, expected_reputation):
        success_ip_address = "0.0.0.1"
        address_response = util_load_json("enrichment_ip_address_response.json")
        threat_response = util_load_json("enrichment_ip_threat_response.json")
        ip_indicator = util_load_json("ip_command_indicator.json")
        if threat_level < 80:
            del ip_indicator[list(ip_indicator.keys())[0]]["Malicious"]
        ip_indicator[list(ip_indicator.keys())[1]]["Score"] = expected_reputation

        threat_response["threat"][0]["threat_level"] = threat_level
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats?ip={success_ip_address}&rlimit=1", json=threat_response, status_code=200
        )
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/ipam/address?_filter=address=='{success_ip_address}'&_limit=1",
            json=address_response,
            status_code=200,
        )

        command_output = ip_command(blox_client, args={"ip": success_ip_address})

        # Verify indicator score
        assert ip_indicator == command_output[0].indicator.to_context()

    def test_ip_command_empty_input(self, blox_client):
        """Test command behavior with empty input"""
        with pytest.raises(ValueError, match=MESSAGES["REQUIRED_ARGUMENT"].format("ip")):
            ip_command(blox_client, args={"ip": ",,,"})

    @patch("InfobloxBloxOneThreatDefense.return_warning")
    def test_ip_command_invalid_input(self, mock_return_warning, blox_client):
        """Test command behavior with invalid input"""
        try:
            ip_command(blox_client, args={"ip": ",123,,"})
        except Exception:
            pass
        mock_return_warning.assert_has_calls(
            [
                call(MESSAGES["INVALID_IP_ADDRESS"].format("123"), exit=True),
            ]
        )


class TestUrlCommand:
    @patch("InfobloxBloxOneThreatDefense.return_warning")
    def test_url_command_success(self, mock_return_warning, blox_client, requests_mock, capfd):
        url = "https://test.com"
        not_found_url = "https://notfound.com"
        list_of_urls = ", ".join([url, not_found_url])
        threat_response = util_load_json("enrichment_url_threat_response.json")
        output = util_load_json("url_command_context.json")
        url_hr = util_load_text_data("url_command_success_hr.md")
        url_indicator = util_load_json("url_command_indicator.json")

        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats?text_search={url}&type=url&rlimit=1", json=threat_response, status_code=200
        )

        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats?text_search={not_found_url}&type=url&rlimit=1", json={}, status_code=200
        )

        capfd.disabled()
        command_output = url_command(blox_client, args={"url": list_of_urls})

        # Ensure return_warning is called with the expected message
        mock_return_warning.assert_has_calls(
            [
                call(MESSAGES["NO_INFO_FOUND"].format("threat", "URL", not_found_url)),
            ]
        )

        # Verify command outputs
        assert output == command_output[0].outputs
        assert command_output[0].raw_response == {"threat_data": threat_response}
        assert url_hr == command_output[0].readable_output
        assert command_output[0].outputs_key_field == "url"
        assert OUTPUT_PREFIX["URL"] == command_output[0].outputs_prefix
        assert url_indicator == command_output[0].indicator.to_context()

    @pytest.mark.parametrize("threat_level,expected_reputation", [(100, 3), (80, 3), (30, 2), (10, 1), (0, 0)])
    def test_url_command_all_threat(self, blox_client, requests_mock, threat_level, expected_reputation):
        success_url_address = "https://test.com"
        threat_response = util_load_json("enrichment_url_threat_response.json")
        url_indicator = util_load_json("url_command_indicator.json")
        if threat_level < 80:
            del url_indicator[list(url_indicator.keys())[0]]["Malicious"]
        url_indicator[list(url_indicator.keys())[1]]["Score"] = expected_reputation

        threat_response["threat"][0]["threat_level"] = threat_level
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats?text_search={success_url_address}&rlimit=1", json=threat_response, status_code=200
        )

        command_output = url_command(blox_client, args={"url": success_url_address})

        # Verify indicator score
        assert url_indicator == command_output[0].indicator.to_context()

    def test_url_command_invalid_args(self, blox_client, capfd):
        capfd.disabled()
        with pytest.raises(ValueError) as error_msg:
            url_command(blox_client, args={"url": ",,,"})

        assert str(error_msg.value) == MESSAGES["REQUIRED_ARGUMENT"].format("url")


class TestFetchIncidents:
    """Test cases for the fetch_incidents function"""

    @pytest.fixture
    def mock_demisto_methods(self, mocker):
        """Mock demisto methods used by fetch_incidents"""
        mock_get_last_run = mocker.patch.object(demisto, "getLastRun")
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mock_incidents = mocker.patch.object(demisto, "incidents")
        return {"getLastRun": mock_get_last_run, "setLastRun": mock_set_last_run, "incidents": mock_incidents}

    def test_fetch_incidents_first_run_no_last_run(self, blox_client, requests_mock, mock_demisto_methods):
        """Test fetch_incidents when no previous last_run exists (first run)"""
        # Mock API response
        requests_mock.get(f"{BASE_URL}/api/v1/insights", text=load_json_file("soc-insights-list"))

        # Mock no previous last run
        mock_demisto_methods["getLastRun"].return_value = None

        params = {
            "ingestion_type": "SOC Insight",
            "max_fetch": "10",
            "soc_insight_status": "Active",
            "soc_insight_priority_level": "HIGH",
            "soc_insight_threat_type": "Malware",
        }

        fetch_incidents(blox_client, params)

        # Verify API was called with correct parameters
        assert requests_mock.call_count == 1
        request = requests_mock.request_history[0]
        assert request.qs["status"] == ["active"]
        assert request.qs["priority"] == ["high"]
        assert request.qs["threat_type"] == ["malware"]

        # Verify incidents were created
        mock_demisto_methods["incidents"].assert_called_once()
        incidents = mock_demisto_methods["incidents"].call_args[0][0]
        assert len(incidents) == 3

        # Verify incident structure
        incident = incidents[0]
        assert "insightId" in incident["rawJSON"]
        assert incident["severity"] == 3  # HIGH priority maps to severity 3

        # Verify last run was set
        mock_demisto_methods["setLastRun"].assert_called_once()
        last_run_call = mock_demisto_methods["setLastRun"].call_args[0][0]
        assert "soc_insight_ids" in last_run_call
        assert "insight-001" in last_run_call["soc_insight_ids"]
        assert "insight-002" in last_run_call["soc_insight_ids"]
        assert "insight-003" in last_run_call["soc_insight_ids"]

    def test_fetch_incidents_with_existing_last_run(self, blox_client, requests_mock, mock_demisto_methods):
        """Test fetch_incidents with existing last_run data"""
        # Mock API response
        requests_mock.get(f"{BASE_URL}/api/v1/insights", text=load_json_file("soc-insights-list"))

        # Mock existing last run with one insight already processed
        existing_last_run = {"soc_insight_ids": ["insight-001"]}
        mock_demisto_methods["getLastRun"].return_value = existing_last_run

        params = {"ingestion_type": "SOC Insight", "max_fetch": "10"}

        fetch_incidents(blox_client, params)

        # Verify only new incidents were created (insight-002 and insight-003)
        mock_demisto_methods["incidents"].assert_called_once()
        incidents = mock_demisto_methods["incidents"].call_args[0][0]
        assert len(incidents) == 2

        # Verify the skipped insight is not in the incidents
        incident_data = [json.loads(inc["rawJSON"]) for inc in incidents]
        soc_insight_ids = [data["insightId"] for data in incident_data]
        assert "insight-001" not in soc_insight_ids
        assert "insight-002" in soc_insight_ids
        assert "insight-003" in soc_insight_ids

    def test_fetch_incidents_max_fetch_limit(self, blox_client, requests_mock, mock_demisto_methods):
        """Test fetch_incidents respects max_fetch limit"""
        # Mock API response
        requests_mock.get(f"{BASE_URL}/api/v1/insights", text=load_json_file("soc-insights-list"))

        mock_demisto_methods["getLastRun"].return_value = None

        params = {"ingestion_type": "SOC Insight", "max_fetch": "2"}  # Limit to 2 incidents

        fetch_incidents(blox_client, params)

        # Verify only 2 incidents were created despite 3 available
        mock_demisto_methods["incidents"].assert_called_once()
        incidents = mock_demisto_methods["incidents"].call_args[0][0]
        assert len(incidents) == 2

        # Verify last_run only contains the processed insights
        last_run_call = mock_demisto_methods["setLastRun"].call_args[0][0]
        assert len(last_run_call["soc_insight_ids"]) == 2

    def test_fetch_incidents_with_max_fetch_less_than_1(self, blox_client, requests_mock):
        requests_mock.get(f"{BASE_URL}/api/v1/insights", json={"insightList": []})

        with pytest.raises(ValueError, match="Invalid Max Fetch: -1"):
            fetch_incidents(blox_client, {"max_fetch": -1})

    def test_fetch_incidents_empty_response(self, blox_client, requests_mock, mock_demisto_methods):
        """Test fetch_incidents when API returns empty insight list"""
        # Mock empty API response
        requests_mock.get(f"{BASE_URL}/api/v1/insights", json={"insightList": []})

        mock_demisto_methods["getLastRun"].return_value = None

        params = {"ingestion_type": "SOC Insight", "max_fetch": "10"}

        fetch_incidents(blox_client, params)

        # Verify no incidents were created
        mock_demisto_methods["incidents"].assert_called_once()
        incidents = mock_demisto_methods["incidents"].call_args[0][0]
        assert len(incidents) == 0

        # Verify empty last_run was set
        last_run_call = mock_demisto_methods["setLastRun"].call_args[0][0]
        assert "soc_insight_ids" not in last_run_call

    def test_fetch_incidents_empty_response_with_last_run(self, blox_client, requests_mock, mock_demisto_methods):
        """Test fetch_incidents when API returns empty insight list"""
        # Mock empty API response
        requests_mock.get(f"{BASE_URL}/api/v1/insights", json={"insightList": []})

        mock_demisto_methods["getLastRun"].return_value = {"soc_insight_ids": ["insight-001"]}

        params = {"ingestion_type": "SOC Insight", "max_fetch": "10"}

        fetch_incidents(blox_client, params)

        # Verify no incidents were created
        mock_demisto_methods["incidents"].assert_called_once()
        incidents = mock_demisto_methods["incidents"].call_args[0][0]
        assert len(incidents) == 0

        # Verify empty last_run was set
        last_run_call = mock_demisto_methods["setLastRun"].call_args[0][0]
        assert last_run_call["soc_insight_ids"] == ["insight-001"]

    def test_fetch_incidents_invalid_insights_skipped(self, blox_client, requests_mock, mock_demisto_methods):
        """Test fetch_incidents skips insights with missing required fields"""
        # Mock API response with invalid insights
        requests_mock.get(f"{BASE_URL}/api/v1/insights", text=load_json_file("soc-insights-list-invalid"))

        mock_demisto_methods["getLastRun"].return_value = None

        params = {"ingestion_type": "SOC Insight", "max_fetch": "10"}

        fetch_incidents(blox_client, params)

        # Verify only 1 incident was created (1 insight are invalid)
        mock_demisto_methods["incidents"].assert_called_once()
        incidents = mock_demisto_methods["incidents"].call_args[0][0]
        assert len(incidents) == 1

        # Verify empty last_run was set
        last_run_call = mock_demisto_methods["setLastRun"].call_args[0][0]
        assert last_run_call["soc_insight_ids"] == ["insight-004"]

    @pytest.mark.parametrize(
        "priority_text,expected_severity",
        [
            ("INFO", 1),
            ("MEDIUM", 2),
            ("HIGH", 3),
            ("CRITICAL", 4),
            ("UNKNOWN", 1),  # Default severity for unmapped priority
            (None, 1),  # Default severity for missing priority
        ],
    )
    def test_fetch_incidents_severity_mapping(
        self, blox_client, requests_mock, mock_demisto_methods, priority_text, expected_severity
    ):
        """Test fetch_incidents correctly maps priority to severity"""
        # Create custom response with specific priority
        insight_data = {
            "insightList": [
                {
                    "insightId": "test-insight",
                    "dateChanged": "2023-12-01T10:00:00Z",
                    "priorityText": priority_text,
                    "title": "Test Insight",
                    "description": "Test description",
                }
            ]
        }

        requests_mock.get(f"{BASE_URL}/api/v1/insights", json=insight_data)

        mock_demisto_methods["getLastRun"].return_value = None

        params = {"ingestion_type": "SOC Insight", "max_fetch": "10"}

        fetch_incidents(blox_client, params)

        # Verify correct severity mapping
        mock_demisto_methods["incidents"].assert_called_once()
        incidents = mock_demisto_methods["incidents"].call_args[0][0]
        assert len(incidents) == 1
        assert incidents[0]["severity"] == expected_severity

    def test_fetch_incidents_default_max_fetch(self, blox_client, requests_mock, mock_demisto_methods):
        """Test fetch_incidents uses default max_fetch of 50 when not specified"""
        requests_mock.get(f"{BASE_URL}/api/v1/insights", text=load_json_file("soc-insights-list"))

        mock_demisto_methods["getLastRun"].return_value = None

        # Don't specify max_fetch parameter
        params = {"ingestion_type": "SOC Insight"}

        fetch_incidents(blox_client, params)

        # Verify function completes successfully (default max_fetch is used internally)
        mock_demisto_methods["incidents"].assert_called_once()
        incidents = mock_demisto_methods["incidents"].call_args[0][0]
        assert len(incidents) == 3  # All 3 test insights should be processed

    def test_fetch_incidents_empty_string_ingestion_type_uses_default(self, blox_client, requests_mock, mock_demisto_methods):
        """Test fetch_incidents falls back to the default ingestion type when ingestion_type is an empty string"""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", text=load_json_file("iq-for-td-insight-list"))
        mock_demisto_methods["getLastRun"].return_value = None

        # An empty string is what the UI sends for an unset select field; it must not be
        # treated as an explicit selection and must fall back to "IQ for TD Insight".
        params = {"ingestion_type": "", "max_fetch": "10"}

        fetch_incidents(blox_client, params)

        mock_demisto_methods["incidents"].assert_called_once()
        incidents = mock_demisto_methods["incidents"].call_args[0][0]
        assert len(incidents) == 3
        incident_data = json.loads(incidents[0]["rawJSON"])
        assert "insight_id" in incident_data

    def test_fetch_incidents_through_main_function(self, requests_mock, mocker):
        """Test of fetch_incidents through main() function"""
        # Mock demisto methods
        mock_incidents = mocker.patch.object(demisto, "incidents")

        # Mock API response
        requests_mock.get(f"{BASE_URL}/api/v1/insights", text=load_json_file("soc-insights-list"))

        # Mock demisto command and params
        patch_command_args_and_params(mocker, "fetch-incidents", {})
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "credentials": {"password": "test-api-key"},
                "ingestion_type": "SOC Insight",
                "max_fetch": "201",
                "soc_insight_status": "open",
            },
        )

        # Run main function
        main()

        # Verify fetch_incidents was executed successfully
        mock_incidents.assert_called_once()
        incidents = mock_incidents.call_args[0][0]
        assert len(incidents) == 3

    @patch("InfobloxBloxOneThreatDefense.return_results")
    def test_test_module_through_main_function_for_insight_fetch(self, mock_return, requests_mock, mocker):
        """Test of test_module through main() function for insight fetch"""

        # Mock API response
        requests_mock.get(f"{BASE_URL}/api/v1/insights", text=load_json_file("soc-insights-list"))

        # Mock demisto command and params
        patch_command_args_and_params(mocker, "test-module", {})
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "credentials": {"password": "test-api-key"},
                "isFetch": True,
                "ingestion_type": "SOC Insight",
                "max_fetch": "10",
                "soc_insight_status": "open",
            },
        )

        # Run main function
        main()

        # Verify fetch_incidents was executed successfully
        assert mock_return.call_args.args[0] == "ok"

    @pytest.mark.parametrize(
        "max_fetch,expected_error",
        [
            ("0", ERRORS["INVALID_MAX_FETCH"].format("0")),
            ("201", ERRORS["INVALID_MAX_FETCH"].format("201")),
        ],
    )
    def test_fetch_invalid_max_fetch(self, blox_client, max_fetch, expected_error):
        """Test command behavior with error input"""
        with pytest.raises(ValueError, match=expected_error):
            fetch_incidents(blox_client, params={"max_fetch": max_fetch}, is_test=True)


class TestFetchDnsSecurityEvents:
    """Test cases for the fetch_dns_security_events function"""

    @pytest.fixture
    def dns_events_response(self):
        """Load DNS security events test data"""
        return util_load_json("dns-security-event-response-success.json")

    def test_fetch_dns_security_events_first_run_no_last_run(self, blox_client, requests_mock, dns_events_response):
        """Test fetch_dns_security_events when no previous last_run exists (first run)"""
        # Mock API response
        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json={"result": dns_events_response})

        params = {"first_fetch": "24 hours", "dns_events_queried_name": "example.com", "dns_events_threat_level": "HIGH,MEDIUM"}
        last_run = {}
        max_fetch = 50

        incidents, updated_last_run = fetch_dns_security_events(blox_client, params, last_run, max_fetch)

        # Verify API was called with correct parameters
        assert requests_mock.call_count == 1
        request = requests_mock.request_history[0]
        assert "_limit" in request.qs
        assert request.qs["_limit"] == ["50"]
        assert "t0" in request.qs  # Should have start time
        assert "t1" in request.qs  # Should have end time
        assert request.qs["qname"] == ["example.com"]
        assert request.qs["threat_level"] == ["high,medium"]

        # Verify incident was created
        assert len(incidents) == 1
        incident = incidents[0]
        assert "Infoblox DNS Security Event - Data Exfiltration" in incident["name"]
        assert incident["severity"] == 3  # HIGH severity maps to 3
        assert "occurred" in incident
        assert "rawJSON" in incident

        # Verify last run was updated
        assert "dns_events_last_fetch" in updated_last_run
        assert "dns_events_ids" in updated_last_run
        assert len(updated_last_run["dns_events_ids"]) == 1

    def test_fetch_dns_security_events_with_existing_last_run(self, blox_client, requests_mock, dns_events_response):
        """Test fetch_dns_security_events with existing last_run data"""
        # Mock API response with same event
        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json={"result": dns_events_response})

        # Create composite key from the test data event
        event = dns_events_response[0]
        event_time = event.get("event_time")
        qname_truncated = event.get("qname", "")[:20]
        composite_key = "|".join([event_time, qname_truncated, event.get("device", ""), event.get("feed_name", "")])

        # Mock existing last run with the event already processed
        existing_last_run = {"dns_events_last_fetch": "2025-09-17T07:45:30.000Z", "dns_events_ids": [composite_key]}

        params = {"first_fetch": "24 hours"}
        max_fetch = 50

        incidents, updated_last_run = fetch_dns_security_events(blox_client, params, existing_last_run, max_fetch)

        # Verify no incidents were created (event was already processed)
        assert len(incidents) == 0

        # Verify last run was updated
        assert updated_last_run["dns_events_last_fetch"] == event_time
        assert composite_key in updated_last_run["dns_events_ids"]

    def test_fetch_dns_security_events_max_fetch_limit(self, blox_client, requests_mock):
        """Test fetch_dns_security_events respects max_fetch limit"""
        # Create multiple events
        multiple_events = []
        base_event = util_load_json("dns-security-event-response-success.json")[0]
        for i in range(5):
            event = base_event.copy()
            event["event_time"] = f"2025-09-18T07:45:3{i}.000Z"
            event["qname"] = f"test{i}.example.com"
            multiple_events.append(event)

        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json={"result": multiple_events})

        params = {"first_fetch": "24 hours"}
        last_run = {}
        max_fetch = 5  # Limit to 5 events

        incidents, _ = fetch_dns_security_events(blox_client, params, last_run, max_fetch)

        # Verify API was called with correct limit
        request = requests_mock.request_history[0]
        assert request.qs["_limit"] == ["5"]

        # Note: The function doesn't actually limit incidents in processing,
        # it relies on API _limit parameter
        assert len(incidents) == 5

    def test_fetch_dns_security_events_with_filters(self, blox_client, requests_mock, dns_events_response):
        """Test fetch_dns_security_events with various filter parameters"""
        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json={"result": dns_events_response})

        params = {
            "first_fetch": "24 hours",
            "dns_events_queried_name": "example.com,test.com",
            "dns_events_policy_name": "Policy1,Policy2",
            "dns_events_threat_level": "HIGH,MEDIUM",
            "dns_events_threat_class": "Malware,Phishing",
            "dns_events_threat_family": "Family1,Family2",
            "dns_events_threat_indicator": "indicator1,indicator2",
            "dns_events_policy_action": "Block,Log",
            "dns_events_feed_name": "Feed1,Feed2",
            "dns_events_network": "Network1,Network2",
        }
        last_run = {}
        max_fetch = 50

        fetch_dns_security_events(blox_client, params, last_run, max_fetch)

        # Verify API was called with all filter parameters
        request = requests_mock.request_history[0]
        assert request.qs["qname"] == ["example.com,test.com"]
        assert request.qs["policy_name"] == ["policy1,policy2"]
        assert request.qs["threat_level"] == ["high,medium"]
        assert request.qs["threat_class"] == ["malware,phishing"]
        assert request.qs["threat_family"] == ["family1,family2"]
        assert request.qs["threat_indicator"] == ["indicator1,indicator2"]
        assert request.qs["policy_action"] == ["block,log"]
        assert request.qs["feed_name"] == ["feed1,feed2"]
        assert request.qs["network"] == ["network1,network2"]

    def test_fetch_dns_security_events_empty_response(self, blox_client, requests_mock):
        """Test fetch_dns_security_events when API returns empty result"""
        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json={"result": []})

        params = {"first_fetch": "24 hours"}
        last_run = {}
        max_fetch = 50

        incidents, updated_last_run = fetch_dns_security_events(blox_client, params, last_run, max_fetch)

        # Verify no incidents were created
        assert len(incidents) == 0

        # Verify last_run is returned unchanged since no events
        assert updated_last_run == last_run

    def test_fetch_dns_security_events_test_mode(self, blox_client, requests_mock, dns_events_response):
        """Test fetch_dns_security_events in test mode"""
        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json={"result": dns_events_response})

        params = {"first_fetch": "24 hours"}
        last_run = {}
        max_fetch = 50
        is_test = True

        incidents, updated_last_run = fetch_dns_security_events(blox_client, params, last_run, max_fetch, is_test)

        # In test mode, should return empty incidents and last_run
        assert incidents == []
        assert updated_last_run == {}

    @pytest.mark.parametrize(
        "severity, expected_severity_level",
        [
            ("HIGH", 3),
            ("MEDIUM", 2),
            ("INFO", 1),
            ("CRITICAL", 4),
            ("UNKNOWN", 1),  # Default for unmapped severity
            (None, 1),  # Default for missing severity
        ],
    )
    def test_fetch_dns_security_events_severity_mapping(self, blox_client, requests_mock, severity, expected_severity_level):
        """Test fetch_dns_security_events correctly maps severity to incident severity"""
        base_event = util_load_json("dns-security-event-response-success.json")[0]
        if severity is not None:
            base_event["severity"] = severity
        else:
            base_event.pop("severity", None)

        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json={"result": [base_event]})

        params = {"first_fetch": "24 hours"}
        last_run = {}
        max_fetch = 50

        incidents, _ = fetch_dns_security_events(blox_client, params, last_run, max_fetch)

        assert len(incidents) == 1
        assert incidents[0]["severity"] == expected_severity_level

    def test_fetch_dns_security_events_response_format_variations(self, blox_client, requests_mock, dns_events_response):
        """Test fetch_dns_security_events handles different response formats"""
        # Test when response is directly a list (not wrapped in result key)
        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json=dns_events_response)

        params = {"first_fetch": "24 hours"}
        last_run = {}
        max_fetch = 50

        incidents, _ = fetch_dns_security_events(blox_client, params, last_run, max_fetch)

        # Should handle both response formats
        assert len(incidents) == 1

    def test_fetch_dns_security_events_time_handling(self, blox_client, requests_mock, dns_events_response, mocker):
        """Test fetch_dns_security_events properly handles time parameters"""
        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json={"result": dns_events_response})

        # Mock datetime to control timestamp calculation
        mock_now = mocker.patch("InfobloxBloxOneThreatDefense.arg_to_datetime")
        mock_now.side_effect = lambda x: arg_to_datetime("2025-09-18T08:00:00.000Z") if x == "now" else arg_to_datetime(x)

        params = {"first_fetch": "1 day"}
        last_run = {"dns_events_last_fetch": "2025-09-17T08:00:00.000Z"}
        max_fetch = 50

        fetch_dns_security_events(blox_client, params, last_run, max_fetch)

        # Verify time parameters were set correctly in API call
        request = requests_mock.request_history[0]
        assert "t0" in request.qs  # Start time from last fetch
        assert "t1" in request.qs  # End time (now)

    def test_fetch_dns_security_events_composite_key_generation(self, blox_client, requests_mock):
        """Test fetch_dns_security_events generates correct composite keys for deduplication"""
        # Create event with specific fields for key generation
        test_event = {
            "event_time": "2025-09-18T07:45:30.000Z",
            "qname": "test.example.com.with.very.long.domain.name.that.exceeds.twenty.characters",
            "device": "10.0.0.1",
            "feed_name": "Test Feed",
            "severity": "HIGH",
            "tclass": "Malware",
        }

        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json={"result": [test_event]})

        params = {"first_fetch": "24 hours"}
        last_run = {}
        max_fetch = 50

        _, updated_last_run = fetch_dns_security_events(blox_client, params, last_run, max_fetch)

        # Verify composite key format: event_time|qname_truncated|device|feed_name
        expected_composite_key = "2025-09-18T07:45:30.000Z|test.example.com.wit|10.0.0.1|Test Feed"
        assert expected_composite_key in updated_last_run["dns_events_ids"]

    def test_fetch_dns_security_events_integration_with_fetch_incidents(
        self, blox_client, requests_mock, dns_events_response, mocker
    ):
        """Test fetch_dns_security_events integration with main fetch_incidents function"""
        # Mock demisto methods
        mock_get_last_run = mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mock_incidents = mocker.patch.object(demisto, "incidents")

        # Mock API response
        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json={"result": dns_events_response})

        params = {"max_fetch": "50", "ingestion_type": "DNS Security Event", "first_fetch": "24 hours"}

        fetch_incidents(blox_client, params)

        # Verify demisto methods were called correctly
        mock_get_last_run.assert_called_once()
        mock_set_last_run.assert_called_once()
        mock_incidents.assert_called_once()

        # Verify incident was created
        incidents_call = mock_incidents.call_args[0][0]
        assert len(incidents_call) == 1
        assert incidents_call[0]["name"].startswith("Infoblox DNS Security Event")

    @patch("InfobloxBloxOneThreatDefense.return_results")
    def test_test_module_through_main_function_for_event_fetch(self, mock_return, requests_mock, mocker):
        """Test of test_module through main() function for DNS Security Events fetch"""

        # Mock API response
        requests_mock.get(f"{BASE_URL}/api/dnsdata/v2/dns_event", json=util_load_json("dns-security-event-response-success.json"))

        # Mock demisto command and params
        patch_command_args_and_params(mocker, "test-module", {})
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "credentials": {"password": "test-api-key"},
                "isFetch": True,
                "max_fetch": "10",
                "soc_insight_status": "open",
                "ingestion_type": "DNS Security Event",
            },
        )

        # Run main function
        main()

        # Verify fetch_incidents was executed successfully
        assert mock_return.call_args.args[0] == "ok"

    @pytest.mark.parametrize(
        "dns_events_threat_level,expected_error",
        [
            ("abc", MESSAGES["INVALID_DNS_EVENT_THREAT_LEVEL"].format("abc")),
            ("lower,high", MESSAGES["INVALID_DNS_EVENT_THREAT_LEVEL"].format("lower")),
        ],
    )
    def test_fetch_dns_security_events_error_input(self, blox_client, dns_events_threat_level, expected_error):
        """Test command behavior with error input"""
        with pytest.raises(ValueError, match=expected_error):
            fetch_dns_security_events(
                blox_client, params={"dns_events_threat_level": dns_events_threat_level}, last_run={}, max_fetch=50
            )


class TestFetchIQForTDInsights:
    """Test cases for the fetch_iq_for_td_insights function"""

    @freeze_time("2026-12-02T00:00:00Z")
    def test_fetch_iq_for_td_insights_first_run_no_last_run(self, blox_client, requests_mock):
        """Test fetch_iq_for_td_insights when no previous last_run exists (first run)"""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", text=load_json_file("iq-for-td-insight-list"))

        params = {
            "first_fetch": "24 hours",
            "iq_for_td_insight_status": "In Progress",
            "iq_for_td_insight_severity": "High",
            "iq_for_td_insight_threat_properties": "malware,phishing",
        }
        last_run = {}
        max_fetch = 50

        incidents, updated_last_run = fetch_iq_for_td_insights(blox_client, params, last_run, max_fetch)

        # Verify API was called with correct parameters. date_created is deliberately not sent to the
        # API since it matches exactly rather than "on or after"; filtering is done client-side instead.
        assert requests_mock.call_count == 1
        request = requests_mock.request_history[0]
        assert "date_created" not in request.qs
        assert request.qs["status"] == ["in progress"]
        assert request.qs["severity"] == ["high"]
        assert request.qs["threat_properties"] == ["malware,phishing"]

        # Verify incidents were created
        assert len(incidents) == 3
        incident = incidents[0]
        assert "insight_id" in incident["rawJSON"]
        assert incident["name"].startswith("Infoblox IQ for TD Insight - ")

        # Verify incident_link uses V2 URL format
        incident_data = json.loads(incident["rawJSON"])
        assert incident_data["incident_link"] == "https://csp.infoblox.com/#/ai/threat-defense/insight-v2-001"

        # Verify last run was seeded once from first_fetch, converted to an absolute timestamp
        assert updated_last_run["iq_for_td_insight_last_fetch"] == "2026-12-01T00:00:00Z"
        assert "insight-v2-001" in updated_last_run["iq_for_td_insight_ids"]
        assert "insight-v2-002" in updated_last_run["iq_for_td_insight_ids"]
        assert "insight-v2-003" in updated_last_run["iq_for_td_insight_ids"]

    @freeze_time("2026-12-02T00:00:00Z")
    def test_fetch_iq_for_td_insights_with_naive_date_created_treated_as_utc(self, blox_client, requests_mock):
        """Naive (no timezone) date_created values must be treated as UTC when compared to the floor timestamp."""
        requests_mock.get(
            f"{BASE_URL}/api/v2/insights",
            json={"insight_list": [{"insight_id": "insight-naive-001", "date_created": "2026-12-01T12:00:00", "name": "n"}]},
        )
        params = {"first_fetch": "24 hours"}
        last_run = {}
        max_fetch = 50

        incidents, updated_last_run = fetch_iq_for_td_insights(blox_client, params, last_run, max_fetch)

        assert len(incidents) == 1
        assert "insight-naive-001" in updated_last_run["iq_for_td_insight_ids"]

    @freeze_time("2026-12-02T00:00:00Z")
    def test_fetch_iq_for_td_insights_empty_string_first_fetch_uses_default(self, blox_client, requests_mock):
        """Test fetch_iq_for_td_insights falls back to DEFAULT_FIRST_FETCH when first_fetch is an empty string"""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", text=load_json_file("iq-for-td-insight-list"))

        params = {"first_fetch": ""}
        last_run = {}
        max_fetch = 50

        incidents, updated_last_run = fetch_iq_for_td_insights(blox_client, params, last_run, max_fetch)

        # An empty string is what the UI sends for an unset field; it must not be passed to
        # arg_to_datetime as-is and must fall back to DEFAULT_FIRST_FETCH instead.
        assert len(incidents) == 3
        assert updated_last_run["iq_for_td_insight_last_fetch"] == "2026-12-01T00:00:00Z"

    def test_fetch_iq_for_td_insights_with_existing_last_run(self, blox_client, requests_mock):
        """Test fetch_iq_for_td_insights with existing last_run data skips already-seen insights"""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", text=load_json_file("iq-for-td-insight-list"))

        existing_last_run = {
            "iq_for_td_insight_last_fetch": "2026-12-01T09:00:00Z",
            "iq_for_td_insight_ids": ["insight-v2-001"],
        }
        params = {}
        max_fetch = 50

        incidents, updated_last_run = fetch_iq_for_td_insights(blox_client, params, existing_last_run, max_fetch)

        assert len(incidents) == 2
        incident_data = [json.loads(inc["rawJSON"]) for inc in incidents]
        insight_ids = [data["insight_id"] for data in incident_data]
        assert "insight-v2-001" not in insight_ids
        assert "insight-v2-002" in insight_ids
        assert "insight-v2-003" in insight_ids
        assert "insight-v2-001" in updated_last_run["iq_for_td_insight_ids"]

        # The floor timestamp must stay intact across cycles, never advanced to the latest insight
        assert updated_last_run["iq_for_td_insight_last_fetch"] == "2026-12-01T09:00:00Z"

    def test_fetch_iq_for_td_insights_client_side_floor_filtering(self, blox_client, requests_mock):
        """Test fetch_iq_for_td_insights drops insights older than the floor even if the API returns them"""
        insight_data = {
            "insight_list": [
                {
                    "insight_id": "insight-v2-before-floor",
                    "name": "Insight before the floor",
                    "severity": "High",
                    "date_created": "2026-12-01T08:00:00Z",
                },
                {
                    "insight_id": "insight-v2-after-floor",
                    "name": "Insight after the floor",
                    "severity": "High",
                    "date_created": "2026-12-01T10:00:00Z",
                },
            ]
        }
        requests_mock.get(f"{BASE_URL}/api/v2/insights", json=insight_data)

        existing_last_run = {"iq_for_td_insight_last_fetch": "2026-12-01T09:00:00Z"}
        params = {}
        max_fetch = 50

        incidents, updated_last_run = fetch_iq_for_td_insights(blox_client, params, existing_last_run, max_fetch)

        assert len(incidents) == 1
        incident_data = json.loads(incidents[0]["rawJSON"])
        assert incident_data["insight_id"] == "insight-v2-after-floor"
        assert "insight-v2-before-floor" not in updated_last_run["iq_for_td_insight_ids"]

    def test_fetch_iq_for_td_insights_max_fetch_limit(self, blox_client, requests_mock):
        """Test fetch_iq_for_td_insights respects max_fetch limit"""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", text=load_json_file("iq-for-td-insight-list"))

        params = {}
        last_run = {}
        max_fetch = 2

        incidents, updated_last_run = fetch_iq_for_td_insights(blox_client, params, last_run, max_fetch)

        assert len(incidents) == 2
        assert len(updated_last_run["iq_for_td_insight_ids"]) == 2

    def test_fetch_iq_for_td_insights_empty_response(self, blox_client, requests_mock):
        """Test fetch_iq_for_td_insights when API returns empty insight list"""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", json={"insight_list": []})

        params = {}
        last_run = {}
        max_fetch = 50

        incidents, updated_last_run = fetch_iq_for_td_insights(blox_client, params, last_run, max_fetch)

        assert len(incidents) == 0
        # The floor timestamp is still seeded on an empty first cycle so future cycles reuse it
        assert "iq_for_td_insight_last_fetch" in updated_last_run

    def test_fetch_iq_for_td_insights_empty_response_with_existing_last_run(self, blox_client, requests_mock):
        """Test fetch_iq_for_td_insights keeps the floor timestamp intact when API returns no insights"""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", json={"insight_list": []})

        existing_last_run = {"iq_for_td_insight_last_fetch": "2026-12-01T09:00:00Z", "iq_for_td_insight_ids": ["insight-v2-001"]}
        params = {}
        max_fetch = 50

        incidents, updated_last_run = fetch_iq_for_td_insights(blox_client, params, existing_last_run, max_fetch)

        assert len(incidents) == 0
        assert updated_last_run["iq_for_td_insight_last_fetch"] == "2026-12-01T09:00:00Z"
        assert updated_last_run["iq_for_td_insight_ids"] == ["insight-v2-001"]

    def test_fetch_iq_for_td_insights_test_mode(self, blox_client, requests_mock):
        """Test fetch_iq_for_td_insights in test mode"""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", text=load_json_file("iq-for-td-insight-list"))

        params = {}
        last_run = {}
        max_fetch = 50

        incidents, updated_last_run = fetch_iq_for_td_insights(blox_client, params, last_run, max_fetch, is_test=True)

        assert incidents == []
        assert updated_last_run == {}

    @pytest.mark.parametrize(
        "severity,expected_severity_level",
        [
            ("Low", 1),
            ("Medium", 2),
            ("High", 3),
            ("Critical", 4),
            ("Unknown", 1),  # Default severity for unmapped severity
            (None, 1),  # Default severity for missing severity
        ],
    )
    def test_fetch_iq_for_td_insights_severity_mapping(self, blox_client, requests_mock, severity, expected_severity_level):
        """Test fetch_iq_for_td_insights correctly maps severity to incident severity"""
        insight_data = {
            "insight_list": [
                {
                    "insight_id": "insight-v2-test",
                    "name": "Test Insight",
                    "description": "Test description",
                    "date_created": "2026-12-01T10:00:00Z",
                    "severity": severity,
                }
            ]
        }

        requests_mock.get(f"{BASE_URL}/api/v2/insights", json=insight_data)

        params = {}
        last_run = {}
        max_fetch = 50

        incidents, _ = fetch_iq_for_td_insights(blox_client, params, last_run, max_fetch)

        assert len(incidents) == 1
        assert incidents[0]["severity"] == expected_severity_level

    def test_fetch_iq_for_td_insights_integration_with_fetch_incidents(self, blox_client, requests_mock, mocker):
        """Test fetch_iq_for_td_insights integration with main fetch_incidents function"""
        mock_get_last_run = mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
        mock_incidents = mocker.patch.object(demisto, "incidents")

        requests_mock.get(f"{BASE_URL}/api/v2/insights", text=load_json_file("iq-for-td-insight-list"))

        params = {"max_fetch": "50", "ingestion_type": "IQ for TD Insight", "first_fetch": "24 hours"}

        fetch_incidents(blox_client, params)

        mock_get_last_run.assert_called_once()
        mock_set_last_run.assert_called_once()
        mock_incidents.assert_called_once()

        incidents_call = mock_incidents.call_args[0][0]
        assert len(incidents_call) == 3
        assert incidents_call[0]["name"].startswith("Infoblox IQ for TD Insight")

    @patch("InfobloxBloxOneThreatDefense.return_results")
    def test_test_module_through_main_function_for_iq_for_td_insight_fetch(self, mock_return, requests_mock, mocker):
        """Test of test_module through main() function for IQ for TD Insight fetch"""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", text=load_json_file("iq-for-td-insight-list"))

        patch_command_args_and_params(mocker, "test-module", {})
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "credentials": {"password": "test-api-key"},
                "isFetch": True,
                "max_fetch": "10",
                "ingestion_type": "IQ for TD Insight",
            },
        )

        main()

        assert mock_return.call_args.args[0] == "ok"


class TestMacEnrichCommand:
    def test_mac_enrich_command_success(self, blox_client, requests_mock):
        """Test successful MAC address enrichment with valid data"""
        test_mac = "00:00:00:00:00:01"

        # Load test data
        mac_response = util_load_json("enrichment_mac_address_response.json")
        mac_context = util_load_json("mac_command_context.json")
        mac_hr = util_load_text_data("mac_command_success_hr.md")

        # Mock API response
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/dhcp/lease?_filter=hardware=='{test_mac}'&_limit=1", json=mac_response, status_code=200
        )

        # Execute command
        command_result = mac_enrich_command(blox_client, args={"mac": test_mac})

        # Verify command outputs
        assert command_result.outputs_prefix == "InfobloxCloud.DHCPLease"
        assert command_result.outputs_key_field == "hardware"
        assert command_result.outputs == remove_empty_elements(mac_context)
        assert command_result.raw_response == mac_response
        assert command_result.readable_output == mac_hr

    @pytest.mark.parametrize("mac_address", ["00:00:00:00:00:00", "00-00-00-00-00-00", "0000.0000.0000", "000000000000"])
    def test_mac_enrich_command_valid_format(self, blox_client, requests_mock, mac_address):
        """Test successful MAC address enrichment with valid formats."""

        # Load test data
        mac_response = util_load_json("enrichment_mac_address_response.json")

        # Mock API response
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/dhcp/lease?_filter=hardware=='{mac_address}'&_limit=1", json=mac_response, status_code=200
        )

        # Execute command
        mac_enrich_command(blox_client, args={"mac": mac_address})

    @pytest.mark.parametrize(
        "mac,expected_error",
        [("", MESSAGES["REQUIRED_ARGUMENT"].format("mac")), ("123", MESSAGES["INVALID_VALUE"].format("123", "mac"))],
    )
    def test_mac_enrich_command_error_input(self, blox_client, mac, expected_error):
        """Test command behavior with error input"""
        with pytest.raises(ValueError, match=expected_error):
            mac_enrich_command(blox_client, args={"mac": mac})

    def test_mac_enrich_command_no_results(self, blox_client, requests_mock):
        """Test command behavior when no results are returned"""
        test_mac = "00:11:22:33:44:55"

        # Mock empty response
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/dhcp/lease?_filter=hardware=='{test_mac}'&_limit=1", json={"results": []}, status_code=200
        )

        command_result = mac_enrich_command(blox_client, args={"mac": test_mac})
        assert command_result.readable_output == MESSAGES["NO_INFO_FOUND"].format("DHCP lease", "MAC", test_mac)
        assert command_result.outputs is None

    def test_mac_enrich_command_options_parsing(self, blox_client, requests_mock):
        """Test command's options JSON parsing functionality"""
        test_mac = "00:00:00:00:00:01"

        # Create a modified response with valid options JSON
        options_response = deepcopy(util_load_json("enrichment_mac_address_response.json"))
        options_data = options_response["results"][0]
        options_data["options"] = '{"Options":[{"Code":"57","Value":"test"}]}'

        # Mock API response
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/dhcp/lease?_filter=hardware=='{test_mac}'&_limit=1", json=options_response, status_code=200
        )

        # Execute command
        mac_enrich_command(blox_client, args={"mac": test_mac})

        # Verify options were returned as a string
        clean_data = remove_empty_elements_for_hr(options_data)
        assert isinstance(clean_data.get("options"), str)
        assert '"Code":"57"' in clean_data.get("options")

    def test_mac_enrich_command_options_parsing_error(self, blox_client, requests_mock):
        """Test command's handling of invalid options JSON"""
        test_mac = "00:00:00:00:00:01"

        # Create a modified response with invalid options JSON
        invalid_options_response = deepcopy(util_load_json("enrichment_mac_address_response.json"))
        invalid_options_response["results"][0]["options"] = "{invalid json}"

        # Mock API response
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/dhcp/lease?_filter=hardware=='{test_mac}'&_limit=1",
            json=invalid_options_response,
            status_code=200,
        )

        # Execute command - should not raise exception for invalid JSON
        command_result = mac_enrich_command(blox_client, args={"mac": test_mac})

        # Verify command executed without error
        assert command_result.outputs_prefix == "InfobloxCloud.DHCPLease"
        assert command_result.outputs_key_field == "hardware"


class TestBlockUnblock:
    """Test cases for block_ip_command, unblock_ip_command, block_domain_command, unblock_domain_command and indicator_remove_command"""  # noqa: E501

    @pytest.mark.parametrize(
        "args,error_msg",
        [
            ({"ip": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("ip")),
            ({"ip": "dummy", "custom_list_name": "test_name", "custom_list_type": "test_type"}, "Invalid IP or CIDR: dummy"),
            (
                {"ip": "0.0.0.0", "custom_list_name": "", "custom_list_type": "test_type"},
                MESSAGES["REQUIRED_ARGUMENT"].format("custom_list_name"),
            ),
            (
                {"ip": "0.0.0.1", "custom_list_type": "", "custom_list_name": "test_name"},
                MESSAGES["REQUIRED_ARGUMENT"].format("custom_list_type"),
            ),
            ({"ip": "0.0.0.0, 0"}, "Invalid IP or CIDR: 0"),
        ],
    )
    def test_block_ip_command_and_unblock_ip_command_when_empty_or_invalid_args_provided(self, blox_client, args, error_msg):
        """Test block_ip_command and unblock_ip_command when provided args are empty or invalid."""
        with pytest.raises(ValueError) as e:
            block_ip_command(blox_client, args)
        assert str(e.value) == error_msg

        with pytest.raises(ValueError) as e:
            unblock_ip_command(blox_client, args)
        assert str(e.value) == error_msg

    def test_block_ip_command_success(self, blox_client, requests_mock):
        """Test successful IP blocking"""
        # Load test data
        get_response = util_load_json("block-unblock-ip-command-response.json")
        readable_output = util_load_text_data("block-unblock-ip-command-readable.md")

        # Mock the three API calls that generic_named_list_method makes:

        # 1. Initial get_named_list call to get the list ID
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)

        # 2. update_named_list API call (POST to add items)
        requests_mock.post(
            f"{BASE_URL}/api/atcfw/v1/named_lists/{get_response['results']['id']}/items", json={"success": True}, status_code=200
        )

        # 3. Final get_named_list call to get updated results
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)

        result = block_ip_command(
            blox_client, {"ip": "0.0.0.0, 0.0.0.1", "custom_list_name": "Test Name", "custom_list_type": "test_type"}
        )

        assert result.readable_output == readable_output

    def test_block_ip_command_get_named_list_error_with_response_text(self, blox_client, requests_mock):
        """Test generic_named_list_method wraps a get_named_list failure that has a response body."""
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json={"detail": "boom"}, status_code=400)

        with pytest.raises(ValueError, match="boom"):
            block_ip_command(blox_client, {"ip": "0.0.0.1", "custom_list_name": "Test Name", "custom_list_type": "test_type"})

    def test_block_ip_command_get_named_list_error_without_response_text(self, blox_client, requests_mock):
        """Test generic_named_list_method falls back to a generic message when the failed response has no body."""
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", status_code=401, text="")

        with pytest.raises(ValueError, match="Failed to get named list"):
            block_ip_command(blox_client, {"ip": "0.0.0.1", "custom_list_name": "Test Name", "custom_list_type": "test_type"})

    def test_infobloxcloud_customlist_indicator_remove_items_not_present_in_list(self, blox_client, requests_mock):
        """Test that a remove failure reporting missing items is translated to a dedicated error message.

        infobloxcloud_customlist_indicator_remove is the only command that calls generic_named_list_method
        with is_remove=True, i.e. the only one that exercises the remove_named_list_items (DELETE) branch.
        """
        get_response = util_load_json("block-unblock-ip-command-response.json")
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)
        requests_mock.delete(
            f"{BASE_URL}/api/atcfw/v1/named_lists/123456/items",
            json={"detail": "2 Items not found in the list"},
            status_code=400,
        )

        with pytest.raises(ValueError, match="2 indicators were not present in the list."):
            infobloxcloud_customlist_indicator_remove(
                blox_client, {"indicators": "0.0.0.0, 0.0.0.1", "custom_list_name": "Test Name", "custom_list_type": "test_type"}
            )

    def test_infobloxcloud_customlist_indicator_remove_generic_error(self, blox_client, requests_mock):
        """Test that a remove failure with no item-count pattern is wrapped in a generic error message."""
        get_response = util_load_json("block-unblock-ip-command-response.json")
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)
        requests_mock.delete(
            f"{BASE_URL}/api/atcfw/v1/named_lists/123456/items", json={"detail": "list not found"}, status_code=404
        )

        with pytest.raises(ValueError, match="Failed to remove indicators from named list"):
            infobloxcloud_customlist_indicator_remove(
                blox_client, {"indicators": "0.0.0.0, 0.0.0.1", "custom_list_name": "Test Name", "custom_list_type": "test_type"}
            )

    def test_block_ip_command_update_named_list_generic_error(self, blox_client, requests_mock):
        """Test that an update_named_list failure with no item-count pattern is wrapped in a generic error message."""
        get_response = util_load_json("block-unblock-ip-command-response.json")
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)
        requests_mock.post(f"{BASE_URL}/api/atcfw/v1/named_lists/123456/items", status_code=404)

        with pytest.raises(ValueError, match="Failed to add indicators to named list"):
            block_ip_command(
                blox_client, {"ip": "0.0.0.0, 0.0.0.1", "custom_list_name": "Test Name", "custom_list_type": "test_type"}
            )

    def test_unblock_ip_command_success(self, blox_client, requests_mock):
        """Test successful IP unblocking"""
        # Load test data
        get_response = util_load_json("block-unblock-ip-command-response.json")
        readable_output = util_load_text_data("block-unblock-ip-command-readable.md")

        # Mock the three API calls that generic_named_list_method makes for remove operation:

        # 1. Initial get_named_list call to get the list ID
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)

        # 2. remove_named_list_items API call (DELETE to remove items) - needs JSON response
        requests_mock.post(f"{BASE_URL}/api/atcfw/v1/named_lists/123456/items", json={"success": True}, status_code=200)

        # 3. Final get_named_list call to get updated results
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)

        result = unblock_ip_command(
            blox_client, {"ip": "0.0.0.0, 0.0.0.1", "custom_list_name": "Test Name", "custom_list_type": "test_type"}
        )

        assert result.readable_output == readable_output

    @pytest.mark.parametrize(
        "args,error_msg",
        [
            ({"domain": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("domain")),
            (
                {"domain": "example.com", "custom_list_name": "", "custom_list_type": "test_type"},
                MESSAGES["REQUIRED_ARGUMENT"].format("custom_list_name"),
            ),
            (
                {"domain": "example.com", "custom_list_type": "", "custom_list_name": "test_name"},
                MESSAGES["REQUIRED_ARGUMENT"].format("custom_list_type"),
            ),
        ],
    )
    def test_block_domain_command_and_unblock_domain_command_when_empty_or_invalid_args_provided(
        self, blox_client, args, error_msg
    ):
        """Test block_domain_command and unblock_domain_command when provided args are empty or invalid."""
        with pytest.raises(ValueError) as e:
            block_domain_command(blox_client, args)
        assert str(e.value) == error_msg

        with pytest.raises(ValueError) as e:
            unblock_domain_command(blox_client, args)
        assert str(e.value) == error_msg

    def test_block_domain_command_success(self, blox_client, requests_mock):
        """Test successful domain blocking"""
        # Load test data
        get_response = util_load_json("block-unblock-domain-command-response.json")
        readable_output = util_load_text_data("block-unblock-domain-command-readable.md")

        # Mock the three API calls that generic_named_list_method makes:

        # 1. Initial get_named_list call to get the list ID
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)

        # 2. update_named_list API call (POST to add items)
        requests_mock.post(
            f"{BASE_URL}/api/atcfw/v1/named_lists/{get_response['results']['id']}/items", json={"success": True}, status_code=200
        )

        # 3. Final get_named_list call to get updated results
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)

        result = block_domain_command(
            blox_client, {"domain": "test.com, test.org", "custom_list_name": "Test Name", "custom_list_type": "test_type"}
        )

        assert result.readable_output == readable_output

    def test_unblock_domain_command_success(self, blox_client, requests_mock):
        """Test successful domain unblocking"""
        # Load test data
        get_response = util_load_json("block-unblock-domain-command-response.json")
        readable_output = util_load_text_data("block-unblock-domain-command-readable.md")

        # Mock the three API calls that generic_named_list_method makes for remove operation:

        # 1. Initial get_named_list call to get the list ID
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)

        # 2. remove_named_list_items API call (DELETE to remove items) - needs JSON response
        requests_mock.post(f"{BASE_URL}/api/atcfw/v1/named_lists/123456/items", json={"success": True}, status_code=200)

        # 3. Final get_named_list call to get updated results
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)

        result = unblock_domain_command(
            blox_client, {"domain": "test.com, test.org", "custom_list_name": "Test Name", "custom_list_type": "test_type"}
        )

        assert result.readable_output == readable_output

    @pytest.mark.parametrize(
        "args,error_msg",
        [
            ({"indicators": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("indicators")),
            (
                {"indicators": "0.0.0.0", "custom_list_name": "", "custom_list_type": "test_type"},
                MESSAGES["REQUIRED_ARGUMENT"].format("custom_list_name"),
            ),
            (
                {"indicators": "0.0.0.1", "custom_list_type": "", "custom_list_name": "test_name"},
                MESSAGES["REQUIRED_ARGUMENT"].format("custom_list_type"),
            ),
        ],
    )
    def test_infobloxcloud_customlist_indicator_remove_when_empty_or_invalid_args_provided(self, blox_client, args, error_msg):
        """Test infobloxcloud_customlist_indicator_remove when provided args are empty or invalid."""
        with pytest.raises(ValueError) as e:
            infobloxcloud_customlist_indicator_remove(blox_client, args)
        assert str(e.value) == error_msg

    def test_infobloxcloud_customlist_indicator_remove_success(self, blox_client, requests_mock):
        """Test successful indicator removal"""
        get_response = util_load_json("infobloxcloud-customlist-indicator-remove-response.json")
        readable_output = util_load_text_data("infobloxcloud-customlist-indicator-remove-readable.md")

        # 1. Initial get_named_list call to get the list ID
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)

        # 2. update_named_list API call (POST to add items)
        requests_mock.delete(
            f"{BASE_URL}/api/atcfw/v1/named_lists/{get_response['results']['id']}/items", json={"success": True}, status_code=200
        )

        # 3. Final get_named_list call to get updated results
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/named_lists/0", json=get_response, status_code=200)

        result = infobloxcloud_customlist_indicator_remove(
            blox_client, {"indicators": "example.com", "custom_list_name": "Test Name", "custom_list_type": "test_type"}
        )

        assert result.readable_output == readable_output


class TestDomainCommand:
    @patch("InfobloxBloxOneThreatDefense.return_warning")
    def test_domain_command_success(self, mock_return_warning, blox_client, requests_mock, capfd, mocker):
        domain = "test.com"
        not_found_domain = "notfound.com"
        list_of_domains = ", ".join([domain, not_found_domain])
        threat_response = util_load_json("enrichment_domain_threat_response.json")
        address_response = util_load_json("enrichment_domain_address_response.json")
        output = util_load_json("domain_command_context.json")
        domain_hr = util_load_text_data("domain_command_success_hr.md")
        domain_indicator = util_load_json("domain_command_indicator.json")
        params = {"integrationReliability": DBotScoreReliability.B, "create_relationships": True}
        mocker.patch.object(demisto, "params", return_value=params)
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats?host={domain}&type=host&rlimit=1", json=threat_response, status_code=200
        )
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/ipam/host?_filter=name=='{domain}'&_limit=1",
            json=address_response,
            status_code=200,
        )

        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats?host={not_found_domain}&type=host&rlimit=1", json={}, status_code=200
        )
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/ipam/host?_filter=name=='{not_found_domain}'&_limit=1", json={}, status_code=200
        )

        capfd.disabled()
        command_output = domain_command(blox_client, args={"domain": list_of_domains})

        # Ensure return_warning is called with the expected message
        mock_return_warning.assert_has_calls(
            [
                call(MESSAGES["NO_INFO_FOUND"].format("threat and address", "Domain", not_found_domain)),
            ]
        )

        # Verify command outputs
        assert output == command_output[0].outputs
        assert command_output[0].raw_response == {"threat_data": threat_response, "address_data": address_response}
        assert domain_hr == command_output[0].readable_output
        assert command_output[0].outputs_key_field == "domain"
        assert OUTPUT_PREFIX["Domain"] == command_output[0].outputs_prefix
        assert domain_indicator == command_output[0].indicator.to_context()

    @pytest.mark.parametrize("threat_level,expected_reputation", [(100, 3), (80, 3), (30, 2), (10, 1), (0, 0)])
    def test_domain_command_all_threat(self, blox_client, requests_mock, threat_level, expected_reputation, mocker):
        success_domain_address = "test.com"
        address_response = util_load_json("enrichment_domain_address_response.json")
        threat_response = util_load_json("enrichment_domain_threat_response.json")
        domain_indicator = util_load_json("domain_command_indicator.json")
        if threat_level < 80:
            del domain_indicator[list(domain_indicator.keys())[0]]["Malicious"]
        domain_indicator[list(domain_indicator.keys())[1]]["Score"] = expected_reputation

        threat_response["threat"][0]["threat_level"] = threat_level
        requests_mock.get(
            f"{BASE_URL}/tide/api/data/threats?host={success_domain_address}&type=host&rlimit=1",
            json=threat_response,
            status_code=200,
        )
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/ipam/host?_filter=name=='{success_domain_address}'&_limit=1",
            json=address_response,
            status_code=200,
        )

        params = {"integrationReliability": DBotScoreReliability.B, "create_relationships": True}
        mocker.patch.object(demisto, "params", return_value=params)
        command_output = domain_command(blox_client, args={"domain": success_domain_address})

        # Verify indicator score
        assert domain_indicator == command_output[0].indicator.to_context()

    def test_domain_command_maps_string_address_tags(self, blox_client, requests_mock, mocker):
        """Test that domain_command maps address_data tags of string value only onto the indicator."""
        domain = "test.com"
        params = {"integrationReliability": DBotScoreReliability.B}
        mocker.patch.object(demisto, "params", return_value=params)
        requests_mock.get(f"{BASE_URL}/tide/api/data/threats?host={domain}&type=host&rlimit=1", json={}, status_code=200)
        requests_mock.get(
            f"{BASE_URL}/api/ddi/v1/ipam/host?_filter=name=='{domain}'&_limit=1",
            json={"results": [{"tags": {"env": "prod", "empty": "", "num": 5}}]},
            status_code=200,
        )

        command_output = domain_command(blox_client, args={"domain": domain})

        tags = command_output[0].indicator.tags
        assert tags == ["env: prod"]

    def test_domain_command_invalid_args(self, blox_client, capfd):
        capfd.disabled()
        with pytest.raises(ValueError) as error_msg:
            domain_command(blox_client, args={"domain": " "})

        assert str(error_msg.value) == MESSAGES["REQUIRED_ARGUMENT"].format("domain")


class TestListSOCInsights:
    """Tests for list_soc_insights command."""

    @pytest.fixture
    def return_data(self):
        """Returns test data for insights."""
        response = util_load_json("soc-insights-list.json")
        return response

    def test_list_soc_insights_with_no_filters(self, return_data, blox_client, requests_mock):
        """Test list_soc_insights command with no filters applied."""
        # Mock the soc_insights_list API call
        requests_mock.get(f"{BASE_URL}/api/v1/insights", json=return_data, status_code=200)

        result = list_soc_insights_command(blox_client, {})

        assert result.outputs_prefix == "InfobloxCloud.SOCInsight"
        assert result.outputs_key_field == "insightId"
        assert len(result.outputs) == 3
        assert result.readable_output == util_load_text_data("soc-insights-list-readable.md")
        assert result.outputs == return_data.get("insightList")

    def test_list_soc_insights_with_filters(self, return_data, blox_client, requests_mock):
        """Test list_soc_insights command with filters applied."""
        args = {"status": "OPEN", "priority": "HIGH", "threat_type": "MALWARE"}

        # Mock the soc_insights_list API call
        requests_mock.get(f"{BASE_URL}/api/v1/insights", json=return_data, status_code=200)

        list_soc_insights_command(blox_client, args)

        # Verify the parameters were passed correctly to the API
        request = requests_mock.request_history[0]
        assert request.qs["status"] == ["open"]
        assert request.qs["priority"] == ["high"]
        assert request.qs["threat_type"] == ["malware"]

    def test_list_soc_insights_with_empty_response(self, blox_client, requests_mock):
        """Test list_soc_insights command with empty response."""
        # Mock empty API response
        requests_mock.get(f"{BASE_URL}/api/v1/insights", json={"insightList": []}, status_code=200)

        result = list_soc_insights_command(blox_client, {})

        assert result.raw_response == []


class TestListSOCInsightIndicators:
    """Tests for list_soc_insight_indicators_command command."""

    @pytest.fixture
    def indicators_data(self):
        """Load test data for indicators."""
        return util_load_json("insight-indicators-list-command-response.json")

    def test_list_soc_insight_indicators_command_success(self, indicators_data, blox_client, requests_mock):
        """Test successful listing of insight indicators."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/indicators",
            json=indicators_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123"}
        result = list_soc_insight_indicators_command(blox_client, args)

        expected_readable = util_load_text_data("insight-indicators-list-command-readable.md")
        assert result.outputs_prefix == "InfobloxCloud.Indicator"
        assert result.readable_output == expected_readable

    def test_list_soc_insight_indicators_command_empty_insight_id(self, blox_client):
        """Test with empty insight ID."""

        args = {"soc_insight_id": ""}
        with pytest.raises(ValueError) as e:
            list_soc_insight_indicators_command(blox_client, args)
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("soc_insight_id")

    def test_list_soc_insight_indicators_command_with_time_range(self, indicators_data, requests_mock, blox_client):
        """Test filtering indicators by time range."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/indicators",
            json=indicators_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123", "start_time": "2025-07-01T00:00:00Z", "end_time": "2025-07-31T23:59:59Z"}
        list_soc_insight_indicators_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.qs.get("from") == ["2025-07-01t00:00:00.000"]
        assert request.qs.get("to") == ["2025-07-31t23:59:59.000"]

    def test_list_soc_insight_indicators_command_with_invalid_time_range(self, blox_client):
        """Test filtering indicators by time range."""

        args = {"soc_insight_id": "insight-123", "start_time": "invalid-time", "end_time": "invalid-time"}
        with pytest.raises(ValueError) as e:
            list_soc_insight_indicators_command(blox_client, args)
        assert str(e.value) == 'Invalid date: "start_time"="invalid-time"'

    def test_list_soc_insight_indicators_command_empty_response(self, blox_client, requests_mock):
        """Test handling of empty response."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/indicators",
            json={"indicators": []},
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123"}
        result = list_soc_insight_indicators_command(blox_client, args)

        assert result.readable_output == "No indicators found."
        assert result.raw_response == []


class TestListSOCInsightEvents:
    """Tests for list_soc_insight_events_command command."""

    @pytest.fixture
    def events_data(self):
        """Load test data for events."""
        return util_load_json("insight-events-list-command-response.json")

    def test_list_soc_insight_events_command_success(self, events_data, blox_client, requests_mock):
        """Test successful listing of insight events."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/events",
            json=events_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123"}
        result = list_soc_insight_events_command(blox_client, args)

        expected_readable = util_load_text_data("insight-events-list-command-readable.md")
        assert result.readable_output == expected_readable
        assert result.outputs_prefix == "InfobloxCloud.Event"

    def test_list_soc_insight_events_command_with_device_ip(self, events_data, blox_client, requests_mock):
        """Test filtering events by device IP."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/events",
            json=events_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123", "device_ip": "0.0.0.0"}
        list_soc_insight_events_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.qs.get("device_ip") == ["0.0.0.0"]

    def test_list_soc_insight_events_command_invalid_ip(self, blox_client):
        """Test validation of invalid IP address."""

        args = {"soc_insight_id": "insight-123", "device_ip": "invalid-ip"}
        with pytest.raises(ValueError) as e:
            list_soc_insight_events_command(blox_client, args)

        assert str(e.value) == MESSAGES["INVALID_VALUE"].format("invalid-ip", "device_ip")

    def test_list_soc_insight_events_command_empty_insight_id(self, blox_client):
        """Test with empty insight ID."""

        args = {"soc_insight_id": ""}
        with pytest.raises(ValueError) as e:
            list_soc_insight_events_command(blox_client, args)
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("soc_insight_id")

    def test_list_soc_insight_events_command_with_time_range(self, events_data, requests_mock, blox_client):
        """Test filtering events by time range."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/events",
            json=events_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123", "start_time": "2025-07-01T00:00:00Z", "end_time": "2025-07-31T23:59:59Z"}
        list_soc_insight_events_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.qs.get("from") == ["2025-07-01t00:00:00.000"]
        assert request.qs.get("to") == ["2025-07-31t23:59:59.000"]

    def test_list_soc_insight_events_command_with_invalid_time_range(self, blox_client):
        """Test filtering events by time range."""

        args = {"soc_insight_id": "insight-123", "start_time": "invalid-time", "end_time": "invalid-time"}
        with pytest.raises(ValueError) as e:
            list_soc_insight_events_command(blox_client, args)
        assert str(e.value) == 'Invalid date: "start_time"="invalid-time"'

    def test_list_soc_insight_events_command_empty_response(self, blox_client, requests_mock):
        """Test handling of an empty events response."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/events",
            json={"events": []},
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123"}
        result = list_soc_insight_events_command(blox_client, args)

        assert result.readable_output == "No events found."
        assert result.raw_response == []


class TestListSOCInsightAssets:
    """Tests for list_soc_insight_assets_command command."""

    @pytest.fixture
    def assets_data(self):
        """Load test data for assets."""
        return util_load_json("insight-assets-list-command-response.json")

    def test_list_soc_insight_assets_command_success(self, assets_data, requests_mock, blox_client):
        """Test successful listing of insight assets."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/assets",
            json=assets_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123"}
        result = list_soc_insight_assets_command(blox_client, args)

        expected_readable = util_load_text_data("insight-assets-list-command-readable.md")
        assert result.readable_output == expected_readable
        assert result.outputs_prefix == "InfobloxCloud.Asset"

    def test_list_soc_insight_assets_command_empty_insight_id(self, blox_client):
        """Test with empty insight ID."""

        args = {"soc_insight_id": ""}
        with pytest.raises(ValueError) as e:
            list_soc_insight_assets_command(blox_client, args)
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("soc_insight_id")

    def test_list_soc_insight_assets_command_with_ip_filter(self, assets_data, requests_mock, blox_client):
        """Test filtering assets by IP address."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/assets",
            json=assets_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123", "qip": "0.0.0.0"}
        list_soc_insight_assets_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.qs.get("qip") == ["0.0.0.0"]

    def test_list_soc_insight_assets_command_with_mac_filter(self, assets_data, requests_mock, blox_client):
        """Test filtering assets by MAC address."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/assets",
            json=assets_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123", "cmac": "00:00:00:00:00:00"}
        list_soc_insight_assets_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.qs.get("cmac") == ["00:00:00:00:00:00"]

    def test_list_soc_insight_assets_command_with_time_range(self, assets_data, requests_mock, blox_client):
        """Test filtering assets by time range."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/assets",
            json=assets_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123", "start_time": "2025-07-01T00:00:00Z", "end_time": "2025-07-31T23:59:59Z"}
        list_soc_insight_assets_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.qs.get("from") == ["2025-07-01t00:00:00.000"]
        assert request.qs.get("to") == ["2025-07-31t23:59:59.000"]

    def test_list_soc_insight_assets_command_with_invalid_time_range(self, blox_client):
        """Test filtering assets by time range."""

        args = {"soc_insight_id": "insight-123", "start_time": "invalid-time", "end_time": "invalid-time"}
        with pytest.raises(ValueError) as e:
            list_soc_insight_assets_command(blox_client, args)
        assert str(e.value) == 'Invalid date: "start_time"="invalid-time"'

    def test_list_soc_insight_assets_command_empty_response(self, requests_mock, blox_client):
        """Test handling of empty response."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/assets",
            json={"assets": []},
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123"}
        result = list_soc_insight_assets_command(blox_client, args)

        assert result.readable_output == "No assets found."
        assert result.raw_response == []

    def test_list_soc_insight_assets_command_invalid_ip(self, blox_client):
        """Test validation of invalid IP address."""

        args = {"soc_insight_id": "insight-123", "qip": "invalid-ip"}
        with pytest.raises(ValueError) as e:
            list_soc_insight_assets_command(blox_client, args)

        assert str(e.value) == MESSAGES["INVALID_VALUE"].format("invalid-ip", "qip")

    def test_list_soc_insight_assets_command_invalid_mac(self, blox_client):
        """Test validation of invalid MAC address."""

        args = {"soc_insight_id": "insight-123", "cmac": "invalid-mac"}
        with pytest.raises(ValueError) as e:
            list_soc_insight_assets_command(blox_client, args)

        assert str(e.value) == MESSAGES["INVALID_VALUE"].format("invalid-mac", "cmac")


class TestListSOCInsightComments:
    """Tests for list_soc_insight_comments_command command."""

    @pytest.fixture
    def comments_data(self):
        """Load test data for comments."""
        return util_load_json("insight-comments-list-command-response.json")

    def test_list_soc_insight_comments_command_success(self, comments_data, requests_mock, blox_client):
        """Test successful listing of insight comments."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/comments",
            json=comments_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123"}
        result = list_soc_insight_comments_command(blox_client, args)

        expected_readable = util_load_text_data("insight-comments-list-command-readable.md")
        assert result.readable_output == expected_readable
        assert result.outputs_prefix == "InfobloxCloud.Comment"
        assert len(result.outputs) == 3

    def test_list_soc_insight_comments_command_with_limit(self, comments_data, requests_mock, blox_client):
        """Test limiting the number of comments returned."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/comments",
            json=comments_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123", "limit": "2"}
        result = list_soc_insight_comments_command(blox_client, args)

        assert len(result.outputs) == 2

    def test_list_soc_insight_comments_command_with_invalid_limit(self, blox_client):
        """Test invalid limit value."""

        args = {"soc_insight_id": "insight-123", "limit": "-1"}
        with pytest.raises(ValueError) as e:
            list_soc_insight_comments_command(blox_client, args)
        assert str(e.value) == "Limit should not be less than 0."

    def test_list_soc_insight_comments_with_time_range(self, comments_data, requests_mock, blox_client):
        """Test filtering comments by time range."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/comments",
            json=comments_data,
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123", "start_time": "2025-07-01T00:00:00Z", "end_time": "2025-07-31T23:59:59Z"}
        list_soc_insight_comments_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.qs.get("from") == ["2025-07-01t00:00:00.000"]
        assert request.qs.get("to") == ["2025-07-31t23:59:59.000"]

    def test_list_soc_insight_comments_command_with_invalid_time_range(self, blox_client):
        """Test filtering comments by time range."""

        args = {"soc_insight_id": "insight-123", "start_time": "invalid-time", "end_time": "invalid-time"}
        with pytest.raises(ValueError) as e:
            list_soc_insight_comments_command(blox_client, args)
        assert str(e.value) == 'Invalid date: "start_time"="invalid-time"'

    def test_list_soc_insight_comments_command_empty_response(self, requests_mock, blox_client):
        """Test handling of empty response."""

        requests_mock.get(
            f"{BASE_URL}/api/v1/insights/insight-123/comments",
            json={"comments": []},
            status_code=200,
        )

        args = {"soc_insight_id": "insight-123"}
        result = list_soc_insight_comments_command(blox_client, args)

        assert result.readable_output == "No comments found."
        assert result.raw_response == []

    def test_list_soc_insight_comments_command_empty_insight_id(self, blox_client):
        """Test with empty insight ID."""

        args = {"soc_insight_id": ""}
        with pytest.raises(ValueError) as e:
            list_soc_insight_comments_command(blox_client, args)
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("soc_insight_id")


class TestListIQForTDInsight:
    """Tests for list_iq_for_td_insight_command command."""

    @pytest.fixture
    def return_data(self):
        """Returns test data for IQ for TD Insights V2."""
        return util_load_json("iq-for-td-insight-list.json")

    def test_list_iq_for_td_insight_with_no_filters(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight command with no filters applied."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", json=return_data, status_code=200)

        result = list_iq_for_td_insight_command(blox_client, {})

        assert result.outputs_prefix == "InfobloxCloud.IQForTDInsight"
        assert result.outputs_key_field == "insight_id"
        assert len(result.outputs) == 3
        assert result.readable_output == util_load_text_data("iq-for-td-insight-list-readable.md")
        assert result.outputs == return_data.get("insight_list")

    def test_list_iq_for_td_insight_with_filters(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight command with filters applied, including comma-separated list cleaning."""
        args = {
            "status": "Needs Review",
            "name": "Beacon",
            "severity": "high",
            "threat_properties": " malware, phishing ,,ransomware ",
            "indicators": " 1.2.3.4 , 5.6.7.8,,",
            "assets": " asset-1 , asset-2",
            "user": "user1, ,user2",
        }
        requests_mock.get(f"{BASE_URL}/api/v2/insights", json=return_data, status_code=200)

        list_iq_for_td_insight_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.qs["status"] == ["needs review"]
        assert request.qs["name"] == ["beacon"]
        assert request.qs["severity"] == ["high"]
        assert request.qs["threat_properties"] == ["malware,phishing,ransomware"]
        assert request.qs["indicators"] == ["1.2.3.4,5.6.7.8"]
        assert request.qs["assets"] == ["asset-1,asset-2"]
        assert request.qs["user"] == ["user1,user2"]

    def test_list_iq_for_td_insight_with_invalid_date_created(self, blox_client):
        """Test list_iq_for_td_insight command with an invalid date_created value."""
        args = {"date_created": "invalid-time"}
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_command(blox_client, args)
        assert str(e.value) == 'Invalid date: "date_created"="invalid-time"'

    def test_list_iq_for_td_insight_with_invalid_status(self, blox_client):
        """Test list_iq_for_td_insight command with an invalid status."""
        args = {"status": "Under Review"}
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_command(blox_client, args)
        assert str(e.value) == MESSAGES["INVALID_VALUE"].format("Under Review", "status")

    def test_list_iq_for_td_insight_with_invalid_severity(self, blox_client):
        """Test list_iq_for_td_insight command with an invalid severity."""
        args = {"severity": "Urgent"}
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_command(blox_client, args)
        assert str(e.value) == MESSAGES["INVALID_VALUE"].format("Urgent", "severity")

    def test_list_iq_for_td_insight_with_case_insensitive_severity(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight command matches severity case-insensitively and sends the canonical value."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", json=return_data, status_code=200)

        list_iq_for_td_insight_command(blox_client, {"severity": "CRITICAL"})

        request = requests_mock.request_history[0]
        assert request.qs["severity"] == ["critical"]

    def test_list_iq_for_td_insight_with_date_created_floor_filtering(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight command filters out insights older than date_created client-side."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", json=return_data, status_code=200)

        args = {"date_created": "2026-12-01T11:00:00Z"}
        result = list_iq_for_td_insight_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert "date_created" not in request.qs

        insight_ids = [insight.get("insight_id") for insight in result.outputs]
        assert "insight-v2-001" not in insight_ids
        assert "insight-v2-002" in insight_ids
        assert "insight-v2-003" in insight_ids

    def test_list_iq_for_td_insight_with_empty_response(self, blox_client, requests_mock):
        """Test list_iq_for_td_insight command with empty response."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights", json={"insight_list": []}, status_code=200)

        result = list_iq_for_td_insight_command(blox_client, {})

        assert result.readable_output == "No IQ for TD Insights found."
        assert result.raw_response == []

    def test_list_iq_for_td_insight_with_naive_date_created_treated_as_utc(self, blox_client, requests_mock):
        """Naive (no timezone) date_created values, in both the filter arg and the insight data, are treated as UTC."""
        requests_mock.get(
            f"{BASE_URL}/api/v2/insights",
            json={
                "insight_list": [
                    {"insight_id": "insight-naive-001", "date_created": "2026-12-01T12:00:00", "name": "new"},
                    {"insight_id": "insight-naive-002", "date_created": "2026-12-01T09:00:00", "name": "old"},
                ]
            },
        )

        result = list_iq_for_td_insight_command(blox_client, {"date_created": "2026-12-01T10:00:00"})

        insight_ids = [insight.get("insight_id") for insight in result.outputs]
        assert "insight-naive-001" in insight_ids
        assert "insight-naive-002" not in insight_ids


class TestGetIQForTDInsight:
    """Tests for get_iq_for_td_insight_command command."""

    @pytest.fixture
    def return_data(self):
        """Returns test data for IQ for TD Insight detail."""
        return util_load_json("iq-for-td-insight-get.json")

    def test_get_iq_for_td_insight(self, return_data, blox_client, requests_mock):
        """Test get_iq_for_td_insight command with a valid insight_id."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001", json=return_data, status_code=200)

        result = get_iq_for_td_insight_command(blox_client, {"insight_id": "insight-v2-001"})

        assert result.outputs_prefix == "InfobloxCloud.IQForTDInsight"
        assert result.outputs_key_field == "insight_id"
        assert result.outputs == return_data
        assert result.readable_output == util_load_text_data("iq-for-td-insight-get-readable.md")

    def test_get_iq_for_td_insight_without_insight_id(self, blox_client):
        """Test get_iq_for_td_insight command with a missing insight_id."""
        with pytest.raises(ValueError) as e:
            get_iq_for_td_insight_command(blox_client, {})
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("insight_id")

    def test_get_iq_for_td_insight_not_found(self, blox_client, requests_mock):
        """Test get_iq_for_td_insight command when the insight does not exist."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-999", json={"detail": "insight not found"}, status_code=404)

        with pytest.raises(DemistoException) as e:
            get_iq_for_td_insight_command(blox_client, {"insight_id": "insight-v2-999"})
        assert MESSAGES["NO_RECORD_FOUND"] in str(e.value)

    def test_get_iq_for_td_insight_empty_body(self, blox_client, requests_mock):
        """Test get_iq_for_td_insight command when the API returns 200 with an empty body."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-000", json={}, status_code=200)

        result = get_iq_for_td_insight_command(blox_client, {"insight_id": "insight-v2-000"})

        assert result.readable_output == "No IQ for TD Insight found."
        assert result.raw_response == {}


class TestTrackingHeaders:
    """Tests for the x-Infoblox-client and x-Infoblox-customer tracking headers."""

    def test_client_sets_client_header_without_network_call(self, blox_client, requests_mock):
        """Constructing the client attaches x-Infoblox-client and never makes an API call."""
        assert blox_client._headers["x-Infoblox-client"] == "xsoar-ThreatDefense"
        assert "x-Infoblox-customer" not in blox_client._headers
        assert requests_mock.call_count == 0

    @pytest.mark.parametrize(
        "platform, expected",
        [
            ("x2", "cortex"),
            ("unified_platform", "cortex"),
            ("xsoar", "xsoar"),
            ("xsoar_hosted", "xsoar"),
            (None, "xsoar"),
        ],
    )
    def test_get_platform_name(self, mocker, platform, expected):
        """Test the platform segment of the x-Infoblox-client header for each server platform."""
        mocker.patch.object(demisto, "demistoVersion", return_value={"platform": platform})
        assert get_platform_name() == expected

    def test_attach_customer_tracking_header_success(self, blox_client, requests_mock, mocker):
        """Test the header is fetched, set, and cached when there is no prior cached value."""
        mocker.patch("InfobloxBloxOneThreatDefense.get_integration_context", return_value={})
        mock_set_context = mocker.patch("InfobloxBloxOneThreatDefense.set_integration_context")
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/account", json={"results": {"customer_id": "1234"}}, status_code=200)

        blox_client.attach_customer_tracking_header()

        assert blox_client._headers["x-Infoblox-customer"] == "1234"
        mock_set_context.assert_called_once_with({"api_key_hash": blox_client._api_key_hash, "customer_id": "1234"})

    def test_attach_customer_tracking_header_uses_cache(self, blox_client, requests_mock, mocker):
        """Test a cached customer_id for the same Service API Key is reused without an API call."""
        mocker.patch(
            "InfobloxBloxOneThreatDefense.get_integration_context",
            return_value={"api_key_hash": blox_client._api_key_hash, "customer_id": "cached-1234"},
        )
        mock_set_context = mocker.patch("InfobloxBloxOneThreatDefense.set_integration_context")

        blox_client.attach_customer_tracking_header()

        assert blox_client._headers["x-Infoblox-customer"] == "cached-1234"
        assert requests_mock.call_count == 0
        mock_set_context.assert_not_called()

    def test_attach_customer_tracking_header_refetches_on_api_key_change(self, blox_client, requests_mock, mocker):
        """Test a cached customer_id for a different Service API Key triggers a fresh fetch."""
        mocker.patch(
            "InfobloxBloxOneThreatDefense.get_integration_context",
            return_value={"api_key_hash": "some-other-hash", "customer_id": "stale-1234"},
        )
        mock_set_context = mocker.patch("InfobloxBloxOneThreatDefense.set_integration_context")
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/account", json={"results": {"customer_id": "new-5678"}}, status_code=200)

        blox_client.attach_customer_tracking_header()

        assert blox_client._headers["x-Infoblox-customer"] == "new-5678"
        mock_set_context.assert_called_once_with({"api_key_hash": blox_client._api_key_hash, "customer_id": "new-5678"})

    def test_attach_customer_tracking_header_swallows_errors(self, blox_client, requests_mock, mocker):
        """Test a failure to retrieve customer_id is logged and never raised or blocks the header from being set."""
        mocker.patch("InfobloxBloxOneThreatDefense.get_integration_context", return_value={})
        mock_set_context = mocker.patch("InfobloxBloxOneThreatDefense.set_integration_context")
        requests_mock.get(f"{BASE_URL}/api/atcfw/v1/account", json={"error": "forbidden"}, status_code=403)

        blox_client.attach_customer_tracking_header()

        assert "x-Infoblox-customer" not in blox_client._headers
        mock_set_context.assert_not_called()


class TestUpdateIQForTDInsightStatus:
    """Tests for update_iq_for_td_insight_status_command command."""

    def test_update_iq_for_td_insight_status_with_comment(self, blox_client, requests_mock):
        """Test update_iq_for_td_insight_status command with a valid insight_id, status, and comment."""
        requests_mock.put(f"{BASE_URL}/api/v2/insights/status", json={}, status_code=201)
        args = {"insight_id": "insight-v2-001", "status": "Resolved", "comment": "Remediated the affected asset."}

        result = update_iq_for_td_insight_status_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.json() == {
            "insight_id": "insight-v2-001",
            "status": "Resolved",
            "comment": "Remediated the affected asset.",
        }
        assert result.outputs_prefix == "InfobloxCloud.IQForTDInsight"
        assert result.outputs_key_field == "insight_id"
        assert result.outputs == {
            "insight_id": "insight-v2-001",
            "status": "Resolved",
            "comment": "Remediated the affected asset.",
        }
        assert result.readable_output == "Successfully updated the status of IQ for TD Insight 'insight-v2-001' to 'Resolved'."

    def test_update_iq_for_td_insight_status_without_comment(self, blox_client, requests_mock):
        """Test update_iq_for_td_insight_status command without an optional comment."""
        requests_mock.put(f"{BASE_URL}/api/v2/insights/status", json={}, status_code=201)
        args = {"insight_id": "insight-v2-001", "status": "In Progress"}

        result = update_iq_for_td_insight_status_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.json() == {"insight_id": "insight-v2-001", "status": "In Progress"}
        assert result.outputs == {"insight_id": "insight-v2-001", "status": "In Progress"}

    def test_update_iq_for_td_insight_status_without_insight_id(self, blox_client):
        """Test update_iq_for_td_insight_status command with a missing insight_id."""
        with pytest.raises(ValueError) as e:
            update_iq_for_td_insight_status_command(blox_client, {"status": "Resolved"})
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("insight_id")

    def test_update_iq_for_td_insight_status_without_status(self, blox_client):
        """Test update_iq_for_td_insight_status command with a missing status."""
        with pytest.raises(ValueError) as e:
            update_iq_for_td_insight_status_command(blox_client, {"insight_id": "insight-v2-001"})
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("status")

    def test_update_iq_for_td_insight_status_with_invalid_status(self, blox_client):
        """Test update_iq_for_td_insight_status command with an invalid status value."""
        args = {"insight_id": "insight-v2-001", "status": "Closed"}
        with pytest.raises(ValueError) as e:
            update_iq_for_td_insight_status_command(blox_client, args)
        assert str(e.value) == MESSAGES["INVALID_VALUE"].format("Closed", "status")

    def test_update_iq_for_td_insight_status_not_found(self, blox_client, requests_mock):
        """Test update_iq_for_td_insight_status command when the insight does not exist."""
        requests_mock.put(f"{BASE_URL}/api/v2/insights/status", json={"detail": "insight not found"}, status_code=404)
        args = {"insight_id": "insight-v2-999", "status": "Resolved"}

        with pytest.raises(DemistoException) as e:
            update_iq_for_td_insight_status_command(blox_client, args)
        assert MESSAGES["NO_RECORD_FOUND"] in str(e.value)


class TestListIQForTDInsightAssets:
    """Tests for list_iq_for_td_insight_assets_command command."""

    @pytest.fixture
    def return_data(self):
        """Returns test data for IQ for TD Insight assets."""
        return util_load_json("iq-for-td-insight-asset-list.json")

    def test_list_iq_for_td_insight_assets_with_no_filters(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight_assets_command with no filters applied."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/assets", json=return_data, status_code=200)

        result = list_iq_for_td_insight_assets_command(blox_client, {"insight_id": "insight-v2-001"})

        assert result.outputs_prefix == "InfobloxCloud.IQForTDInsightAsset"
        assert result.outputs_key_field == "device_name"
        assert len(result.outputs) == 2
        assert result.readable_output == util_load_text_data("iq-for-td-insight-asset-list-readable.md")
        assert result.outputs == return_data.get("assets")

    def test_list_iq_for_td_insight_assets_with_filters(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight_assets_command with filters applied, including comma-separated list cleaning."""
        args = {
            "insight_id": "insight-v2-001",
            "device_name": "dummy-host-01",
            "indicators": " dummy-indicator-1.com , dummy-indicator-2.com,,",
            "users": " dummy-user-1 , ,dummy-user-2",
            "ip_address": "0.0.0.0, 0.0.0.1",
            "is_verified": "true",
            "limit": "50",
        }
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/assets", json=return_data, status_code=200)

        list_iq_for_td_insight_assets_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.qs["device_name"] == ["dummy-host-01"]
        assert request.qs["indicators"] == ["dummy-indicator-1.com,dummy-indicator-2.com"]
        assert request.qs["users"] == ["dummy-user-1,dummy-user-2"]
        assert request.qs["ip_address"] == ["0.0.0.0,0.0.0.1"]
        assert request.qs["is_verified"] == ["true"]
        assert request.qs["limit"] == ["50"]

    def test_list_iq_for_td_insight_assets_with_is_verified_false(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight_assets_command with is_verified=false, verifying False is preserved."""
        args = {
            "insight_id": "insight-v2-001",
            "is_verified": "false",
        }
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/assets", json=return_data, status_code=200)

        list_iq_for_td_insight_assets_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert request.qs["is_verified"] == ["false"]

    def test_list_iq_for_td_insight_assets_without_insight_id(self, blox_client):
        """Test list_iq_for_td_insight_assets_command with a missing insight_id."""
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_assets_command(blox_client, {})
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("insight_id")

    @pytest.mark.parametrize("limit", ["0", "-5"])
    def test_list_iq_for_td_insight_assets_with_non_positive_limit(self, blox_client, limit):
        """Test list_iq_for_td_insight_assets_command with a zero or negative limit."""
        args = {"insight_id": "insight-v2-001", "limit": limit}
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_assets_command(blox_client, args)
        assert str(e.value) == MESSAGES["INVALID_VALUE"].format(limit, "limit")

    def test_list_iq_for_td_insight_assets_with_empty_response(self, blox_client, requests_mock):
        """Test list_iq_for_td_insight_assets_command with empty response."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/assets", json={"assets": []}, status_code=200)

        result = list_iq_for_td_insight_assets_command(blox_client, {"insight_id": "insight-v2-001"})

        assert result.readable_output == "No assets found for the given IQ for TD Insight."
        assert result.raw_response == []

    def test_list_iq_for_td_insight_assets_not_found(self, blox_client, requests_mock):
        """Test list_iq_for_td_insight_assets_command when the insight does not exist."""
        requests_mock.get(
            f"{BASE_URL}/api/v2/insights/insight-v2-999/assets", json={"detail": "insight not found"}, status_code=404
        )

        with pytest.raises(DemistoException) as e:
            list_iq_for_td_insight_assets_command(blox_client, {"insight_id": "insight-v2-999"})
        assert MESSAGES["NO_RECORD_FOUND"] in str(e.value)


class TestListIQForTDInsightEvents:
    """Tests for list_iq_for_td_insight_events_command command."""

    @pytest.fixture
    def return_data(self):
        """Returns test data for IQ for TD Insight events."""
        return util_load_json("iq-for-td-insight-event-list.json")

    def test_list_iq_for_td_insight_events_with_no_filters(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight_events_command with no filters applied."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/events", json=return_data, status_code=200)

        result = list_iq_for_td_insight_events_command(blox_client, {"insight_id": "insight-v2-001"})

        assert result.outputs_prefix == "InfobloxCloud.IQForTDInsightEvent"
        assert result.outputs_key_field == ["event_key"]
        assert len(result.outputs) == 2
        assert result.readable_output == util_load_text_data("iq-for-td-insight-event-list-readable.md")
        expected_events = add_event_count_to_events(return_data.get("events"), "insight-v2-001")
        assert result.outputs == [dict(event, insight_id="insight-v2-001") for event in expected_events]

    def test_list_iq_for_td_insight_events_with_duplicate_events(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight_events_command deduplicates events and reports event_count in context and HR."""
        events = return_data.get("events")
        duplicated_events = events + [events[0]]
        requests_mock.get(
            f"{BASE_URL}/api/v2/insights/insight-v2-001/events", json={"events": duplicated_events}, status_code=200
        )

        result = list_iq_for_td_insight_events_command(blox_client, {"insight_id": "insight-v2-001"})

        assert len(result.outputs) == 2
        assert result.outputs[0]["event_count"] == 2
        assert result.outputs[1]["event_count"] == 1
        assert len({event["event_key"] for event in result.outputs}) == 2
        assert "Event Count" in result.readable_output
        assert result.raw_response == duplicated_events

    def test_list_iq_for_td_insight_events_key_field_stable_when_optional_field_missing(self, blox_client, requests_mock):
        """Test event_key stays truthy even when an optional field is empty, so context merges instead of duplicating."""
        base_event = {
            "threat_level": "3",
            "threat_confidence": "90",
            "detected_at": "2026-12-01T02:55:00Z",
            "query": "dummy-indicator-1.com",
            "device_ip": "0.0.0.0",
            "mac_address": "",
        }
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/events", json={"events": [base_event]}, status_code=200)

        result = list_iq_for_td_insight_events_command(blox_client, {"insight_id": "insight-v2-001"})

        assert result.outputs[0]["event_key"]
        assert add_event_count_to_events([base_event], "insight-v2-001")[0]["event_key"] == result.outputs[0]["event_key"]

    def test_list_iq_for_td_insight_events_with_filters(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight_events_command with filters applied, including comma-separated list cleaning."""
        args = util_load_json("iq-for-td-insight-event-list-filters-args.json")
        expected_qs = util_load_json("iq-for-td-insight-event-list-filters-expected-qs.json")
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/events", json=return_data, status_code=200)

        list_iq_for_td_insight_events_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert {key: request.qs[key] for key in expected_qs} == expected_qs

    def test_list_iq_for_td_insight_events_without_insight_id(self, blox_client):
        """Test list_iq_for_td_insight_events_command with a missing insight_id."""
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_events_command(blox_client, {})
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("insight_id")

    @pytest.mark.parametrize("limit", ["0", "-5"])
    def test_list_iq_for_td_insight_events_with_non_positive_limit(self, blox_client, limit):
        """Test list_iq_for_td_insight_events_command with a zero or negative limit."""
        args = {"insight_id": "insight-v2-001", "limit": limit}
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_events_command(blox_client, args)
        assert str(e.value) == MESSAGES["INVALID_VALUE"].format(limit, "limit")

    def test_list_iq_for_td_insight_events_with_invalid_threat_level(self, blox_client):
        """Test list_iq_for_td_insight_events_command with an invalid threat_level."""
        args = {"insight_id": "insight-v2-001", "threat_level": "90"}
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_events_command(blox_client, args)
        assert str(e.value) == MESSAGES["INVALID_VALUE"].format("90", "threat_level")

    def test_list_iq_for_td_insight_events_with_invalid_threat_confidence(self, blox_client):
        """Test list_iq_for_td_insight_events_command with an invalid threat_confidence."""
        args = {"insight_id": "insight-v2-001", "threat_confidence": "90"}
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_events_command(blox_client, args)
        assert str(e.value) == MESSAGES["INVALID_VALUE"].format("90", "threat_confidence")

    def test_list_iq_for_td_insight_events_with_case_insensitive_threat_confidence(self, blox_client, requests_mock):
        """Test list_iq_for_td_insight_events_command matches threat_confidence case-insensitively and sends canonical value."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/events", json={"events": []}, status_code=200)

        list_iq_for_td_insight_events_command(blox_client, {"insight_id": "insight-v2-001", "threat_confidence": "high"})

        request = requests_mock.request_history[0]
        assert request.qs["threat_confidence"] == ["high"]

    def test_list_iq_for_td_insight_events_with_empty_response(self, blox_client, requests_mock):
        """Test list_iq_for_td_insight_events_command with empty response."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/events", json={"events": []}, status_code=200)

        result = list_iq_for_td_insight_events_command(blox_client, {"insight_id": "insight-v2-001"})

        assert result.readable_output == "No events found for the given IQ for TD Insight."
        assert result.raw_response == []

    def test_list_iq_for_td_insight_events_not_found(self, blox_client, requests_mock):
        """Test list_iq_for_td_insight_events_command when the insight does not exist."""
        requests_mock.get(
            f"{BASE_URL}/api/v2/insights/insight-v2-999/events", json={"detail": "insight not found"}, status_code=404
        )

        with pytest.raises(DemistoException) as e:
            list_iq_for_td_insight_events_command(blox_client, {"insight_id": "insight-v2-999"})
        assert MESSAGES["NO_RECORD_FOUND"] in str(e.value)


class TestListIQForTDInsightIndicators:
    """Tests for list_iq_for_td_insight_indicators_command command."""

    @pytest.fixture
    def return_data(self):
        """Returns test data for IQ for TD Insight indicators."""
        return util_load_json("iq-for-td-insight-indicator-list.json")

    def test_list_iq_for_td_insight_indicators_with_no_filters(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight_indicators_command with no filters applied."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/indicators", json=return_data, status_code=200)

        result = list_iq_for_td_insight_indicators_command(blox_client, {"insight_id": "insight-v2-001"})

        assert result.outputs_prefix == "InfobloxCloud.IQForTDInsightIndicator"
        assert result.outputs_key_field == ["indicator_key"]
        assert len(result.outputs) == 2
        assert result.readable_output == util_load_text_data("iq-for-td-insight-indicator-list-readable.md")
        expected_indicators = remove_empty_elements(return_data.get("indicators"))
        assert result.outputs == [
            dict(
                indicator,
                insight_id="insight-v2-001",
                indicator_key=f"insight-v2-001|{indicator.get('threat_indicator')}",
            )
            for indicator in expected_indicators
        ]

    def test_list_iq_for_td_insight_indicators_key_field_scoped_to_insight(self, return_data, blox_client, requests_mock):
        """Test indicator_key includes insight_id so the same indicator across different insights does not collide."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/indicators", json=return_data, status_code=200)
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-002/indicators", json=return_data, status_code=200)

        result_one = list_iq_for_td_insight_indicators_command(blox_client, {"insight_id": "insight-v2-001"})
        result_two = list_iq_for_td_insight_indicators_command(blox_client, {"insight_id": "insight-v2-002"})

        keys_one = {output["indicator_key"] for output in result_one.outputs}
        keys_two = {output["indicator_key"] for output in result_two.outputs}
        assert keys_one.isdisjoint(keys_two)

    def test_list_iq_for_td_insight_indicators_with_filters(self, return_data, blox_client, requests_mock):
        """Test list_iq_for_td_insight_indicators_command with filters applied, including comma-separated list cleaning."""
        args = util_load_json("iq-for-td-insight-indicator-list-filters-args.json")
        expected_qs = util_load_json("iq-for-td-insight-indicator-list-filters-expected-qs.json")
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/indicators", json=return_data, status_code=200)

        list_iq_for_td_insight_indicators_command(blox_client, args)

        request = requests_mock.request_history[0]
        assert {key: request.qs[key] for key in expected_qs} == expected_qs

    def test_list_iq_for_td_insight_indicators_without_insight_id(self, blox_client):
        """Test list_iq_for_td_insight_indicators_command with a missing insight_id."""
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_indicators_command(blox_client, {})
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("insight_id")

    @pytest.mark.parametrize("limit", ["0", "-5"])
    def test_list_iq_for_td_insight_indicators_with_non_positive_limit(self, blox_client, limit):
        """Test list_iq_for_td_insight_indicators_command with a zero or negative limit."""
        args = {"insight_id": "insight-v2-001", "limit": limit}
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_indicators_command(blox_client, args)
        assert str(e.value) == MESSAGES["INVALID_VALUE"].format(limit, "limit")

    def test_list_iq_for_td_insight_indicators_with_invalid_threat_level(self, blox_client):
        """Test list_iq_for_td_insight_indicators_command with an invalid threat_level."""
        args = {"insight_id": "insight-v2-001", "threat_level": "90"}
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_indicators_command(blox_client, args)
        assert str(e.value) == MESSAGES["INVALID_VALUE"].format("90", "threat_level")

    def test_list_iq_for_td_insight_indicators_with_invalid_statuses(self, blox_client):
        """Test list_iq_for_td_insight_indicators_command with an invalid status in a comma-separated statuses list."""
        args = {"insight_id": "insight-v2-001", "statuses": "Blocked,Under Review"}
        with pytest.raises(ValueError) as e:
            list_iq_for_td_insight_indicators_command(blox_client, args)
        assert str(e.value) == MESSAGES["INVALID_VALUE"].format("Under Review", "statuses")

    def test_list_iq_for_td_insight_indicators_with_empty_response(self, blox_client, requests_mock):
        """Test list_iq_for_td_insight_indicators_command with empty response."""
        requests_mock.get(f"{BASE_URL}/api/v2/insights/insight-v2-001/indicators", json={"indicators": []}, status_code=200)

        result = list_iq_for_td_insight_indicators_command(blox_client, {"insight_id": "insight-v2-001"})

        assert result.readable_output == "No indicators found for the given IQ for TD Insight."
        assert result.raw_response == []

    def test_list_iq_for_td_insight_indicators_not_found(self, blox_client, requests_mock):
        """Test list_iq_for_td_insight_indicators_command when the insight does not exist."""
        requests_mock.get(
            f"{BASE_URL}/api/v2/insights/insight-v2-999/indicators", json={"detail": "insight not found"}, status_code=404
        )

        with pytest.raises(DemistoException) as e:
            list_iq_for_td_insight_indicators_command(blox_client, {"insight_id": "insight-v2-999"})
        assert MESSAGES["NO_RECORD_FOUND"] in str(e.value)


class TestExecuteIQForTDInsightAction:
    """Tests for execute_iq_for_td_insight_action_command command."""

    @pytest.fixture
    def return_data(self):
        """Returns test data for IQ for TD Insight action execution result."""
        return util_load_json("iq-for-td-insight-action-execute.json")

    def test_execute_iq_for_td_insight_action_success(self, return_data, blox_client, requests_mock):
        """Test execute_iq_for_td_insight_action_command with a succeeded result."""
        requests_mock.post(f"{BASE_URL}/api/v2/insights/insight-v2-001/actions", json=return_data, status_code=200)
        args = {"insight_id": "insight-v2-001", "recommendation_id": "dummy-recommendation-id-1"}

        result = execute_iq_for_td_insight_action_command(blox_client, args)

        assert result.outputs_prefix == "InfobloxCloud.IQForTDInsightAction"
        assert result.outputs_key_field == "audit_entry_id"
        assert result.readable_output == util_load_text_data("iq-for-td-insight-action-execute-readable.md")
        assert result.outputs == {
            "action": "block",
            "status": "succeeded",
            "audit_entry_id": "dummy-audit-entry-1",
            "reason": "applied",
            "message": "",
            "insight_id": "insight-v2-001",
            "recommendation_id": "dummy-recommendation-id-1",
        }

    def test_execute_iq_for_td_insight_action_with_failed_result(self, blox_client, requests_mock):
        """Test execute_iq_for_td_insight_action_command with a failed result."""
        return_data = util_load_json("iq-for-td-insight-action-execute-failed.json")
        requests_mock.post(f"{BASE_URL}/api/v2/insights/insight-v2-001/actions", json=return_data, status_code=200)
        args = {"insight_id": "insight-v2-001", "recommendation_id": "dummy-recommendation-id-2"}

        result = execute_iq_for_td_insight_action_command(blox_client, args)

        assert result.outputs == {
            "action": "mark_risky",
            "status": "failed",
            "audit_entry_id": "",
            "reason": "resource_not_found",
            "message": "Recommendation not found.",
            "insight_id": "insight-v2-001",
            "recommendation_id": "dummy-recommendation-id-2",
        }

    def test_execute_iq_for_td_insight_action_request_body(self, return_data, blox_client, requests_mock):
        """Test execute_iq_for_td_insight_action_command sends the recommendation id and optional action override."""
        requests_mock.post(f"{BASE_URL}/api/v2/insights/insight-v2-001/actions", json=return_data, status_code=200)
        args = {
            "insight_id": "insight-v2-001",
            "recommendation_id": "dummy-recommendation-id-1",
            "action": "block",
        }

        execute_iq_for_td_insight_action_command(blox_client, args)

        request_body = requests_mock.last_request.json()
        assert request_body == {"items": [{"recommendation_id": "dummy-recommendation-id-1", "action": "block"}]}

    def test_execute_iq_for_td_insight_action_without_insight_id(self, blox_client):
        """Test execute_iq_for_td_insight_action_command with a missing insight_id."""
        with pytest.raises(ValueError) as e:
            execute_iq_for_td_insight_action_command(blox_client, {"recommendation_id": "dummy-recommendation-id-1"})
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("insight_id")

    def test_execute_iq_for_td_insight_action_without_recommendation_id(self, blox_client):
        """Test execute_iq_for_td_insight_action_command with a missing recommendation_id."""
        with pytest.raises(ValueError) as e:
            execute_iq_for_td_insight_action_command(blox_client, {"insight_id": "insight-v2-001"})
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("recommendation_id")

    def test_execute_iq_for_td_insight_action_with_invalid_action(self, blox_client):
        """Test execute_iq_for_td_insight_action_command with an invalid action."""
        args = {
            "insight_id": "insight-v2-001",
            "recommendation_id": "dummy-recommendation-id-1",
            "action": "delete",
        }
        with pytest.raises(ValueError) as e:
            execute_iq_for_td_insight_action_command(blox_client, args)
        assert str(e.value) == MESSAGES["INVALID_VALUE"].format("delete", "action")

    def test_execute_iq_for_td_insight_action_with_empty_response(self, blox_client, requests_mock):
        """Test execute_iq_for_td_insight_action_command with empty results in the response."""
        requests_mock.post(f"{BASE_URL}/api/v2/insights/insight-v2-001/actions", json={"results": []}, status_code=200)
        args = {"insight_id": "insight-v2-001", "recommendation_id": "dummy-recommendation-id-1"}

        result = execute_iq_for_td_insight_action_command(blox_client, args)

        assert result.readable_output == "No action execution result returned for the given IQ for TD Insight."
        assert result.raw_response is None

    def test_execute_iq_for_td_insight_action_not_found(self, blox_client, requests_mock):
        """Test execute_iq_for_td_insight_action_command when the insight does not exist."""
        requests_mock.post(
            f"{BASE_URL}/api/v2/insights/insight-v2-999/actions", json={"detail": "insight not found"}, status_code=404
        )
        args = {"insight_id": "insight-v2-999", "recommendation_id": "dummy-recommendation-id-1"}

        with pytest.raises(DemistoException) as e:
            execute_iq_for_td_insight_action_command(blox_client, args)
        assert MESSAGES["NO_RECORD_FOUND"] in str(e.value)


class TestUndoIQForTDInsightAction:
    """Tests for undo_iq_for_td_insight_action_command command."""

    @pytest.fixture
    def return_data(self):
        """Returns test data for IQ for TD Insight action undo result."""
        return util_load_json("iq-for-td-insight-action-undo.json")

    def test_undo_iq_for_td_insight_action_success(self, return_data, blox_client, requests_mock):
        """Test undo_iq_for_td_insight_action_command with a succeeded result."""
        requests_mock.post(
            f"{BASE_URL}/api/v2/insights/global-activity/dummy-audit-entry-1/undo", json=return_data, status_code=200
        )
        args = {"audit_entry_id": "dummy-audit-entry-1"}

        result = undo_iq_for_td_insight_action_command(blox_client, args)

        assert result.outputs_prefix == "InfobloxCloud.IQForTDInsightAction"
        assert result.outputs_key_field == "audit_entry_id"
        assert result.readable_output == util_load_text_data("iq-for-td-insight-action-undo-readable.md")
        assert result.outputs == {
            "action": "allow",
            "status": "succeeded",
            "audit_entry_id": "dummy-audit-entry-1",
        }

    def test_undo_iq_for_td_insight_action_with_failed_result(self, blox_client, requests_mock):
        """Test undo_iq_for_td_insight_action_command with a failed result."""
        return_data = util_load_json("iq-for-td-insight-action-undo-failed.json")
        requests_mock.post(
            f"{BASE_URL}/api/v2/insights/global-activity/dummy-audit-entry-2/undo", json=return_data, status_code=200
        )
        args = {"audit_entry_id": "dummy-audit-entry-2"}

        result = undo_iq_for_td_insight_action_command(blox_client, args)

        assert result.outputs == {
            "action": "",
            "status": "failed",
            "audit_entry_id": "dummy-audit-entry-2",
        }

    def test_undo_iq_for_td_insight_action_without_audit_entry_id(self, blox_client):
        """Test undo_iq_for_td_insight_action_command with a missing audit_entry_id."""
        with pytest.raises(ValueError) as e:
            undo_iq_for_td_insight_action_command(blox_client, {})
        assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("audit_entry_id")

    def test_undo_iq_for_td_insight_action_with_empty_response(self, blox_client, requests_mock):
        """Test undo_iq_for_td_insight_action_command with an empty result in the response."""
        requests_mock.post(f"{BASE_URL}/api/v2/insights/global-activity/dummy-audit-entry-1/undo", json={}, status_code=200)
        args = {"audit_entry_id": "dummy-audit-entry-1"}

        result = undo_iq_for_td_insight_action_command(blox_client, args)

        assert result.readable_output == "No action undo result returned for the given audit entry."
        assert result.raw_response is None

    def test_undo_iq_for_td_insight_action_not_found(self, blox_client, requests_mock):
        """Test undo_iq_for_td_insight_action_command when the audit entry does not exist."""
        requests_mock.post(
            f"{BASE_URL}/api/v2/insights/global-activity/dummy-audit-entry-999/undo",
            json={"detail": "audit entry not found"},
            status_code=404,
        )
        args = {"audit_entry_id": "dummy-audit-entry-999"}

        with pytest.raises(DemistoException) as e:
            undo_iq_for_td_insight_action_command(blox_client, args)
        assert MESSAGES["NO_RECORD_FOUND"] in str(e.value)


def test_main_entry_point():
    """
    Given:
    - Module is run as __main__.

    When:
    - The entry point guard executes main().

    Then:
    - main() is invoked. Client construction reads params["credentials"]["password"] before
      main()'s own try/except is entered, so with no integration params configured this
      surfaces as an unhandled KeyError rather than the usual return_error/SystemExit path.
    """
    import runpy

    with pytest.raises(KeyError, match="credentials"):
        runpy.run_module("InfobloxBloxOneThreatDefense", run_name="__main__")
