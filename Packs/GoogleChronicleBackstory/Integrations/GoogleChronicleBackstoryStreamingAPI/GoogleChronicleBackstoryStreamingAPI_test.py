"""Test File for GoogleChronicleBackstory Integration."""

import json
import os
import time
from unittest import mock

import demistomock as demisto
import pytest
from CommonServerPython import arg_to_datetime
from GoogleChronicleBackstoryStreamingAPI import (
    DATE_FORMAT,
    MAX_CONSECUTIVE_FAILURES,
    MAX_DELTA_TIME_FOR_STREAMING_DETECTIONS,
    MESSAGES,
    Client,
    auth_requests,
    fetch_samples,
    main,
    parse_error_message,
    service_account,
    stream_detection_alerts_in_retry_loop,
    timedelta,
    timezone,
    validate_configuration_parameters,
    validate_response,
)
from GoogleChronicleBackstoryStreamingAPI import test_module as main_test_module

GENERIC_INTEGRATION_PARAMS = {
    "credentials": {
        "password": "{}",
    },
    "first_fetch": "1 days",
}

FILTER_PARAMS = {
    "credentials": {
        "password": "{}",
    },
    "first_fetch": "1 days",
    "alert_type": ["Rule Detection Alerts"],
    "detection_severity": ["low"],
    "rule_names": ["SampleRule"],
    "exclude_rule_names": False,
    "rule_ids": ["ru_e6abfcb5-1b85-41b0-b64c-695b3250436f"],
    "exclude_rule_ids": False,
}


class MockResponse:
    status_code = 200
    json = lambda **_: {}  # noqa: E731
    text = "{}"
    request = lambda **_: ""  # noqa: E731
    post = lambda **_: ""  # noqa: E731


class StreamResponse:
    def __init__(self, **_):
        pass

    def __enter__(self):
        return self.mock_response

    def __exit__(self, *_):
        pass


def util_load_json(path):
    """Load a JSON file to python dictionary."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def mock_client_for_filter_params(mocker):
    """Fixture for the http client."""
    credentials = {"type": "service_account"}
    mocker.patch.object(service_account.Credentials, "from_service_account_info", return_value=credentials)
    mocker.patch.object(auth_requests, "AuthorizedSession", return_value=MockResponse)
    client = Client(params=FILTER_PARAMS, proxy=False, disable_ssl=True)
    return client


@pytest.fixture
def special_mock_client():
    """Fixture for the http client with no original client class response."""
    mocked_client = mock.Mock()
    mocked_client.region = "General"
    return mocked_client


@pytest.fixture()
def mock_client(mocker):
    """Fixture for the http client."""
    credentials = {"type": "service_account"}
    mocker.patch.object(service_account.Credentials, "from_service_account_info", return_value=credentials)
    mocker.patch.object(auth_requests, "AuthorizedSession", return_value=MockResponse)
    client = Client(params=GENERIC_INTEGRATION_PARAMS, proxy=False, disable_ssl=True)
    return client


@pytest.fixture()
def mock_client_v1_alpha(mocker):
    """Fixture for the http client for v1 alpha."""
    credentials = {"type": "service_account", "project_id": "test_project"}
    mocker.patch.object(service_account.Credentials, "from_service_account_info", return_value=credentials)
    mocker.patch.object(auth_requests, "AuthorizedSession", return_value=MockResponse)
    v1_alpha_params = {
        "credentials": {
            "password": "{}",
        },
        "first_fetch": "1 days",
        "use_v1_alpha": True,
        "project_instance_id": "test_instance",
        "region": "US",
    }
    client = Client(params=v1_alpha_params, proxy=False, disable_ssl=True)
    return client


def test_validate_configuration_parameters(capfd):
    """Test case scenario for validating the configuration parameters."""
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    capfd.close()
    validate_configuration_parameters(integration_params, "test-module")


def test_validate_configuration_parameters_with_v1_alpha_missing_instance_id():
    """Test case scenario for validating configuration parameters with v1 alpha enabled but missing project instance id."""
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    integration_params["use_v1_alpha"] = True
    with pytest.raises(ValueError) as e:
        validate_configuration_parameters(integration_params, "test-module")
    assert str(e.value) == "Please Provide the Google SecOps Project Instance ID to use V1 Alpha API."


def test_validate_configuration_parameters_with_v1_alpha_missing_region():
    """Test case scenario for validating configuration parameters with v1 alpha enabled but missing region."""
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    integration_params["use_v1_alpha"] = True
    integration_params["project_instance_id"] = "test_instance"
    integration_params["region"] = ""
    with pytest.raises(ValueError) as e:
        validate_configuration_parameters(integration_params, "test-module")
    assert str(e.value) == "Please Provide the valid region to use V1 Alpha API."


def test_validate_configuration_parameters_with_v1_alpha_success(capfd):
    """Test case scenario for successful validation of configuration parameters with v1 alpha enabled."""
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    integration_params["use_v1_alpha"] = True
    integration_params["project_instance_id"] = "test_instance"
    integration_params["region"] = "US"
    capfd.close()
    _, use_v1_alpha = validate_configuration_parameters(integration_params, "test-module")
    assert use_v1_alpha is True


@pytest.mark.parametrize("first_fetch", ["invalid", "8 days"])
def test_validate_configuration_parameters_with_invalid_first_fetch(capfd, first_fetch):
    """Test case scenario for validating the configuration parameters with invalid first fetch."""
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    integration_params["first_fetch"] = first_fetch
    capfd.close()
    with pytest.raises(ValueError):
        validate_configuration_parameters(integration_params, "test-module")


def test_validate_configuration_parameters_with_invalid_credentials():
    """Test case scenario for validating the configuration parameters with invalid credentials."""
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    integration_params["credentials"] = {"password": "invalid"}
    with pytest.raises(ValueError):
        validate_configuration_parameters(integration_params, "test-module")


@pytest.mark.parametrize("project_number", ["invalid", "-123", "0"])
def test_validate_configuration_parameters_with_invalid_project_number(capfd, project_number):
    """Test case scenario for validating the configuration parameters with invalid project number."""
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    integration_params["use_v1_alpha"] = True
    integration_params["project_instance_id"] = "test_instance"
    integration_params["project_number"] = project_number
    capfd.close()
    with pytest.raises(ValueError) as e:
        validate_configuration_parameters(integration_params, "test-module")

    assert str(e.value) == "Google SecOps Project Number should be a positive number."


def test_parse_error_message_with_invalid_json(capfd):
    """Test case scenario for parsing error message with invalid json."""
    capfd.close()
    assert parse_error_message("invalid json", "General") == MESSAGES["INVALID_JSON_RESPONSE"]


def test_parse_error_message_with_invalid_region(capfd):
    """Test case scenario for parsing error message with invalid region."""
    capfd.close()
    assert parse_error_message("service unavailable 404", "invalid region") == MESSAGES["INVALID_REGION"]


def test_validate_response(mocker, capfd):
    """
    Test case scenario for successful execution of validate_response.

    Given:
       - mocked client
    When:
       - Calling `validate_response` function.
    Then:
       - Returns an ok message
    """
    credentials = {"type": "service_account"}
    mocker.patch.object(service_account.Credentials, "from_service_account_info", return_value=credentials)
    mocker.patch.object(auth_requests, "AuthorizedSession", return_value=MockResponse)
    integration_params = GENERIC_INTEGRATION_PARAMS.copy()
    integration_params["region"] = "other"
    integration_params["other_region"] = "new-region"
    client = Client(params=integration_params, proxy=False, disable_ssl=True)

    mocker.patch.object(client.http_client, "request", return_value=MockResponse)
    capfd.close()
    assert validate_response(client, "") == {}


@mock.patch("demistomock.error")
@pytest.mark.parametrize(
    "args",
    [
        {"status_code": 429, "message": "API rate limit"},
        {"status_code": 300, "message": "Status code: 300"},
        {"status_code": 500, "message": "Internal server error"},
        {"status_code": 400, "message": "Status code: 400"},
        {"status_code": 403, "text": '{"error": {"code": 403}}', "message": "Permission denied"},
        {"text": "", "message": "Technical Error"},
        {"text": "*", "message": MESSAGES["INVALID_JSON_RESPONSE"]},
    ],
)
def test_429_or_500_error_for_validate_response(mock_error, special_mock_client, capfd, args):
    """
    Test behavior for 429 and 500 error codes for validate_response.
    """
    mock_error.return_value = {}

    class MockResponse:
        status_code = 200
        text = '[{"error": {}}]'

        def json(self):
            return json.loads(self.text)

    mock_response = MockResponse()
    if "status_code" in args:
        mock_response.status_code = args.get("status_code")
    if "text" in args:
        mock_response.text = args.get("text")

    special_mock_client.http_client.request.side_effect = [mock_response]
    capfd.close()
    with pytest.raises(ValueError) as value_error:
        validate_response(special_mock_client, "")

    assert args.get("message") in str(value_error.value)
    assert special_mock_client.http_client.request.call_count == 1


def test_test_module(mocker, mock_client, capfd):
    """
    Test case scenario for successful execution of test_module.

    Given:
       - mocked client
    When:
       - Calling `test_module` function.
    Then:
       - Assert for the continuation time and incidents.
    """
    mock_response = MockResponse()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/stream_detections.txt")) as f:
        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(time, "sleep", return_value=lambda **_: None)
        mock_client.http_client = mock_response
        capfd.close()
        assert main_test_module(mock_client, {}) == "ok"


def test_test_module_using_main(mocker, mock_client, capfd):
    """
    Test case scenario for successful execution of test_module using main function.

    Given:
       - mocked client
    When:
       - Calling `test_module` function.
    Then:
       - Assert for the continuation time and incidents.
    """
    mock_response = MockResponse()
    param = {
        "credentials": {"password": '{"key":"value"}'},
    }

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/stream_detections.txt")) as f:
        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(time, "sleep", return_value=lambda **_: None)
        mock_client.http_client = mock_response
        capfd.close()
        mocker.patch.object(demisto, "params", return_value=param)
        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(auth_requests, "AuthorizedSession", return_value=mock_response)
        main()


def test_test_module_for_error(mocker, mock_client, capfd):
    """
    Test case scenario for unsuccessful execution of test_module.

    Given:
       - mocked client
    When:
       - Calling `test_module` function.
    Then:
       - Assert for the continuation time and incidents.
    """
    mock_response = MockResponse()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/stream_detections_error_2.txt")) as f:
        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(time, "sleep", return_value=lambda **_: None)
        mock_client.http_client = mock_response
        capfd.close()
        assert main_test_module(mock_client, {}) == 'Connection closed with error: "error"'
        mock_response.post = None


def test_fetch_samples(mocker):
    """
    Test case scenario for successful execution of fetch_samples.

    Given:
       - mocked client
    When:
       - Calling `fetch_samples` function.
    Then:
       - Returns list of incidents stored in context.
    """
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"sample_events": "[{}]"})
    assert fetch_samples() == [{}]


def test_stream_detection_alerts_with_filter(mocker, mock_client_for_filter_params, capfd):
    """
    Test case scenario for successful execution of stream_detection_alerts with filter.

    Given:
       - mocked client
    When:
       - Calling `stream_detection_alerts` function.
    Then:
       - Assert for the continuation time and incidents.
    """
    mock_response = MockResponse()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/stream_detections.txt")) as f:
        mock_response.iter_lines = lambda **_: f.readlines()
        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(auth_requests, "AuthorizedSession", return_value=mock_response)
        mocker.patch.object(time, "sleep", return_value=lambda **_: None)

        capfd.close()
        assert stream_detection_alerts_in_retry_loop(mock_client_for_filter_params, arg_to_datetime("now"), test_mode=True) == {
            "continuation_time": "2024-03-21T09:44:04.877670709Z",
        }


def test_stream_detection_alerts_in_retry_loop(mocker, mock_client, capfd):
    """
    Test case scenario for successful execution of stream_detection_alerts_in_retry_loop.

    Given:
       - mocked client
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Assert for the continuation time and incidents.
    """
    mock_response = MockResponse()

    stream_detection_outputs: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/steam_detection_outputs.json")
    )

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/stream_detections.txt")) as f:
        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(auth_requests, "AuthorizedSession", return_value=mock_response)
        mocker.patch.object(time, "sleep", return_value=lambda **_: None)
        capfd.close()
        assert (
            stream_detection_alerts_in_retry_loop(mock_client, arg_to_datetime("now"), test_mode=True) == stream_detection_outputs
        )


def test_stream_detection_alerts_in_retry_loop_with_error(mocker, mock_client, capfd):
    """
    Test case scenario for execution of stream_detection_alerts_in_retry_loop when error response comes.

    Given:
       - mocked client
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Assert exception value.
    """
    mock_response = MockResponse()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/stream_detections_error.txt")) as f:
        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(auth_requests, "AuthorizedSession", return_value=mock_response)
        mocker.patch.object(time, "sleep", return_value=lambda **_: None)
        capfd.close()
        with pytest.raises(RuntimeError) as exc_info:
            stream_detection_alerts_in_retry_loop(mock_client, arg_to_datetime("now"), test_mode=True)

        assert str(exc_info.value) == MESSAGES["CONSECUTIVELY_FAILED"].format(MAX_CONSECUTIVE_FAILURES + 1)


def test_stream_detection_alerts_in_retry_loop_with_empty_response(mocker, mock_client, capfd):
    """
    Test case scenario for execution of stream_detection_alerts_in_retry_loop when empty response comes.

    Given:
       - mocked client
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Returns an ok message
    """
    mock_response = MockResponse()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/stream_detections_empty.txt")) as f:
        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(auth_requests, "AuthorizedSession", return_value=mock_response)
        mocker.patch.object(time, "sleep", return_value=lambda **_: None)
        capfd.close()
        with pytest.raises(Exception) as exc_info:
            stream_detection_alerts_in_retry_loop(mock_client, arg_to_datetime("now"), test_mode=True)
        assert str(exc_info.value) == "Exiting retry loop. Consecutive retries have failed 8 times."


def test_stream_detection_alerts_in_retry_loop_with_400(mocker, mock_client, capfd):
    """
    Test case scenario for execution of stream_detection_alerts_in_retry_loop when 400 status code comes.

    Given:
       - mocked client
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Assert exception value.
    """
    mock_response = MockResponse()
    mock_response.status_code = 400

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/stream_detections_error.txt")) as f:
        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(auth_requests, "AuthorizedSession", return_value=mock_response)
        mocker.patch.object(time, "sleep", return_value=lambda **_: None)
        new_continuation_time = arg_to_datetime(MAX_DELTA_TIME_FOR_STREAMING_DETECTIONS).astimezone(timezone.utc) + timedelta(
            minutes=1
        )  # type: ignore
        new_continuation_time_str = new_continuation_time.strftime(DATE_FORMAT)
        integration_context = {"continuation_time": new_continuation_time_str}
        mocker.patch.object(demisto, "getIntegrationContext", return_value=integration_context)
        capfd.close()
        with pytest.raises(RuntimeError) as exc_info:
            stream_detection_alerts_in_retry_loop(mock_client, arg_to_datetime("now"), test_mode=True)

        assert str(exc_info.value) == MESSAGES["INVALID_ARGUMENTS"] + " with status=400, error={}"


def test_stream_detection_alerts_in_retry_loop_with_v1_alpha(mocker, mock_client_v1_alpha, capfd):
    """
    Test case scenario for successful execution of stream_detection_alerts_in_retry_loop with v1 alpha.

    Given:
       - mocked client for v1 alpha
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Assert for the continuation time and incidents.
    """
    mock_response = MockResponse()

    stream_detection_outputs: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/v1_alpha_stream_detection_outputs.json")
    )

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/v1_alpha_stream_detections.txt")) as f:
        mock_response.iter_lines = lambda **_: f.readlines()

        stream_response = StreamResponse
        stream_response.mock_response = mock_response
        mock_response.post = StreamResponse
        mock_response.encoding = None
        mocker.patch.object(auth_requests, "AuthorizedSession", return_value=mock_response)
        mocker.patch.object(time, "sleep", return_value=lambda **_: None)
        mocker.patch.object(demisto, "getIntegrationContext", return_value={})
        capfd.close()
        assert (
            stream_detection_alerts_in_retry_loop(mock_client_v1_alpha, arg_to_datetime("now"), test_mode=True)
            == stream_detection_outputs
        )


def test_stream_detection_alerts_in_retry_loop_with_continuation_time_error_backstory(mocker, mock_client, capfd):
    """
    Test case scenario for execution of stream_detection_alerts_in_retry_loop when continuation time error occurs (Backstory).

    Given:
       - mocked client with old continuation time in integration context
       - 400 error with "continuationTime cannot be older than 168h0m0s ago" message
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Assert that updateModuleHealth is called with continuation time message
       - Assert that continuation time is updated to new value
    """
    mock_response = MockResponse()
    mock_response.status_code = 400
    mock_response.text = (
        '{"error": {"code": 400, "message": "generic::invalid_argument: continuationTime cannot be older than '
        '168h0m0s ago. To get older results, call ListDetections: invalid argument", "status": "INVALID_ARGUMENT"}}'
    )

    stream_response = StreamResponse
    stream_response.mock_response = mock_response
    mock_response.post = StreamResponse
    mock_response.encoding = None
    mocker.patch.object(auth_requests, "AuthorizedSession", return_value=mock_response)
    mocker.patch.object(time, "sleep", return_value=lambda **_: None)

    # Set up old continuation time in integration context (different from initial)
    old_continuation_time = "2025-09-01T05:31:06Z"  # Old time that would trigger the condition
    integration_context = {"continuation_time": old_continuation_time}
    mocker.patch.object(demisto, "getIntegrationContext", return_value=integration_context)

    # Mock updateModuleHealth to capture the call
    mock_update_module_health = mocker.patch.object(demisto, "updateModuleHealth")

    capfd.close()
    with pytest.raises(RuntimeError) as exc_info:
        stream_detection_alerts_in_retry_loop(mock_client, arg_to_datetime("2025-09-15T05:31:06Z"), test_mode=True)

    # Verify that the continuation time error message contains the expected text
    assert "continuationtime cannot be older than 168h0m0s ago" in str(exc_info.value).lower()

    # Verify that updateModuleHealth was called with the continuation time message
    mock_update_module_health.assert_called_once()
    call_args = mock_update_module_health.call_args[0][0]
    assert "Got the continuation time from the integration context which is older than" in call_args
    assert "Changing the continuation time to" in call_args


def test_stream_detection_alerts_in_retry_loop_with_continuation_time_error_v1_alpha(mocker, mock_client_v1_alpha, capfd):
    """
    Test case scenario for execution of stream_detection_alerts_in_retry_loop when continuation time error occurs (v1 alpha).

    Given:
       - mocked v1 alpha client with old continuation time in integration context
       - 400 error with "Request contains an invalid argument" message
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Assert that updateModuleHealth is called with continuation time message
       - Assert that continuation time is updated to new value
    """
    mock_response = MockResponse()
    mock_response.status_code = 400
    mock_response.text = (
        '{"error": {"code": 400, "message": "Request contains an invalid argument.", "status": "INVALID_ARGUMENT"}}'
    )

    stream_response = StreamResponse
    stream_response.mock_response = mock_response
    mock_response.post = StreamResponse
    mock_response.encoding = None
    mocker.patch.object(auth_requests, "AuthorizedSession", return_value=mock_response)
    mocker.patch.object(time, "sleep", return_value=lambda **_: None)

    # Set up old continuation time in integration context (different from initial)
    old_continuation_time = "2025-09-01T05:31:06Z"  # Old time that would trigger the condition
    integration_context = {"continuation_time": old_continuation_time}
    mocker.patch.object(demisto, "getIntegrationContext", return_value=integration_context)

    # Mock updateModuleHealth to capture the call
    mock_update_module_health = mocker.patch.object(demisto, "updateModuleHealth")

    capfd.close()
    with pytest.raises(RuntimeError) as exc_info:
        stream_detection_alerts_in_retry_loop(mock_client_v1_alpha, arg_to_datetime("2025-09-15T05:31:06Z"), test_mode=True)

    # Verify that the continuation time error message contains the expected text
    assert "request contains an invalid argument" in str(exc_info.value).lower()

    # Verify that updateModuleHealth was called with the continuation time message
    mock_update_module_health.assert_called_once()
    call_args = mock_update_module_health.call_args[0][0]
    assert "Got the continuation time from the integration context which is older than" in call_args
    assert "Changing the continuation time to" in call_args


def test_stream_detection_alerts_in_retry_loop_with_invalid_page_token_error(mocker, mock_client_v1_alpha, capfd):
    """
    Test case scenario for execution of stream_detection_alerts_in_retry_loop when invalid page token error occurs.

    Given:
       - mocked client with old continuation time in integration context
       - 400 error with invalid page token message (not continuation time related)
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Assert that updateModuleHealth is NOT called with continuation time message
       - Assert that the error is handled as a general 400 error
    """
    mock_response = MockResponse()
    mock_response.status_code = 400
    mock_response.text = '{"error": {"code": 400, "message": "invalid page token", "status": "INVALID_ARGUMENT"}}'

    stream_response = StreamResponse
    stream_response.mock_response = mock_response
    mock_response.post = StreamResponse
    mock_response.encoding = None
    mocker.patch.object(auth_requests, "AuthorizedSession", return_value=mock_response)
    mocker.patch.object(time, "sleep", return_value=lambda **_: None)

    integration_context = {"page_token": "invalid_page_token"}
    mocker.patch.object(demisto, "getIntegrationContext", return_value=integration_context)

    # Mock updateModuleHealth to capture the call
    mock_update_module_health = mocker.patch.object(demisto, "updateModuleHealth")

    capfd.close()
    with pytest.raises(RuntimeError) as exc_info:
        stream_detection_alerts_in_retry_loop(mock_client_v1_alpha, arg_to_datetime("2025-09-15T05:31:06Z"), test_mode=True)

    # Verify that the permission denied error message contains the expected text
    assert "invalid page token" in str(exc_info.value).lower()

    # Verify that updateModuleHealth was called with the general error message, NOT the continuation time message
    mock_update_module_health.assert_called_once()
    call_args = mock_update_module_health.call_args[0][0]
    # Should NOT contain continuation time message
    assert "Got the continuation time from the integration context which is older than" not in call_args
    # Should contain the actual error message
    assert "invalid page token" in call_args.lower()


def test_stream_detection_alerts_in_retry_loop_with_permission_denied_error(mocker, mock_client_v1_alpha, capfd):
    """
    Test case scenario for execution of stream_detection_alerts_in_retry_loop when permission denied error occurs.

    Given:
       - mocked client with old continuation time in integration context
       - 400 error with project configuration message (not continuation time related)
    When:
       - Calling `stream_detection_alerts_in_retry_loop` function.
    Then:
       - Assert that updateModuleHealth is NOT called with continuation time message
       - Assert that the error is handled as a general 400 error
    """
    mock_response = MockResponse()
    mock_response.status_code = 400
    mock_response.text = '{"error": {"code": 400, "message": "project is not properly configured", "status": "INVALID_ARGUMENT"}}'

    stream_response = StreamResponse
    stream_response.mock_response = mock_response
    mock_response.post = StreamResponse
    mock_response.encoding = None
    mocker.patch.object(auth_requests, "AuthorizedSession", return_value=mock_response)
    mocker.patch.object(time, "sleep", return_value=lambda **_: None)

    # Set up old continuation time in integration context (different from initial)
    old_continuation_time = "2025-09-01T05:31:06Z"  # Old time that would trigger the condition
    integration_context = {"continuation_time": old_continuation_time}
    mocker.patch.object(demisto, "getIntegrationContext", return_value=integration_context)

    # Mock updateModuleHealth to capture the call
    mock_update_module_health = mocker.patch.object(demisto, "updateModuleHealth")

    capfd.close()
    with pytest.raises(RuntimeError) as exc_info:
        stream_detection_alerts_in_retry_loop(mock_client_v1_alpha, arg_to_datetime("2025-09-15T05:31:06Z"), test_mode=True)

    # Verify that the permission denied error message contains the expected text
    error_message = str(exc_info.value).lower()
    assert "project" in error_message
    assert "not properly configured" in error_message

    # Verify that updateModuleHealth was called with the general error message, NOT the continuation time message
    mock_update_module_health.assert_called_once()
    call_args = mock_update_module_health.call_args[0][0]
    # Should NOT contain continuation time message
    assert "Got the continuation time from the integration context which is older than" not in call_args
    # Should contain the actual error message
    call_args_lower = call_args.lower()
    assert "project" in call_args_lower
    assert "not properly configured" in call_args_lower
