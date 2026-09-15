"""Test File for GoogleSecOpsCases Integration."""

import json
from pathlib import Path
from typing import Any
from unittest import mock
from urllib.parse import urlencode

import demistomock as demisto
import pytest
from CommonServerPython import DemistoException
from GoogleSecOpsCases import (
    ALERT_ID_DISPLAY,
    CASE_ALERT_ENTITY_UPDATE_ARGS,
    CASE_ALERT_UPDATE_ARGS,
    CASE_ID_DISPLAY,
    CASE_UPDATE_ARGS,
    DEFAULT_CASE_LIST_SORT_BY,
    DEFAULT_CASE_LIST_SORT_ORDER,
    DEFAULT_PAGE_SIZE,
    ENDPOINTS,
    ENTITY_ID_DISPLAY,
    MAX_FETCH_LIMIT,
    MAX_PAGE_SIZE,
    MAX_RETRIES,
    MESSAGES,
    SECOPS_OUTPUT_PATHS,
    VALID_CASE_ALERT_CLOSE_REASONS,
    VALID_CASE_ALERT_PRIORITIES,
    VALID_CASE_ALERT_STATUSES,
    VALID_CASE_CLOSE_REASONS,
    VALID_CASE_FILTER_LOGIC,
    VALID_CASE_PRIORITIES,
    VALID_CASE_SLA_STATUSES,
    VALID_CASE_STATUSES,
    VALID_CASE_TYPES,
    VALID_CASE_WORKFLOW_STATUSES,
    VALID_EXECUTION_SCOPES,
    VALID_SORT_ORDERS,
    Client,
    convert_time_to_ms,
    fetch_incidents,
    gcb_case_alert_customfield_list_command,
    gcb_case_alert_entity_create_command,
    gcb_case_alert_entity_get_command,
    gcb_case_alert_entity_list_command,
    gcb_case_alert_entity_property_add_command,
    gcb_case_alert_entity_property_update_command,
    gcb_case_alert_entity_update_command,
    gcb_case_alert_get_command,
    gcb_case_alert_list_command,
    gcb_case_alert_move_command,
    gcb_case_alert_recommendation_create_command,
    gcb_case_alert_recommendation_fetch_command,
    gcb_case_alert_sla_pause_command,
    gcb_case_alert_sla_resume_command,
    gcb_case_alert_sla_set_command,
    gcb_case_alert_tag_add_command,
    gcb_case_alert_tag_remove_command,
    gcb_case_alert_update_command,
    gcb_case_assign_command,
    gcb_case_close_command,
    gcb_case_close_definition_list_command,
    gcb_case_comment_create_command,
    gcb_case_comment_list_command,
    gcb_case_get_command,
    gcb_case_list_command,
    gcb_case_priority_change_command,
    gcb_case_reopen_command,
    gcb_case_sla_pause_command,
    gcb_case_sla_resume_command,
    gcb_case_stage_change_command,
    gcb_case_stage_definition_list_command,
    gcb_case_tag_add_command,
    gcb_case_tag_remove_command,
    gcb_case_update_command,
    gcb_playbook_attach_command,
    gcb_playbook_list_command,
    main,
    prepare_alert_entity_filter,
    test_module as secops_test_module,
    validate_case_alert_entity_get_args,
    validate_case_alert_entity_list_args,
    validate_case_alert_sla_set_args,
    validate_configuration_parameters,
    validate_fetch_params,
)

PERMISSION_DENIED_TEXT = MESSAGES["PERMISSION_DENIED"]
VALID_SERVICE_ACCOUNT = json.dumps({"project_id": "test-project", "type": "service_account"})
VALID_PARAMS: dict[str, Any] = {
    "credentials": {"password": VALID_SERVICE_ACCOUNT},
    "secops_project_instance_id": "test-instance",
    "region": "us",
    "secops_project_number": "12345",
    "url_format": "<chronicle>.<region>.<rep.googleapis.com>",
}
TEST_DAY_MS = 24 * 60 * 60 * 1000
MY_IP = "0.0.0.1"

BASE_URL = "https://chronicle.us.rep.googleapis.com/v1alpha/projects/12345/locations/us/instances/test-instance"
TEST_DATA_DIR = Path(__file__).parent


def util_load_json(path):
    """Load file in JSON format."""
    with open(TEST_DATA_DIR / path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_text_data(path: str) -> str:
    """Load a text file."""
    with open(TEST_DATA_DIR / path, encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def mock_client(mocker):
    """Fixture for a real Client instance with mocked credentials and retry."""
    mocker.patch("GoogleSecOpsCases.service_account.Credentials.from_service_account_info")
    mocker.patch("GoogleSecOpsCases.skip_proxy")
    mocker.patch("GoogleSecOpsCases.Client._implement_retry")
    return Client(params=VALID_PARAMS, proxy=False, disable_ssl=False)


def test_module_success(mock_client, requests_mock):
    """When a valid response is received, test_module should return 'ok'."""

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASES']}?pageSize=1&expand=products,tasks,tags,closureDetails,sla,alertsSla",
        json={},
    )

    result = secops_test_module(mock_client, {})

    assert result == "ok"


def test_main_test_module(mocker, mock_client):
    """Test main() routes test-module command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mocker.patch("GoogleSecOpsCases.test_module", return_value="ok")
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_return_results.assert_called_once_with("ok")


@pytest.mark.parametrize(
    "first_fetch",
    [
        "3 days",
        "7 days",
        "7 day",
        "168 hours",
        "168 hour",
        "1 week",
    ],
)
def test_module_with_fetch_enabled(mock_client, requests_mock, first_fetch):
    """When isFetch is enabled, test_module should return 'ok' for valid first_fetch values including 7-day boundary strings."""

    fetch_response = util_load_json("test_data/fetch_cases_success_response.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", json=fetch_response)

    params = {**VALID_PARAMS, "isFetch": True, "first_fetch": first_fetch, "max_fetch": 50}

    result = secops_test_module(mock_client, params)

    assert result == "ok"


def test_main_unknown_command(mocker, mock_client):
    """Test main() calls return_error for an unknown command."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="unknown-command")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_return_error = mocker.patch("GoogleSecOpsCases.return_error")

    main()

    mock_return_error.assert_called_once()
    assert "unknown-command" in mock_return_error.call_args[0][0]


def test_validate_configuration_parameters_success():
    """When valid parameters are provided, validate_configuration_parameters should pass without errors."""

    params = {
        "credentials": {"password": VALID_SERVICE_ACCOUNT},
        "secops_project_instance_id": "dummy_instance_id",
        "region": "us",
    }
    validate_configuration_parameters(params)


def test_validate_configuration_parameters_invalid_service_account_json():
    """When invalid service account JSON is provided, should raise ValueError."""

    params = {
        "credentials": {"password": '{"key","value"}'},
        "secops_project_instance_id": "dummy_instance_id",
    }
    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(params)
    assert str(error.value) == MESSAGES["INVALID_SERVICE_ACCOUNT_JSON"]


@pytest.mark.parametrize(
    "params, expected_error_message",
    [
        ({}, MESSAGES["MISSING_PROJECT_INSTANCE_ID"]),
        (
            {"secops_project_instance_id": "dummy", "region": "other"},
            MESSAGES["MISSING_REGION"],
        ),
        (
            {
                "secops_project_instance_id": "dummy",
                "credentials": {"password": "{}"},
                "secops_project_number": "invalid_number",
            },
            MESSAGES["INVALID_PROJECT_NUMBER"],
        ),
        (
            {
                "secops_project_instance_id": "dummy",
                "credentials": {"password": "{}"},
                "secops_project_number": "0",
            },
            MESSAGES["INVALID_PROJECT_NUMBER"],
        ),
        (
            {
                "secops_project_instance_id": "dummy",
                "credentials": {"password": "{}"},
                "secops_project_number": "-123",
            },
            MESSAGES["INVALID_PROJECT_NUMBER"],
        ),
    ],
)
def test_validate_configuration_parameters_invalid_params(params, expected_error_message):
    """Test validate_configuration_parameters with invalid parameters."""

    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(params)
    assert str(error.value) == expected_error_message


@pytest.mark.parametrize(
    "proxy, handle_proxy_return, expected_https_proxy, url_format, use_new_url_format",
    [
        (False, None, None, "<chronicle>.<region>.<rep.googleapis.com>", True),
        (
            True,
            {"https": "demo.com:8080"},
            "https://demo.com:8080",
            "<region>.<chronicle>.googleapis.com>",
            False,
        ),
    ],
)
def test_client_init(mocker, proxy, handle_proxy_return, expected_https_proxy, url_format, use_new_url_format):
    """Test Client.__init__ with and without proxy."""

    mocker.patch("GoogleSecOpsCases.service_account.Credentials.from_service_account_info")
    mocker.patch("GoogleSecOpsCases.auth_requests.AuthorizedSession")
    mocker.patch("GoogleSecOpsCases.Client._implement_retry")
    if proxy:
        mocker.patch("GoogleSecOpsCases.handle_proxy", return_value=handle_proxy_return)
    else:
        mocker.patch("GoogleSecOpsCases.skip_proxy")

    params = {**VALID_PARAMS, "url_format": url_format}
    google_secops_client = Client(params=params, proxy=proxy, disable_ssl=False)

    assert google_secops_client.use_new_url_format is use_new_url_format
    if expected_https_proxy:
        assert google_secops_client.proxy_info["https"] == expected_https_proxy


@pytest.mark.parametrize(
    "extra_params, expected_attr, expected_value",
    [
        ({"region": "other", "other_region": "eu"}, "project_location", "eu"),
        ({"secops_project_number": ""}, "project_number", "test-project"),
    ],
)
def test_client_init_special_params(mocker, extra_params, expected_attr, expected_value):
    """Test Client.__init__ other_region and project_number fallback branches."""
    mocker.patch("GoogleSecOpsCases.service_account.Credentials.from_service_account_info")
    mocker.patch("GoogleSecOpsCases.auth_requests.AuthorizedSession")
    mocker.patch("GoogleSecOpsCases.skip_proxy")
    mocker.patch("GoogleSecOpsCases.Client._implement_retry")

    google_secops_client = Client(params={**VALID_PARAMS, **extra_params}, proxy=False, disable_ssl=False)

    assert getattr(google_secops_client, expected_attr) == expected_value


def test_implement_retry_ssl_disabled(mocker):
    """Test _implement_retry mounts SSLAdapter when disable_ssl=True and Python >= 3.10."""
    mocker.patch("GoogleSecOpsCases.service_account.Credentials.from_service_account_info")
    mocker.patch("GoogleSecOpsCases.auth_requests.AuthorizedSession")
    mocker.patch("GoogleSecOpsCases.skip_proxy")
    mock_ssl_adapter = mocker.patch("GoogleSecOpsCases.SSLAdapter")
    mocker.patch("GoogleSecOpsCases.IS_PY3", True)
    mocker.patch("GoogleSecOpsCases.PY_VER_MINOR", 10)

    google_secops_client = Client(params=VALID_PARAMS, proxy=False, disable_ssl=True)

    mock_ssl_adapter.assert_called_once()
    google_secops_client.http_client.mount.assert_called_once()


def test_client_init_empty_https_proxy_raises(mocker):
    """Test Client.__init__ raises DemistoException when handle_proxy returns empty https value (line 193)."""
    mocker.patch("GoogleSecOpsCases.service_account.Credentials.from_service_account_info")
    mocker.patch("GoogleSecOpsCases.auth_requests.AuthorizedSession")
    mocker.patch("GoogleSecOpsCases.Client._implement_retry")
    mocker.patch("GoogleSecOpsCases.handle_proxy", return_value={"https": ""})

    with pytest.raises(DemistoException, match="https proxy value is empty"):
        Client(params=VALID_PARAMS, proxy=True, disable_ssl=False)


def test_implement_retry_ssl_enabled(mocker):
    """Test _implement_retry mounts plain HTTPAdapter when disable_ssl=False (line 282)."""
    mocker.patch("GoogleSecOpsCases.service_account.Credentials.from_service_account_info")
    mocker.patch("GoogleSecOpsCases.auth_requests.AuthorizedSession")
    mocker.patch("GoogleSecOpsCases.skip_proxy")
    mock_http_adapter = mocker.patch("GoogleSecOpsCases.HTTPAdapter")

    google_secops_client = Client(params=VALID_PARAMS, proxy=False, disable_ssl=False)

    mock_http_adapter.assert_called_once()
    google_secops_client.http_client.mount.assert_called_once()


def test_implement_retry_ssl_disabled_old_python(mocker):
    """Test _implement_retry falls back to HTTPAdapter when IS_PY3=False or PY_VER_MINOR < 10 (line 286)."""
    mocker.patch("GoogleSecOpsCases.service_account.Credentials.from_service_account_info")
    mocker.patch("GoogleSecOpsCases.auth_requests.AuthorizedSession")
    mocker.patch("GoogleSecOpsCases.skip_proxy")
    mock_ssl_adapter = mocker.patch("GoogleSecOpsCases.SSLAdapter")
    mocker.patch("GoogleSecOpsCases.IS_PY3", True)
    mocker.patch("GoogleSecOpsCases.PY_VER_MINOR", 9)

    google_secops_client = Client(params=VALID_PARAMS, proxy=False, disable_ssl=True)

    mock_ssl_adapter.assert_not_called()
    google_secops_client.http_client.mount.assert_called_once()


def test_implement_retry_name_error(mocker):
    """Test _implement_retry swallows NameError when Retry is not available (lines 290-291)."""
    mocker.patch("GoogleSecOpsCases.service_account.Credentials.from_service_account_info")
    mocker.patch("GoogleSecOpsCases.auth_requests.AuthorizedSession")
    mocker.patch("GoogleSecOpsCases.skip_proxy")
    mocker.patch("GoogleSecOpsCases.Retry", side_effect=NameError("Retry not defined"))
    mock_debug = mocker.patch("GoogleSecOpsCases.demisto.debug")

    Client(params=VALID_PARAMS, proxy=False, disable_ssl=False)

    mock_debug.assert_called_once()
    assert "_implement_retry: NameError" in mock_debug.call_args[0][0]


@pytest.mark.parametrize(
    "error_input, region, expected",
    [
        (json.dumps({"error": {"code": 403, "message": "Forbidden"}}), "us", MESSAGES["PERMISSION_DENIED"]),
        (json.dumps([{"error": {"message": "list error message", "code": 400}}]), "us", "list error message"),
        (
            "404 Not Found plain text",
            "other",
            'Invalid response from Google SecOps API. Check the provided "Other Region" parameter.',
        ),
        ("plain text error", "us", "Invalid response received from SecOps API. Response not in JSON format."),
        (
            json.dumps({"error": {"code": 409, "message": "Alert is already closed.", "status": "FAILED_PRECONDITION"}}),
            "us",
            "Alert is already closed.\nStatus: FAILED_PRECONDITION",
        ),
    ],
)
def test_parse_error_message(error_input, region, expected):
    """Test _parse_error_message across all branches."""

    assert Client._parse_error_message(error_input, region) == expected


@pytest.mark.parametrize(
    "use_new_url_format, location, expected_url_part",
    [
        (True, "us", "chronicle.us.rep.googleapis.com"),
        (False, "eu", "eu-chronicle.googleapis.com"),
    ],
)
def test_create_url_path(mock_client, use_new_url_format, location, expected_url_part):
    """Test _create_url_path uses the correct URL format."""

    mock_client.project_number = "12345"
    mock_client.project_location = location
    mock_client.project_instance_id = "test-instance"
    mock_client.use_new_url_format = use_new_url_format

    result = Client._create_url_path(mock_client)

    assert expected_url_part in result
    assert f"projects/12345/locations/{location}/instances/test-instance" in result


@pytest.mark.parametrize(
    "status_code, expected_error_text",
    [
        (500, MESSAGES["INTERNAL_SERVER_ERROR"].format(500, MAX_RETRIES, "error")),
        (429, MESSAGES["RATE_LIMIT_EXCEEDED"].format(429, MAX_RETRIES, "error")),
        (400, MESSAGES["HTTP_ERROR"].format(400, "error")),
        (401, MESSAGES["HTTP_ERROR"].format(401, "error")),
    ],
)
def test_validate_response_error_status_codes(mock_client, requests_mock, status_code, expected_error_text):
    """Test validate_response raises ValueError for error status codes."""
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", json={"error": {"message": "error"}}, status_code=status_code)

    with pytest.raises(ValueError) as error:
        mock_client.validate_response(ENDPOINTS["CASES"])

    assert str(error.value) == expected_error_text


def test_validate_response_non_json_body(mock_client, requests_mock):
    """Test validate_response raises ValueError when response body is not valid JSON."""
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", text="not-json", status_code=200)

    with pytest.raises(ValueError) as error:
        mock_client.validate_response(ENDPOINTS["CASES"])

    assert str(error.value) == MESSAGES["INVALID_JSON_RESPONSE"]


@pytest.mark.parametrize(
    "allow_empty_response, expected_result, expected_error",
    [
        (True, {}, None),
        (False, None, MESSAGES["EMPTY_RESPONSE"].format(200)),
    ],
)
def test_validate_response_empty_body(mock_client, requests_mock, allow_empty_response, expected_result, expected_error):
    """Test validate_response with empty body — returns {} when allowed, raises ValueError when not."""
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", text="", status_code=200)

    if expected_error:
        with pytest.raises(ValueError) as error:
            mock_client.validate_response(ENDPOINTS["CASES"], allow_empty_response=allow_empty_response)
        assert str(error.value) == expected_error
    else:
        result = mock_client.validate_response(ENDPOINTS["CASES"], allow_empty_response=allow_empty_response)
        assert result == expected_result


def test_fetch_incidents_success_without_last_run(mock_client, requests_mock):
    """Test fetch_incidents returns incidents and correct next_state when last_run is empty."""

    fetch_response = util_load_json("test_data/fetch_cases_success_response.json")
    expected_incidents = util_load_json("test_data/fetch_cases_incidents.json")

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", json=fetch_response)

    params = {
        **VALID_PARAMS,
        "first_fetch": "2026-01-01T00:00:00Z",
        "max_fetch": MAX_PAGE_SIZE,
        "case_priorities": "MEDIUM",
        "case_statuses": "OPENED",
        "case_environments": "Default",
        "case_tags": "phishing",
        "case_filter_logic": "AND",
    }

    incidents, next_state = fetch_incidents(mock_client, params, last_run={})

    assert incidents == expected_incidents
    assert "cases" in next_state
    cases_state = next_state["cases"]
    assert cases_state.get("page_token") == "dummy_next_page_token"
    assert cases_state.get("filter_hash") == "31265ed8b21176b0403f54e4e92bbcc2"
    assert cases_state.get("last_case_create_time") == "2026-05-07T01:39:18.871000Z"
    ingested_ids = cases_state["ingested_case_ids"]
    assert len(ingested_ids) == 3
    assert "101" in ingested_ids
    assert "102" in ingested_ids
    assert "103" in ingested_ids


def test_fetch_incidents_success_with_last_run(mock_client, requests_mock):
    """Test fetch_incidents updates state correctly when last_run already has start_time and page_token."""

    fetch_response = util_load_json("test_data/fetch_cases_success_response.json")
    expected_incidents = util_load_json("test_data/fetch_cases_incidents.json")

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", json=fetch_response)

    last_run = {
        "cases": {
            "start_time": "2026-05-01T00:00:00.000000Z",
            "page_token": "existing_page_cursor",
            "ingested_case_ids": [],
            "filter_hash": "26379b4441bae5bbf56de66366e5b0cf",
        }
    }
    params = {**VALID_PARAMS, "first_fetch": "3 days", "max_fetch": 10, "case_tags": "phishing", "case_filter_logic": "or"}

    incidents, next_state = fetch_incidents(mock_client, params, last_run=last_run)

    assert incidents == expected_incidents
    cases_state = next_state["cases"]
    assert cases_state.get("start_time") == "2026-05-01T00:00:00.000000Z"
    assert cases_state.get("page_token") == "dummy_next_page_token"
    ingested_ids = cases_state["ingested_case_ids"]
    assert len(ingested_ids) == 3
    assert "101" in ingested_ids
    assert "102" in ingested_ids
    assert "103" in ingested_ids


def test_fetch_incidents_with_duplicates(mock_client, requests_mock):
    """Test that already-ingested case IDs are skipped and not returned as incidents."""

    fetch_response = util_load_json("test_data/fetch_cases_success_response.json")
    expected_incidents = util_load_json("test_data/fetch_cases_incidents.json")

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", json=fetch_response)

    last_run = {"cases": {"start_time": "2026-05-01T00:00:00.000000Z", "ingested_case_ids": ["101"]}}
    params = {**VALID_PARAMS, "first_fetch": "3 days", "max_fetch": 10}

    incidents, next_state = fetch_incidents(mock_client, params, last_run=last_run)

    assert incidents == expected_incidents[1:]  # case 101 skipped
    ingested_ids = next_state["cases"]["ingested_case_ids"]
    assert len(ingested_ids) == 3
    assert "101" in ingested_ids
    assert "102" in ingested_ids
    assert "103" in ingested_ids


def test_fetch_incidents_with_no_page_token(mock_client, requests_mock):
    """Test fetch_incidents does not set page_token in next_state when the response has no next page."""

    fetch_response = util_load_json("test_data/fetch_cases_success_response.json")
    fetch_response_no_token = {k: v for k, v in fetch_response.items() if k != "nextPageToken"}

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", json=fetch_response_no_token)

    last_run = {"cases": {"start_time": "2026-05-01T00:00:00.000000Z", "page_token": "old_page_cursor", "ingested_case_ids": []}}
    params = {**VALID_PARAMS, "first_fetch": "3 days", "max_fetch": 10}

    incidents, next_state = fetch_incidents(mock_client, params, last_run=last_run)

    assert len(incidents) == 3
    assert "page_token" not in next_state["cases"]


def test_fetch_incidents_empty_response(mock_client, requests_mock):
    """Test fetch_incidents returns empty incidents list and preserves existing last_run state."""

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", json={"cases": []})

    last_run = {"cases": {"start_time": "2026-05-01T00:00:00.000000Z", "page_token": "some_cursor", "ingested_case_ids": ["101"]}}
    params = {**VALID_PARAMS, "first_fetch": "3 days", "max_fetch": 10}

    incidents, next_state = fetch_incidents(mock_client, params, last_run=last_run)

    assert incidents == []
    cases_state = next_state["cases"]
    assert cases_state.get("start_time") == "2026-05-01T00:00:00.000000Z"
    assert cases_state.get("ingested_case_ids") == ["101"]
    assert "page_token" not in cases_state


def test_fetch_incidents_filter_config_changed(mock_client, requests_mock):
    """Test that page_token is reset and start_time uses last_case_create_time when filter params change."""

    fetch_response = util_load_json("test_data/fetch_cases_success_response.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", json=fetch_response)

    last_run = {
        "cases": {
            "start_time": "2026-05-01T00:00:00.000000Z",
            "page_token": "stale_page_cursor",
            "ingested_case_ids": ["99"],
            "filter_hash": "old_hash_that_will_not_match",
            "last_case_create_time": "2026-05-03T00:00:00.000000Z",
        }
    }
    params = {
        **VALID_PARAMS,
        "first_fetch": "3 days",
        "max_fetch": 10,
        "case_priorities": "HIGH",
        "case_statuses": "OPENED",
        "case_filter_logic": "AND",
    }

    incidents, next_state = fetch_incidents(mock_client, params, last_run=last_run)

    cases_state = next_state["cases"]
    assert len(incidents) == 3
    assert cases_state.get("page_token") == "dummy_next_page_token"
    assert cases_state.get("start_time") == "2026-05-03T00:00:00.000000Z"
    assert cases_state.get("last_case_create_time") == "2026-05-07T01:39:18.871000Z"
    assert cases_state.get("filter_hash") == "5c2a12a431235dfd53483fe85e788bfb"


def test_main_fetch_incidents(mocker, mock_client, requests_mock):
    """Test main() routes fetch-incidents command correctly."""

    fetch_response = util_load_json("test_data/fetch_cases_success_response.json")
    expected_incidents = util_load_json("test_data/fetch_cases_incidents.json")

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", json=fetch_response)

    mocker.patch.object(demisto, "params", return_value={**VALID_PARAMS, "first_fetch": "3 days", "max_fetch": 50})
    mocker.patch.object(demisto, "command", return_value="fetch-incidents")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_incidents = mocker.patch.object(demisto, "incidents")

    main()

    mock_set_last_run.assert_called_once()
    mock_incidents.assert_called_once_with(expected_incidents)


@pytest.mark.parametrize(
    "params, expected_error",
    [
        (
            {"case_priorities": "INVALID_PRIORITY"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("case_priorities", ", ".join(VALID_CASE_PRIORITIES)),
        ),
        (
            {"case_statuses": "INVALID_STATUS"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("case_statuses", ", ".join(VALID_CASE_STATUSES)),
        ),
        (
            {"case_filter_logic": "XOR"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("case_filter_logic", ", ".join(VALID_CASE_FILTER_LOGIC)),
        ),
        (
            {"first_fetch": "2200-01-01T00:00:00Z"},
            MESSAGES["FUTURE_DATE"],
        ),
        (
            {"first_fetch": "10 days"},
            MESSAGES["INVALID_FIRST_FETCH"].format("10 days"),
        ),
        (
            {"max_fetch": 0},
            MESSAGES["INVALID_MAX_FETCH"].format(value=0, max_limit=MAX_FETCH_LIMIT),
        ),
        (
            {"max_fetch": -1},
            MESSAGES["INVALID_MAX_FETCH"].format(value=-1, max_limit=MAX_FETCH_LIMIT),
        ),
        (
            {"max_fetch": "abc"},
            MESSAGES["INVALID_MAX_FETCH"].format(value="abc", max_limit=MAX_FETCH_LIMIT),
        ),
        (
            {"max_fetch": 201},
            MESSAGES["INVALID_MAX_FETCH"].format(value=201, max_limit=MAX_FETCH_LIMIT),
        ),
        (
            {"max_fetch": 300},
            MESSAGES["INVALID_MAX_FETCH"].format(value=300, max_limit=MAX_FETCH_LIMIT),
        ),
    ],
)
def test_validate_fetch_params_invalid_values(params, expected_error):
    """Test validate_fetch_params raises ValueError for invalid parameter values when is_test=True."""

    with pytest.raises(ValueError) as exc_info:
        validate_fetch_params(params, is_test=True)

    assert expected_error in str(exc_info.value)


def test_gcb_case_list_command_success(mock_client, requests_mock):
    """Success with all individual filter args and mixed assignees (@SOC role + email)."""

    user_email = "active.user@example.com"
    user_id = "00000000-0000-0000-0000-000000000111"
    soar_users_response = util_load_json("test_data/legacy_soar_users_response.json")
    emails = [user_email, "not_found_email"]
    email_conditions = " OR ".join(f"email='{e}'" for e in emails)
    soar_users_qs = urlencode({"pageSize": len(emails), "filter": f"({email_conditions}) AND accountState='ACTIVE'"})
    mock_response = util_load_json("test_data/case_list_success_response.json")
    expected_outputs = util_load_json("test_data/case_list_context.json")
    expected_hr = util_load_text_data("test_data/case_list_hr.md")

    case_filter = " AND ".join(
        [
            '(priority="PRIORITY_HIGH" OR priority="PRIORITY_CRITICAL")',
            '(status="OPENED")',
            '(environment="Production")',
            '(displayName="test case")',
            '(type="EXTERNAL")',
            '(stage="Triage")',
            '(source="Server")',
            f'(assignee="@SOC" OR assignee="{user_id}")',
            '(workflowStatus="IN_PROGRESS")',
            '(sla.expirationStatus="OPEN_SLA")',
            '(alertsSla.expirationStatus="PASSED_DUE")',
            'any(tags.displayName,"malware","phishing")',
            'any(products.displayName,"CrowdStrike")',
            "important=true",
            "incident=false",
        ]
    )
    cases_qs = urlencode(
        {
            "pageSize": 10,
            "expand": "products,tasks,tags,closureDetails,sla,alertsSla",
            "filter": case_filter,
            "orderBy": "createTime desc",
        }
    )

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['LEGACY_SOAR_USERS']}?{soar_users_qs}", json=soar_users_response)
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}?{cases_qs}", json=mock_response)
    args = {
        "page_size": "10",
        "sort_by": "createTime",
        "sort_order": "Desc",
        "priority": "HIGH,CRITICAL",
        "status": "OPENED",
        "environment": "Production",
        "tags": "malware,phishing",
        "display_name": "test case",
        "type": "EXTERNAL",
        "stage": "Triage",
        "source": "Server",
        "assignee": f"@SOC,{user_email}, , not_found_email",
        "products": "CrowdStrike",
        "important": "true",
        "incident": "false",
        "workflow_status": "IN_PROGRESS",
        "sla": "OPEN_SLA",
        "alerts_sla": "PASSED_DUE",
        "filter_logic": "AND",
    }

    result = gcb_case_list_command(mock_client, args)

    assert result.outputs == expected_outputs
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


def test_gcb_case_list_command_advanced_filter_success(mock_client, requests_mock):
    """Success scenario with advanced_filter: individual filters are ignored, raw AIP-160 filter is used."""

    mock_response = util_load_json("test_data/case_list_success_response.json")
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}", json=mock_response)
    args = {"advanced_filter": 'priority="HIGH" AND stage="Triage"', "priority": "LOW", "status": "CLOSED"}

    result = gcb_case_list_command(mock_client, args)

    assert result.raw_response == mock_response
    assert result.outputs is not None


def test_gcb_case_list_command_empty_response(mock_client, requests_mock):
    """Empty response with page_token and create/update time range filters."""

    case_filter = " AND ".join(
        ["createTime>=1777593600000", "createTime<=1780272000000", "updateTime>=1778803200000", "updateTime<=1780617600000"]
    )
    cases_qs = urlencode(
        {
            "pageSize": DEFAULT_PAGE_SIZE,
            "pageToken": "token123",
            "expand": "products,tasks,tags,closureDetails,sla,alertsSla",
            "filter": case_filter,
            "orderBy": f"{DEFAULT_CASE_LIST_SORT_BY} {DEFAULT_CASE_LIST_SORT_ORDER.lower()}",
        }
    )
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASES']}?{cases_qs}", json={})
    args = {
        "page_token": "token123",
        "create_start_time": "2026-05-01T00:00:00Z",
        "create_end_time": "2026-06-01T00:00:00Z",
        "update_start_time": "2026-05-15T00:00:00Z",
        "update_end_time": "2026-06-05T00:00:00Z",
    }

    result = gcb_case_list_command(mock_client, args)

    assert result.raw_response == {}
    assert "No cases found" in result.readable_output


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        (
            {"page_size": "0"},
            MESSAGES["INVALID_INT_RANGE"].format(0, "page_size", 1, MAX_PAGE_SIZE),
        ),
        (
            {"page_size": "-1"},
            MESSAGES["INVALID_INT_RANGE"].format(-1, "page_size", 1, MAX_PAGE_SIZE),
        ),
        (
            {"page_size": "1001"},
            MESSAGES["INVALID_INT_RANGE"].format(1001, "page_size", 1, MAX_PAGE_SIZE),
        ),
        (
            {"sort_order": "Invalid"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("sort_order", ", ".join(VALID_SORT_ORDERS)),
        ),
        (
            {"priority": "INVALID"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("priority", ", ".join(VALID_CASE_PRIORITIES)),
        ),
        (
            {"status": "INVALID_STATUS"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("status", ", ".join(VALID_CASE_STATUSES)),
        ),
        (
            {"type": "INVALID_TYPE"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("type", ", ".join(VALID_CASE_TYPES)),
        ),
        (
            {"workflow_status": "INVALID_WF"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("workflow_status", ", ".join(VALID_CASE_WORKFLOW_STATUSES)),
        ),
        (
            {"sla": "INVALID_SLA"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("sla", ", ".join(VALID_CASE_SLA_STATUSES)),
        ),
        (
            {"alerts_sla": "INVALID_SLA"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("alerts_sla", ", ".join(VALID_CASE_SLA_STATUSES)),
        ),
        (
            {"filter_logic": "XOR"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("filter_logic", ", ".join(VALID_CASE_FILTER_LOGIC)),
        ),
        (
            {"create_start_time": "2026-06-01T00:00:00Z", "create_end_time": "2026-05-01T00:00:00Z"},
            MESSAGES["INVALID_DATE_RANGE"].format("create_start_time", "create_end_time"),
        ),
        (
            {"update_start_time": "2026-06-05T00:00:00Z", "update_end_time": "2026-05-15T00:00:00Z"},
            MESSAGES["INVALID_DATE_RANGE"].format("update_start_time", "update_end_time"),
        ),
    ],
)
def test_gcb_case_list_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_list_command raises ValueError for invalid argument values."""

    with pytest.raises(ValueError) as error:
        gcb_case_list_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_gcb_case_get_command_success(mock_client, requests_mock):
    """Test gcb_case_get_command with a successful API response."""

    test_data = util_load_json("test_data/case_get_response.json")
    expected_hr = util_load_text_data("test_data/case_get_hr.md")

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASE'].format(case_id='1001')}", json=test_data.get("raw_response"))

    result = gcb_case_get_command(mock_client, {"case_id": "1001"})

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == test_data.get("outputs")
    assert result.raw_response == test_data.get("raw_response")
    assert result.readable_output == expected_hr


def test_gcb_case_get_command_api_error(mock_client, requests_mock):
    """Test gcb_case_get_command when API returns a 404 error for a non-existent case."""

    case_id = "999999"
    error_message = "Case not found"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE'].format(case_id=case_id)}",
        json={"error": {"message": error_message}},
        status_code=404,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_get_command(mock_client, {"case_id": case_id})

    assert str(error.value) == MESSAGES["HTTP_ERROR"].format(404, error_message)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "abc"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY)),
        ({"case_id": "-1"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-1", CASE_ID_DISPLAY)),
        ({"case_id": "0"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY)),
    ],
)
def test_gcb_case_get_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_get_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_get_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_gcb_case_get_command_empty_response(mock_client, requests_mock):
    """Test gcb_case_get_command when API returns empty response."""

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASE'].format(case_id='1001')}", json={})

    result = gcb_case_get_command(mock_client, {"case_id": "1001"})

    assert result.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("case information")
    assert result.outputs is None
    assert result.raw_response is None


@pytest.mark.parametrize(
    "args, expected_update_mask_fields",
    [
        (
            {
                "case_id": "1001",
                "display_name": "XSOAR 1 Testing",
                "description": "Test description",
                "important": "true",
                "incident": "false",
            },
            {"displayname", "description", "important", "incident"},
        ),
        (
            {"case_id": "1001", "display_name": "XSOAR 1 Testing"},
            {"displayname"},
        ),
        (
            {"case_id": "1001", "important": "true"},
            {"important"},
        ),
    ],
)
def test_gcb_case_update_command_success(mock_client, requests_mock, args, expected_update_mask_fields):
    """Test gcb_case_update_command: all-fields, partial (display_name only), and boolean-only (important only)."""

    raw_response = util_load_json("test_data/case_update_raw_response.json")
    expected_context = util_load_json("test_data/case_update_context.json")
    expected_hr = util_load_text_data("test_data/case_update_hr.md")

    requests_mock.patch(f"{BASE_URL}{ENDPOINTS['CASE'].format(case_id='1001')}", json=raw_response)

    result = gcb_case_update_command(mock_client, args)

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == expected_context
    assert result.raw_response == raw_response
    assert result.readable_output == expected_hr

    update_mask_value = requests_mock.last_request.qs["updatemask"][0]
    assert set(update_mask_value.split(",")) == expected_update_mask_fields


def test_gcb_case_update_command_api_error(mock_client, requests_mock):
    """Test gcb_case_update_command when API returns a 404 error for a non-existent case."""

    case_id = "999999"
    error_message = "Case not found"
    requests_mock.patch(
        f"{BASE_URL}{ENDPOINTS['CASE'].format(case_id=case_id)}",
        json={"error": {"message": error_message}},
        status_code=404,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_update_command(mock_client, {"case_id": case_id, "display_name": "Test"})

    assert str(error.value) == MESSAGES["HTTP_ERROR"].format(404, error_message)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "abc"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY)),
        ({"case_id": "-1"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-1", CASE_ID_DISPLAY)),
        ({"case_id": "0"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY)),
        (
            {"case_id": "1001"},
            MESSAGES["AT_LEAST_ONE_REQUIRED"].format(", ".join(CASE_UPDATE_ARGS)),
        ),
    ],
)
def test_gcb_case_update_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_update_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_update_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_gcb_case_tag_add_command_success(mock_client, requests_mock):
    """Test gcb_case_tag_add_command with a successful response."""

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['CASES_BULK_ADD_TAG']}", text="", status_code=200)

    expected_outputs = [
        {"caseId": "1001", "recentlyAddedTags": ["malware", "phishing"]},
        {"caseId": "1002", "recentlyAddedTags": ["malware", "phishing"]},
    ]

    result = gcb_case_tag_add_command(mock_client, {"case_ids": "1001,1002", "tags": "malware,phishing"})

    assert result.readable_output == "Tags malware, phishing successfully added to cases 1001, 1002."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


def test_gcb_case_tag_add_command_api_error(mock_client, requests_mock):
    """Test gcb_case_tag_add_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASES_BULK_ADD_TAG']}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_tag_add_command(mock_client, {"case_ids": "1001", "tags": "malware"})

    assert str(error.value) == MESSAGES["HTTP_ERROR"].format(403, PERMISSION_DENIED_TEXT)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_ids")),
        ({"case_ids": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("tags")),
        ({"case_ids": "abc", "tags": "malware"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY)),
        ({"case_ids": "-5", "tags": "malware"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "-5", CASE_ID_DISPLAY)),
        ({"case_ids": "0", "tags": "malware"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "0", CASE_ID_DISPLAY)),
        (
            {"case_ids": "1001,abc,1002", "tags": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY),
        ),
    ],
)
def test_gcb_case_tag_add_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_tag_add_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_tag_add_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_tag_add_command_success(mocker, mock_client):
    """Test main() routes gcb-case-tag-add command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-tag-add")
    mocker.patch.object(demisto, "args", return_value={"case_ids": "1001", "tags": "malware"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_tag_add_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_tag_remove_command_success(mock_client, requests_mock):
    """Test gcb_case_tag_remove_command with a successful response."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASES_REMOVE_TAG'].format(case_id='1001')}",
        text="",
        status_code=200,
    )

    expected_outputs = {"caseId": "1001", "recentlyRemovedTag": "malware"}

    result = gcb_case_tag_remove_command(mock_client, {"case_id": "1001", "tag": "malware"})

    assert result.readable_output == "Tag malware successfully removed from case 1001."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


def test_gcb_case_tag_remove_command_api_error(mock_client, requests_mock):
    """Test gcb_case_tag_remove_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASES_REMOVE_TAG'].format(case_id='1001')}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_tag_remove_command(mock_client, {"case_id": "1001", "tag": "malware"})

    assert str(error.value) == MESSAGES["HTTP_ERROR"].format(403, PERMISSION_DENIED_TEXT)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("tag")),
        (
            {"case_id": "abc,def", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc,def", CASE_ID_DISPLAY),
        ),
        ({"case_id": "-5", "tag": "malware"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY)),
        ({"case_id": "0", "tag": "malware"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY)),
    ],
)
def test_gcb_case_tag_remove_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_tag_remove_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_tag_remove_command(mock_client, args)

    assert str(error.value) == expected_error_message


@pytest.mark.parametrize(
    "input_priority, expected_priority",
    [
        ("info", "INFO"),
        ("Low", "LOW"),
        ("MEDIUM", "MEDIUM"),
        ("High", "HIGH"),
        ("critical", "CRITICAL"),
    ],
)
def test_gcb_case_priority_change_command_success(mock_client, requests_mock, input_priority, expected_priority):
    """Test gcb_case_priority_change_command succeeds for all supported priorities with mixed-case input."""

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['CASES_BULK_CHANGE_PRIORITY']}", text="", status_code=200)

    expected_outputs = [
        {"caseId": "1001", "priority": expected_priority},
        {"caseId": "1002", "priority": expected_priority},
    ]

    result = gcb_case_priority_change_command(mock_client, {"case_ids": "1001,1002", "priority": input_priority})

    assert result.readable_output == f"Priority of cases 1001, 1002 successfully changed to {expected_priority}."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


def test_gcb_case_priority_change_command_api_error(mock_client, requests_mock):
    """Test gcb_case_priority_change_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASES_BULK_CHANGE_PRIORITY']}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_priority_change_command(mock_client, {"case_ids": "1001", "priority": "CRITICAL"})

    assert PERMISSION_DENIED_TEXT in str(error.value)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_ids")),
        ({"case_ids": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("priority")),
        (
            {"case_ids": "abc", "priority": "CRITICAL"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "-5", "priority": "CRITICAL"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "-5", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "0", "priority": "CRITICAL"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "0", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "1001,abc,1002", "priority": "CRITICAL"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "1001", "priority": "INVALID"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("priority", ", ".join(VALID_CASE_PRIORITIES)),
        ),
    ],
)
def test_gcb_case_priority_change_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_priority_change_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_priority_change_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_priority_change_command_success(mocker, mock_client):
    """Test main() routes gcb-case-priority-change command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-priority-change")
    mocker.patch.object(demisto, "args", return_value={"case_ids": "1001", "priority": "CRITICAL"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_priority_change_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_stage_definition_list_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_case_stage_definition_list_command should return display names."""

    base_name = "projects/google-001/locations/us/instances/00000000-0000-0000-0000-000000000001/caseStageDefinitions"
    mock_response = {
        "caseStageDefinitions": [
            {"name": f"{base_name}/1", "displayName": "Triage", "order": 1},
            {"name": f"{base_name}/2", "displayName": "Assessment", "order": 2},
            {"name": f"{base_name}/3", "displayName": "Investigation", "order": 3},
        ]
    }

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_STAGE_DEFINITIONS']}?pageSize={MAX_PAGE_SIZE}&orderBy=order",
        json=mock_response,
    )

    result = gcb_case_stage_definition_list_command(mock_client, {})

    assert result.outputs_prefix == "GoogleSecOps.CaseStageDefinition"
    assert result.outputs == ["Triage", "Assessment", "Investigation"]
    assert "Triage, Assessment, Investigation" in result.readable_output


def test_main_gcb_case_stage_definition_list(mocker, mock_client):
    """Test main() routes gcb-case-stage-definition-list command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-stage-definition-list")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_stage_definition_list_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


@pytest.mark.parametrize("input_stage", ["triage", "Incident", "Investigation", "Assessment"])
def test_gcb_case_stage_change_command_success(mock_client, requests_mock, input_stage):
    """Test gcb_case_stage_change_command succeeds for stages with mixed-case input."""

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['CASES_BULK_CHANGE_STAGE']}", text="", status_code=200)

    expected_outputs = [
        {"caseId": "1001", "stage": input_stage},
        {"caseId": "1002", "stage": input_stage},
    ]

    result = gcb_case_stage_change_command(mock_client, {"case_ids": "1001,1002", "stage": input_stage})

    assert result.readable_output == f"Stage of cases 1001, 1002 successfully changed to {input_stage}."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


def test_gcb_case_stage_change_command_api_error(mock_client, requests_mock):
    """Test gcb_case_stage_change_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASES_BULK_CHANGE_STAGE']}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_stage_change_command(mock_client, {"case_ids": "1001", "stage": "Investigation"})

    assert PERMISSION_DENIED_TEXT in str(error.value)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_ids")),
        ({"case_ids": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("stage")),
        ({"case_ids": "abc", "stage": "Triage"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY)),
        ({"case_ids": "-5", "stage": "Triage"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "-5", CASE_ID_DISPLAY)),
        ({"case_ids": "0", "stage": "Triage"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "0", CASE_ID_DISPLAY)),
        (
            {"case_ids": "1001,abc,1002", "stage": "Triage"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY),
        ),
    ],
)
def test_gcb_case_stage_change_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_stage_change_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_stage_change_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_stage_change_command_success(mocker, mock_client):
    """Test main() routes gcb-case-stage-change command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-stage-change")
    mocker.patch.object(demisto, "args", return_value={"case_ids": "1001", "stage": "Investigation"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_stage_change_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_reopen_command_success(mock_client, requests_mock):
    """Test gcb_case_reopen_command succeeds for valid case IDs."""

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['CASES_BULK_REOPEN']}", text="", status_code=200)

    expected_outputs = [
        {"caseId": "1001", "status": "OPENED"},
        {"caseId": "1002", "status": "OPENED"},
    ]

    result = gcb_case_reopen_command(mock_client, {"case_ids": "1001,1002", "reopen_comment": "Reopening due to new evidence."})

    assert result.readable_output == "Cases 1001, 1002 successfully reopened."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


def test_gcb_case_reopen_command_api_error(mock_client, requests_mock):
    """Test gcb_case_reopen_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASES_BULK_REOPEN']}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_reopen_command(mock_client, {"case_ids": "1001", "reopen_comment": "Reopening due to new evidence."})

    assert PERMISSION_DENIED_TEXT in str(error.value)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_ids")),
        ({"case_ids": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("reopen_comment")),
        (
            {"case_ids": "abc", "reopen_comment": "test"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "-5", "reopen_comment": "test"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "-5", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "0", "reopen_comment": "test"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "0", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "1001,abc,1002", "reopen_comment": "test"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY),
        ),
    ],
)
def test_gcb_case_reopen_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_reopen_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_reopen_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_reopen_command_success(mocker, mock_client):
    """Test main() routes gcb-case-reopen command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-reopen")
    mocker.patch.object(demisto, "args", return_value={"case_ids": "1001", "reopen_comment": "Reopening due to new evidence."})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_reopen_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_close_definition_list_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_case_close_definition_list_command should return case close definitions."""

    mock_response = util_load_json("test_data/case_close_definitions.json")
    expected_hr = util_load_text_data("test_data/case_close_definitions_hr.md")

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_CLOSE_DEFINITIONS']}?pageSize={MAX_PAGE_SIZE}&orderBy=closeReason",
        json=mock_response,
    )

    result = gcb_case_close_definition_list_command(mock_client, {})

    assert result.outputs_prefix == "GoogleSecOps.CaseCloseDefinition"
    assert result.outputs == mock_response["caseCloseDefinitions"]
    assert result.readable_output == expected_hr


def test_gcb_case_close_definition_list_command_empty_response(mock_client, requests_mock):
    """When empty response is received, gcb_case_close_definition_list_command should return appropriate message."""

    mock_response = {"caseCloseDefinitions": []}

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_CLOSE_DEFINITIONS']}?pageSize=1000&orderBy=closeReason",
        json=mock_response,
    )

    result = gcb_case_close_definition_list_command(mock_client, {})

    assert result.outputs_prefix == "GoogleSecOps.CaseCloseDefinition"
    assert result.outputs == []
    assert "No case close definitions found" in result.readable_output


def test_main_gcb_case_close_definition_list(mocker, mock_client):
    """Test main() routes gcb-case-close-definition-list command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-close-definition-list")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_close_definition_list_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_close_command_success(mock_client, requests_mock):
    """Test gcb_case_close_command succeeds for valid case IDs and close reason."""

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['CASES_BULK_CLOSE']}", text="", status_code=200)

    expected_outputs = util_load_json("test_data/case_close_success.json")

    result = gcb_case_close_command(
        mock_client,
        {
            "case_ids": "1001,1002",
            "close_reason": "NOT_MALICIOUS",
            "root_cause": "False positive",
            "close_comment": "Test comment",
        },
    )

    assert result.readable_output == "Cases 1001, 1002 successfully closed with reason NOT_MALICIOUS."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_ids")),
        ({"case_ids": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("close_reason")),
        ({"case_ids": "1001", "close_reason": "NOT_MALICIOUS"}, MESSAGES["REQUIRED_ARGUMENT"].format("root_cause")),
        (
            {"case_ids": "abc", "close_reason": "NOT_MALICIOUS", "root_cause": "test"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "-5", "close_reason": "NOT_MALICIOUS", "root_cause": "test"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "-5", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "0", "close_reason": "NOT_MALICIOUS", "root_cause": "test"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "0", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "1001,abc,1002", "close_reason": "NOT_MALICIOUS", "root_cause": "test"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "1001", "close_reason": "INVALID_REASON", "root_cause": "test"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("close_reason", ", ".join(VALID_CASE_CLOSE_REASONS)),
        ),
    ],
)
def test_gcb_case_close_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_close_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_close_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_close_command_success(mocker, mock_client):
    """Test main() routes gcb-case-close command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-close")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "case_ids": "1001",
            "close_reason": "NOT_MALICIOUS",
            "root_cause": "False positive",
            "close_comment": "Test comment",
        },
    )
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_close_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_assign_command_success_email(mock_client, requests_mock):
    """Test gcb_case_assign_command with an email address resolved to a SOAR user ID."""
    user_email = "active.user@example.com"
    user_id = "00000000-0000-0000-0000-000000000111"
    args = {"case_ids": "1001, 1002", "assignee": user_email}
    expected_outputs = [{"caseId": "1001", "assignee": user_id}, {"caseId": "1002", "assignee": user_id}]

    soar_users_response = util_load_json("test_data/legacy_soar_users_response.json")
    soar_users_qs = urlencode({"pageSize": 1, "filter": f"(email='{user_email}') AND accountState='ACTIVE'"})
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['LEGACY_SOAR_USERS']}?{soar_users_qs}", json=soar_users_response)
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['CASES_BULK_ASSIGN']}", json={}, status_code=200)

    result = gcb_case_assign_command(mock_client, args)

    assert result.readable_output == f"Cases 1001, 1002 successfully assigned to {user_email}."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


def test_gcb_case_assign_command_success_soc_role(mock_client, requests_mock):
    """Test gcb_case_assign_command with a SOC role passed through unchanged."""

    soc_role = "@SOC"
    args = {"case_ids": "1001, 1002", "assignee": soc_role}
    expected_outputs = [{"caseId": "1001", "assignee": soc_role}, {"caseId": "1002", "assignee": soc_role}]

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['CASES_BULK_ASSIGN']}", json={}, status_code=200)

    result = gcb_case_assign_command(mock_client, args)

    assert result.readable_output == f"Cases 1001, 1002 successfully assigned to {soc_role}."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


@pytest.mark.parametrize("assignee", [("unknown@example.com"), ("nodisplay.user@example.com")])
def test_gcb_case_assign_command_unresolved_email(mock_client, requests_mock, assignee):
    """Test gcb_case_assign_command raises ValueError for not found and no-display-name users."""

    soar_users_response = util_load_json("test_data/legacy_soar_users_response.json")
    soar_users_qs = urlencode({"pageSize": 1, "filter": f"(email='{assignee}') AND accountState='ACTIVE'"})
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['LEGACY_SOAR_USERS']}?{soar_users_qs}", json=soar_users_response)

    with pytest.raises(ValueError) as error:
        gcb_case_assign_command(mock_client, {"case_ids": "1001", "assignee": assignee})

    assert str(error.value) == MESSAGES["USER_NOT_FOUND"].format(assignee)


def test_gcb_case_assign_command_inactive_user(mock_client, requests_mock):
    """Test gcb_case_assign_command raises ValueError for inactive users filtered by the API."""

    assignee = "inactive.user@example.com"
    soar_users_qs = urlencode({"pageSize": 1, "filter": f"(email='{assignee}') AND accountState='ACTIVE'"})
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['LEGACY_SOAR_USERS']}?{soar_users_qs}", json={"legacySoarUsers": []})

    with pytest.raises(ValueError) as error:
        gcb_case_assign_command(mock_client, {"case_ids": "1001", "assignee": assignee})

    assert str(error.value) == MESSAGES["USER_NOT_FOUND"].format(assignee)


def test_gcb_case_assign_command_api_error(mock_client, requests_mock):
    """Test gcb_case_assign_command when API returns a permission denied error."""
    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASES_BULK_ASSIGN']}", json={"error": {"message": PERMISSION_DENIED_TEXT}}, status_code=403
    )

    with pytest.raises(ValueError) as error:
        gcb_case_assign_command(mock_client, {"case_ids": "1001", "assignee": "@role"})

    assert str(error.value) == MESSAGES["HTTP_ERROR"].format(403, PERMISSION_DENIED_TEXT)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_ids")),
        ({"case_ids": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("assignee")),
        (
            {"case_ids": "abc", "assignee": "user_email"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "-5", "assignee": "user_email"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "-5", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "0", "assignee": "user_email"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "0", CASE_ID_DISPLAY),
        ),
        (
            {"case_ids": "1001,abc", "assignee": "user_email"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_ids", "abc", CASE_ID_DISPLAY),
        ),
    ],
)
def test_gcb_case_assign_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_assign_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_assign_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_gcb_case_comment_list_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_case_comment_list_command should return case comments."""

    mock_response = util_load_json("test_data/case_comment_list_success_response.json")
    outputs = util_load_json("test_data/case_comment_list_context.json")
    expected_hr = util_load_text_data("test_data/case_comment_list_hr.md")

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_COMMENTS'].format(case_id='1001')}?pageSize=50&orderBy=createTime%20desc",
        json=mock_response,
    )

    result = gcb_case_comment_list_command(mock_client, {"case_id": "1001"})

    assert result.outputs == outputs
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


def test_gcb_case_comment_list_command_empty_response(mock_client, requests_mock):
    """When empty response is received, gcb_case_comment_list_command should return appropriate message."""

    mock_response = {}

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_COMMENTS'].format(case_id='1001')}?pageSize=50&orderBy=createTime%20desc",
        json=mock_response,
    )

    result = gcb_case_comment_list_command(mock_client, {"case_id": "1001"})

    assert result.raw_response == {}
    assert "No case comments found" in result.readable_output


def test_gcb_case_comment_list_command_with_pagination(mock_client, requests_mock):
    """Test gcb_case_comment_list_command with pagination parameters."""

    mock_response = util_load_json("test_data/case_comment_list_success_response.json")

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_COMMENTS'].format(case_id='1001')}?pageSize=10&pageToken=token123&orderBy=updateTime%20asc",
        json=mock_response,
    )

    result = gcb_case_comment_list_command(
        mock_client,
        {"case_id": "1001", "page_size": "10", "page_token": "token123", "sort_by": "updateTime", "sort_order": "Asc"},
    )

    assert result.raw_response == mock_response
    assert len(result.outputs) == 2


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "abc"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY)),
        ({"case_id": "-5"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY)),
        ({"case_id": "0"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY)),
        (
            {"case_id": "1001", "page_size": "-1"},
            MESSAGES["INVALID_INT_RANGE"].format(-1, "page_size", 1, 1000),
        ),
        (
            {"case_id": "1001", "page_size": "1001"},
            MESSAGES["INVALID_INT_RANGE"].format(1001, "page_size", 1, 1000),
        ),
        (
            {"case_id": "1001", "sort_order": "Invalid"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("sort_order", "Asc, Desc"),
        ),
        (
            {"case_id": "1001", "sort_order": "ascending"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("sort_order", "Asc, Desc"),
        ),
    ],
)
def test_gcb_case_comment_list_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_comment_list_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_comment_list_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_gcb_case_comment_create_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_case_comment_create_command should return created comment details."""

    mock_response = util_load_json("test_data/case_comment_create_success_response.json")
    outputs = util_load_json("test_data/case_comment_create_context.json")
    expected_hr = util_load_text_data("test_data/case_comment_create_hr.md")

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_COMMENTS'].format(case_id='1001')}",
        json=mock_response,
    )

    result = gcb_case_comment_create_command(
        mock_client, {"case_id": "1001", "comment": "Investigated the outbound traffic. Confirmed malicious C2 communication."}
    )

    assert result.outputs_key_field == "name"
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["CaseComment"]
    assert result.outputs == outputs
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "abc"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY)),
        ({"case_id": "-5"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY)),
        ({"case_id": "0"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY)),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("comment")),
        ({"case_id": "1001", "comment": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("comment")),
    ],
)
def test_gcb_case_comment_create_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_comment_create_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_comment_create_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_gcb_case_sla_pause_command_success(mock_client, requests_mock):
    """Test gcb_case_sla_pause_command succeeds for a valid case ID."""

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['CASE_SLA_PAUSE'].format(case_id='1001')}", text="", status_code=200)

    expected_outputs = {"caseId": "1001", "slaStatus": "PAUSED"}

    result = gcb_case_sla_pause_command(
        mock_client, {"case_id": "1001", "message": "Pausing SLA pending additional investigation."}
    )

    assert result.readable_output == "SLA timer for case 1001 successfully paused."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


def test_gcb_case_sla_pause_command_success_without_message(mock_client, requests_mock):
    """Test gcb_case_sla_pause_command succeeds when message is not provided."""

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['CASE_SLA_PAUSE'].format(case_id='1001')}", text="", status_code=200)

    result = gcb_case_sla_pause_command(mock_client, {"case_id": "1001"})

    assert result.readable_output == "SLA timer for case 1001 successfully paused."
    assert result.outputs == {"caseId": "1001", "slaStatus": "PAUSED"}


def test_gcb_case_sla_pause_command_api_error(mock_client, requests_mock):
    """Test gcb_case_sla_pause_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_SLA_PAUSE'].format(case_id='1001')}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_sla_pause_command(mock_client, {"case_id": "1001", "message": "Pausing SLA pending additional investigation."})

    assert PERMISSION_DENIED_TEXT in str(error.value)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "abc"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY)),
        ({"case_id": "-5"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY)),
        ({"case_id": "0"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY)),
    ],
)
def test_gcb_case_sla_pause_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_sla_pause_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_sla_pause_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_sla_pause_command_success(mocker, mock_client):
    """Test main() routes gcb-case-sla-pause command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-sla-pause")
    mocker.patch.object(
        demisto, "args", return_value={"case_id": "1001", "message": "Pausing SLA pending additional investigation."}
    )
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_sla_pause_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_sla_resume_command_success(mock_client, requests_mock):
    """Test gcb_case_sla_resume_command succeeds for a valid case ID."""

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['CASE_SLA_RESUME'].format(case_id='1001')}", text="", status_code=200)

    expected_outputs = {"caseId": "1001", "slaStatus": "SLA_EXPIRATION_STATUS_UNSPECIFIED"}

    result = gcb_case_sla_resume_command(mock_client, {"case_id": "1001"})

    assert result.readable_output == "SLA timer for case 1001 successfully resumed."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Case"]
    assert result.outputs_key_field == "caseId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


def test_gcb_case_sla_resume_command_api_error(mock_client, requests_mock):
    """Test gcb_case_sla_resume_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_SLA_RESUME'].format(case_id='1001')}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_sla_resume_command(mock_client, {"case_id": "1001"})

    assert PERMISSION_DENIED_TEXT in str(error.value)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "abc"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY)),
        ({"case_id": "-5"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY)),
        ({"case_id": "0"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY)),
    ],
)
def test_gcb_case_sla_resume_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_sla_resume_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_sla_resume_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_sla_resume_command_success(mocker, mock_client):
    """Test main() routes gcb-case-sla-resume command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-sla-resume")
    mocker.patch.object(demisto, "args", return_value={"case_id": "1001"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_sla_resume_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_alert_list_command_success(mock_client, requests_mock):
    """Success with all individual filter args."""

    raw_response = util_load_json("test_data/case_alert_list_raw_response.json")
    expected_context = util_load_json("test_data/case_alert_list_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_list_hr.md")

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASE_ALERTS'].format(case_id='1001')}", json=raw_response)

    result = gcb_case_alert_list_command(
        mock_client,
        {
            "case_id": "1001",
            "priority": "HIGH",
            "status": "OPEN",
            "product": "Test Product",
            "vendor": "Test Vendor",
            "environment": "Default Environment",
            "source_system_name": "Test Source System",
            "tag": "demo_1",
            "display_name": "TEST ALERT",
            "manual": "false",
            "filter_logic": "AND",
            "sort_by": "priority",
            "sort_order": "Asc",
            "create_start_time": "1 week",
            "create_end_time": "3 days",
            "update_start_time": "2 weeks",
            "update_end_time": "1 day",
            "page_size": "10",
        },
    )

    assert result.outputs == expected_context
    assert result.raw_response == raw_response
    assert result.readable_output == expected_hr


def test_gcb_case_alert_list_command_advanced_filter_success(mock_client, requests_mock):
    """Success with advanced_filter: individual filters ignored, raw filter used as-is."""

    raw_response = util_load_json("test_data/case_alert_list_raw_response.json")
    expected_context = util_load_json("test_data/case_alert_list_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_list_hr.md")

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASE_ALERTS'].format(case_id='1001')}", json=raw_response)

    advanced_filter = "priority='HIGH' AND status='OPEN'"
    result = gcb_case_alert_list_command(
        mock_client,
        {
            "case_id": "1001",
            "advanced_filter": advanced_filter,
            "priority": "LOW",
        },
    )

    assert result.raw_response == raw_response
    assert result.outputs == expected_context
    assert result.readable_output == expected_hr


def test_gcb_case_alert_list_command_empty_response(mock_client, requests_mock):
    """Empty response with page_token returns no-records message."""

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASE_ALERTS'].format(case_id='1001')}", json={})

    result = gcb_case_alert_list_command(mock_client, {"case_id": "1001", "page_token": "token123", "page_size": "5"})

    assert result.raw_response == {}
    assert MESSAGES["NO_RECORDS_FOUND"].format("case alerts") in result.readable_output


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "abc"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", "Case ID")),
        ({"case_id": "-1"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-1", "Case ID")),
        (
            {"case_id": "1001", "page_size": "0"},
            MESSAGES["INVALID_INT_RANGE"].format(0, "page_size", 1, MAX_PAGE_SIZE),
        ),
        (
            {"case_id": "1001", "page_size": "1001"},
            MESSAGES["INVALID_INT_RANGE"].format(1001, "page_size", 1, MAX_PAGE_SIZE),
        ),
        (
            {"case_id": "1001", "sort_order": "INVALID"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("sort_order", ", ".join(VALID_SORT_ORDERS)),
        ),
        (
            {"case_id": "1001", "priority": "INVALID_PRIORITY"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("priority", ", ".join(VALID_CASE_ALERT_PRIORITIES)),
        ),
        (
            {"case_id": "1001", "status": "INVALID_STATUS"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("status", ", ".join(VALID_CASE_ALERT_STATUSES)),
        ),
        (
            {"case_id": "1001", "create_start_time": "2026-05-20", "create_end_time": "2026-05-10"},
            MESSAGES["INVALID_DATE_RANGE"].format("create_start_time", "create_end_time"),
        ),
        (
            {"case_id": "1001", "update_start_time": "2026-06-05T00:00:00Z", "update_end_time": "2026-05-15T00:00:00Z"},
            MESSAGES["INVALID_DATE_RANGE"].format("update_start_time", "update_end_time"),
        ),
        (
            {"case_id": "1001", "filter_logic": "XOR"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("filter_logic", ", ".join(VALID_CASE_FILTER_LOGIC)),
        ),
    ],
)
def test_gcb_case_alert_list_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_list_command raises ValueError for invalid argument values."""

    with pytest.raises((ValueError, SystemExit)) as error:
        gcb_case_alert_list_command(mock_client, args)

    assert expected_error_message in str(error.value)


def test_gcb_case_alert_get_command_success(mock_client, requests_mock):
    """Test gcb_case_alert_get_command with a successful API response."""

    raw_response = util_load_json("test_data/case_alert_get_raw_response.json")
    expected_context = util_load_json("test_data/case_alert_get_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_get_hr.md")

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT'].format(case_id='1001', alert_id='1000001')}",
        json=raw_response,
    )

    result = gcb_case_alert_get_command(mock_client, {"case_id": "1001", "alert_id": "1000001"})

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["CaseAlert"]
    assert result.outputs_key_field == "alertId"
    assert result.outputs == expected_context
    assert result.raw_response == raw_response
    assert result.readable_output == expected_hr


def test_gcb_case_alert_get_command_api_error(mock_client, requests_mock):
    """Test gcb_case_alert_get_command when API returns a 404 error for a non-existent alert."""

    error_message = "Case alert not found"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT'].format(case_id='1001', alert_id='999999')}",
        json={"error": {"message": error_message}},
        status_code=404,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_alert_get_command(mock_client, {"case_id": "1001", "alert_id": "999999"})

    assert str(error.value) == MESSAGES["HTTP_ERROR"].format(404, error_message)


def test_gcb_case_alert_get_command_empty_response(mock_client, requests_mock):
    """Test gcb_case_alert_get_command when API returns empty response."""

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT'].format(case_id='1001', alert_id='1000001')}",
        json={},
    )

    result = gcb_case_alert_get_command(mock_client, {"case_id": "1001", "alert_id": "1000001"})

    assert result.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("case alert information")


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "1001", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "abc", "alert_id": "1000001"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        ({"case_id": "-1", "alert_id": "1000001"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-1", CASE_ID_DISPLAY)),
        ({"case_id": "0", "alert_id": "1000001"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY)),
        (
            {"case_id": "1001", "alert_id": "abc"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        ({"case_id": "1001", "alert_id": "-1"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-1", ALERT_ID_DISPLAY)),
        ({"case_id": "1001", "alert_id": "0"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "0", ALERT_ID_DISPLAY)),
    ],
)
def test_gcb_case_alert_get_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_get_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_get_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_get_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-get command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-get")
    mocker.patch.object(demisto, "args", return_value={"case_id": "1001", "alert_id": "1000001"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_get_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


@pytest.mark.parametrize(
    "args, expected_update_mask_fields",
    [
        (
            {
                "case_id": "1001",
                "alert_id": "1000001",
                "status": "CLOSE",
                "priority": "HIGH",
                "close_reason": "NOT_MALICIOUS",
                "close_comment": "Reviewed and confirmed as false positive.",
                "root_cause": "Misconfigured DLP policy",
            },
            {"status", "closureDetails", "priority"},
        ),
        (
            {"case_id": "1001", "alert_id": "1000001", "priority": "HIGH"},
            {"priority"},
        ),
        (
            {
                "case_id": "1001",
                "alert_id": "1000001",
                "status": "CLOSE",
                "close_reason": "MALICIOUS",
                "root_cause": "Confirmed malicious activity",
            },
            {"status", "closureDetails"},
        ),
    ],
)
def test_gcb_case_alert_update_command_success(mock_client, requests_mock, args, expected_update_mask_fields):
    """Test gcb_case_alert_update_command: full-fields, priority-only, and close-status cases."""

    raw_response = util_load_json("test_data/case_alert_update_raw_response.json")
    expected_context = util_load_json("test_data/case_alert_update_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_update_hr.md")

    requests_mock.patch(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT'].format(case_id='1001', alert_id='1000001')}",
        json=raw_response,
    )

    result = gcb_case_alert_update_command(mock_client, args)

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["CaseAlert"]
    assert result.outputs_key_field == "alertId"
    assert result.outputs == expected_context
    assert result.raw_response == raw_response
    assert result.readable_output == expected_hr

    update_mask_value = requests_mock.last_request.qs["updatemask"][0]
    assert set(update_mask_value.split(",")) == {f.lower() for f in expected_update_mask_fields}


def test_gcb_case_alert_update_command_api_error(mock_client, requests_mock):
    """Test gcb_case_alert_update_command when API returns a 404 error for a non-existent alert."""

    error_message = "Case alert not found"
    requests_mock.patch(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT'].format(case_id='1001', alert_id='999999')}",
        json={"error": {"message": error_message}},
        status_code=404,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_alert_update_command(mock_client, {"case_id": "1001", "alert_id": "999999", "priority": "HIGH"})

    assert str(error.value) == MESSAGES["HTTP_ERROR"].format(404, error_message)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "1001", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "abc", "alert_id": "1000001"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-1", "alert_id": "1000001"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-1", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "abc"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "-1"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-1", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "1000001"},
            MESSAGES["AT_LEAST_ONE_REQUIRED"].format(", ".join(CASE_ALERT_UPDATE_ARGS)),
        ),
        (
            {"case_id": "1001", "alert_id": "1000001", "status": "INVALID"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("status", ", ".join(VALID_CASE_ALERT_STATUSES)),
        ),
        (
            {"case_id": "1001", "alert_id": "1000001", "priority": "INVALID"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("priority", ", ".join(VALID_CASE_ALERT_PRIORITIES)),
        ),
        (
            {"case_id": "1001", "alert_id": "1000001", "status": "CLOSE"},
            "close_reason is required when status is CLOSE.",
        ),
        (
            {"case_id": "1001", "alert_id": "1000001", "status": "CLOSE", "close_reason": "MALICIOUS"},
            "root_cause is required when status is CLOSE.",
        ),
        (
            {"case_id": "1001", "alert_id": "1000001", "status": "CLOSE", "close_reason": "INVALID", "root_cause": "some cause"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("close_reason", ", ".join(VALID_CASE_ALERT_CLOSE_REASONS)),
        ),
    ],
)
def test_gcb_case_alert_update_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_update_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_update_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_gcb_case_alert_tag_add_command_success(mock_client, requests_mock):
    """Test gcb_case_alert_tag_add_command with a successful response."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_ADD_TAG'].format(case_id='1001', alert_id='1142656')}",
        text="",
        status_code=200,
    )

    expected_outputs = {"alertId": "1142656", "caseId": 1001, "recentlyAddedTag": "insider-threat"}

    result = gcb_case_alert_tag_add_command(mock_client, {"case_id": "1001", "alert_id": "1142656", "tag": "insider-threat"})

    assert result.readable_output == "Tag insider-threat successfully added to alert 1142656."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["CaseAlert"]
    assert result.outputs_key_field == "alertId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


def test_gcb_case_alert_tag_add_command_api_error(mock_client, requests_mock):
    """Test gcb_case_alert_tag_add_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_ADD_TAG'].format(case_id='1001', alert_id='1142656')}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_alert_tag_add_command(mock_client, {"case_id": "1001", "alert_id": "1142656", "tag": "insider-threat"})

    assert str(error.value) == MESSAGES["HTTP_ERROR"].format(403, PERMISSION_DENIED_TEXT)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "1001", "alert_id": "1142656"}, MESSAGES["REQUIRED_ARGUMENT"].format("tag")),
        (
            {"case_id": "abc", "alert_id": "1142656", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_id": "1142656", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "0", "alert_id": "1142656", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "abc", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "-5", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-5", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "0", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "0", ALERT_ID_DISPLAY),
        ),
    ],
)
def test_gcb_case_alert_tag_add_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_tag_add_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_tag_add_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_tag_add_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-tag-add command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-tag-add")
    mocker.patch.object(demisto, "args", return_value={"case_id": "1001", "alert_id": "1142656", "tag": "insider-threat"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_tag_add_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_alert_tag_remove_command_success(mock_client, requests_mock):
    """Test gcb_case_alert_tag_remove_command with a successful response."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_REMOVE_TAG'].format(case_id='1001', alert_id='1142656')}",
        text="",
        status_code=200,
    )

    expected_outputs = {"alertId": "1142656", "caseId": 1001, "recentlyRemovedTag": "insider-threat"}

    result = gcb_case_alert_tag_remove_command(mock_client, {"case_id": "1001", "alert_id": "1142656", "tag": "insider-threat"})

    assert result.readable_output == "Tag insider-threat successfully removed from alert 1142656."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["CaseAlert"]
    assert result.outputs_key_field == "alertId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


def test_gcb_case_alert_tag_remove_command_api_error(mock_client, requests_mock):
    """Test gcb_case_alert_tag_remove_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_REMOVE_TAG'].format(case_id='1001', alert_id='1142656')}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_alert_tag_remove_command(mock_client, {"case_id": "1001", "alert_id": "1142656", "tag": "insider-threat"})

    assert str(error.value) == MESSAGES["HTTP_ERROR"].format(403, PERMISSION_DENIED_TEXT)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "1001", "alert_id": "1142656"}, MESSAGES["REQUIRED_ARGUMENT"].format("tag")),
        (
            {"case_id": "abc", "alert_id": "1142656", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_id": "1142656", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "0", "alert_id": "1142656", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "abc", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "-5", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-5", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "0", "tag": "malware"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "0", ALERT_ID_DISPLAY),
        ),
    ],
)
def test_gcb_case_alert_tag_remove_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_tag_remove_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_tag_remove_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_tag_remove_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-tag-remove command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-tag-remove")
    mocker.patch.object(demisto, "args", return_value={"case_id": "1001", "alert_id": "1142656", "tag": "insider-threat"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_tag_remove_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_alert_move_command_success(mock_client, requests_mock):
    """Test gcb_case_alert_move_command with a successful response."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_MOVE'].format(case_id='1001', alert_id='1142656')}",
        json={"newCaseId": 1005, "valid": True},
        status_code=200,
    )

    result = gcb_case_alert_move_command(mock_client, {"case_id": "1001", "alert_id": "1142656", "destination_case_id": "1005"})

    assert result.readable_output == "Successfully moved Alert `1142656` to Case `1005`."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["CaseAlert"]
    assert result.outputs_key_field == "alertId"
    assert result.outputs == {"alertId": "1142656", "caseId": 1005}
    assert result.raw_response == {"newCaseId": 1005, "valid": True}


def test_gcb_case_alert_move_command_api_error(mock_client, requests_mock):
    """Test gcb_case_alert_move_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_MOVE'].format(case_id='1001', alert_id='1142656')}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_alert_move_command(mock_client, {"case_id": "1001", "alert_id": "1142656", "destination_case_id": "1005"})

    assert str(error.value) == MESSAGES["HTTP_ERROR"].format(403, PERMISSION_DENIED_TEXT)


def test_gcb_case_alert_move_command_errors_in_response(mock_client, requests_mock):
    """Test gcb_case_alert_move_command when API response contains errors array."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_MOVE'].format(case_id='1001', alert_id='1142656')}",
        json={"newCaseId": 1005, "errors": ["Cannot move alert to a new case to a different environment"]},
        status_code=200,
    )

    with pytest.raises(Exception) as error:
        gcb_case_alert_move_command(mock_client, {"case_id": "1001", "alert_id": "1142656", "destination_case_id": "1005"})

    assert "Cannot move alert to a new case to a different environment" in str(error.value)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "1001", "alert_id": "1142656"}, MESSAGES["REQUIRED_ARGUMENT"].format("destination_case_id")),
        (
            {"case_id": "abc", "alert_id": "1142656", "destination_case_id": "1005"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_id": "1142656", "destination_case_id": "1005"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "0", "alert_id": "1142656", "destination_case_id": "1005"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "abc", "destination_case_id": "1005"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "-5", "destination_case_id": "1005"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-5", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "0", "destination_case_id": "1005"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "0", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "1142656", "destination_case_id": "abc"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("destination_case_id", "abc", "Destination Case ID"),
        ),
        (
            {"case_id": "1001", "alert_id": "1142656", "destination_case_id": "-5"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("destination_case_id", "-5", "Destination Case ID"),
        ),
        (
            {"case_id": "1001", "alert_id": "1142656", "destination_case_id": "0"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("destination_case_id", "0", "Destination Case ID"),
        ),
    ],
)
def test_gcb_case_alert_move_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_move_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_move_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_move_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-move command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-move")
    mocker.patch.object(demisto, "args", return_value={"case_id": "1001", "alert_id": "1142656", "destination_case_id": "1005"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_move_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


# --- gcb-case-alert-sla-pause ---


def test_gcb_case_alert_sla_pause_command_success(mock_client, requests_mock):
    """Test gcb_case_alert_sla_pause_command succeeds with a message."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_SLA_PAUSE'].format(case_id='1001', alert_id='1142656')}",
        text="",
        status_code=200,
    )

    result = gcb_case_alert_sla_pause_command(
        mock_client,
        {"case_id": "1001", "alert_id": "1142656", "message": "Pausing SLA pending additional investigation."},
    )

    assert result.readable_output == "SLA timer for alert 1142656 successfully paused."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["CaseAlert"]
    assert result.outputs_key_field == "alertId"
    assert result.outputs == {"alertId": "1142656", "caseId": 1001, "slaExpirationStatus": "PAUSED"}
    assert result.raw_response == result.outputs


def test_gcb_case_alert_sla_pause_command_success_without_message(mock_client, requests_mock):
    """Test gcb_case_alert_sla_pause_command succeeds when message is not provided."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_SLA_PAUSE'].format(case_id='1001', alert_id='1142656')}",
        text="",
        status_code=200,
    )

    result = gcb_case_alert_sla_pause_command(mock_client, {"case_id": "1001", "alert_id": "1142656"})

    assert result.readable_output == "SLA timer for alert 1142656 successfully paused."
    assert result.outputs == {"alertId": "1142656", "caseId": 1001, "slaExpirationStatus": "PAUSED"}


def test_gcb_case_alert_sla_pause_command_api_error(mock_client, requests_mock):
    """Test gcb_case_alert_sla_pause_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_SLA_PAUSE'].format(case_id='1001', alert_id='1142656')}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_alert_sla_pause_command(mock_client, {"case_id": "1001", "alert_id": "1142656"})

    assert PERMISSION_DENIED_TEXT in str(error.value)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "1001", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "abc", "alert_id": "1142656"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_id": "1142656"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "0", "alert_id": "1142656"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "abc"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "-5"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-5", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "0"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "0", ALERT_ID_DISPLAY),
        ),
    ],
)
def test_gcb_case_alert_sla_pause_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_sla_pause_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_sla_pause_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_sla_pause_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-sla-pause command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-sla-pause")
    mocker.patch.object(demisto, "args", return_value={"case_id": "1001", "alert_id": "1142656", "message": "Pausing SLA."})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_sla_pause_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


# --- gcb-case-alert-sla-resume ---


def test_gcb_case_alert_sla_resume_command_success(mock_client, requests_mock):
    """Test gcb_case_alert_sla_resume_command succeeds for valid case and alert IDs."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_SLA_RESUME'].format(case_id='1001', alert_id='1142656')}",
        text="",
        status_code=200,
    )

    expected_outputs = {"alertId": "1142656", "caseId": 1001, "slaExpirationStatus": "SLA_EXPIRATION_STATUS_UNSPECIFIED"}

    result = gcb_case_alert_sla_resume_command(mock_client, {"case_id": "1001", "alert_id": "1142656"})

    assert result.readable_output == "SLA timer for alert 1142656 successfully resumed."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["CaseAlert"]
    assert result.outputs_key_field == "alertId"
    assert result.outputs == expected_outputs
    assert result.raw_response == expected_outputs


def test_gcb_case_alert_sla_resume_command_api_error(mock_client, requests_mock):
    """Test gcb_case_alert_sla_resume_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_SLA_RESUME'].format(case_id='1001', alert_id='1142656')}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_alert_sla_resume_command(mock_client, {"case_id": "1001", "alert_id": "1142656"})

    assert PERMISSION_DENIED_TEXT in str(error.value)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "1001", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "abc", "alert_id": "1142656"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_id": "1142656"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "0", "alert_id": "1142656"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "abc"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "-5"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-5", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "0"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "0", ALERT_ID_DISPLAY),
        ),
    ],
)
def test_gcb_case_alert_sla_resume_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_sla_resume_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_sla_resume_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_sla_resume_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-sla-resume command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-sla-resume")
    mocker.patch.object(demisto, "args", return_value={"case_id": "1001", "alert_id": "1142656"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_sla_resume_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


# --- gcb-case-alert-sla-set ---


@pytest.mark.parametrize(
    "time_str, expected_ms, tolerance_ms",
    [
        ("2 minutes", 2 * 60 * 1000, 1000),
        ("1 hour", 60 * 60 * 1000, 1000),
        ("3 days", 3 * TEST_DAY_MS, 1000),
        ("2 weeks", 14 * TEST_DAY_MS, 1000),
        ("1 month", 30 * TEST_DAY_MS, 2 * TEST_DAY_MS),
        ("2 years", 2 * 365 * TEST_DAY_MS, 2 * TEST_DAY_MS),
    ],
)
def test_convert_time_to_ms_relative_durations(time_str, expected_ms, tolerance_ms):
    """Test convert_time_to_ms with relative duration strings — within tolerance for calendar variation."""

    result = convert_time_to_ms(time_str, "test")
    assert abs(result - expected_ms) <= tolerance_ms


@pytest.mark.parametrize(
    "time_str, match",
    [
        ("not-a-date-at-all-xyz", "Invalid date"),
        ("2000-01-01", "is in the past"),
    ],
)
def test_convert_time_to_ms_invalid_input_raises(time_str, match):
    """Test convert_time_to_ms raises ValueError for unparseable or past-date input."""

    with pytest.raises(ValueError, match=match):
        convert_time_to_ms(time_str, "test_arg")


@pytest.mark.parametrize(
    "case_id, alert_id, total_time, critical_time, expected_error",
    [
        ("abc", "1142656", "2 days", None, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY)),
        ("-1", "1142656", "2 days", None, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-1", CASE_ID_DISPLAY)),
        ("1001", "abc", "2 days", None, MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY)),
        ("1001", "0", "2 days", None, MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "0", ALERT_ID_DISPLAY)),
        ("1001", "1142656", "1 day", "2 days", "total_time must be greater than critical_time"),
        (
            "1001",
            "1142656",
            "18-5-2026",
            "2 weeks",
            MESSAGES["TIME_IN_PAST"].format(arg_name="total_time", time_str="18-5-2026"),
        ),
        (
            "1001",
            "1142656",
            "2 weeks",
            "18-5-2026",
            MESSAGES["TIME_IN_PAST"].format(arg_name="critical_time", time_str="18-5-2026"),
        ),
    ],
)
def test_validate_case_alert_sla_set_args_invalid(case_id, alert_id, total_time, critical_time, expected_error):
    """Test validate_case_alert_sla_set_args raises ValueError for invalid inputs."""

    with pytest.raises(ValueError, match=expected_error):
        validate_case_alert_sla_set_args(case_id, alert_id, total_time, critical_time)


def test_validate_case_alert_sla_set_args_valid():
    """Test validate_case_alert_sla_set_args returns correct values for valid inputs."""

    two_days_ms = 2 * 24 * 60 * 60 * 1000
    one_day_ms = 24 * 60 * 60 * 1000

    total_ms, critical_ms = validate_case_alert_sla_set_args("1001", "1142656", "2 days", "1 day")

    assert abs(total_ms - two_days_ms) <= 1000
    assert critical_ms is not None
    assert abs(critical_ms - one_day_ms) <= 1000


def test_validate_case_alert_sla_set_args_without_critical_time():
    """Test validate_case_alert_sla_set_args returns None for critical_time_ms when not provided."""

    total_ms, critical_ms = validate_case_alert_sla_set_args("1001", "1142656", "2 days", None)

    assert abs(total_ms - 2 * 24 * 60 * 60 * 1000) <= 1000
    assert critical_ms is None


def test_gcb_case_alert_sla_set_command_success(mock_client, requests_mock):
    """Test gcb_case_alert_sla_set_command succeeds with valid inputs."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_SLA_SET'].format(case_id='1001', alert_id='1142656')}",
        text="",
        status_code=200,
    )

    result = gcb_case_alert_sla_set_command(
        mock_client,
        {"case_id": "1001", "alert_id": "1142656", "total_time": "2 days", "critical_time": "1 day"},
    )

    assert result.readable_output == "SLA for Alert `1142656` successfully set."
    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["CaseAlert"]
    assert result.outputs_key_field == "alertId"
    assert result.outputs["alertId"] == "1142656"
    assert result.outputs["caseId"] == 1001
    assert isinstance(result.outputs["slaExpirationTime"], str)
    assert isinstance(result.outputs["slaCriticalExpirationTime"], str)
    assert result.raw_response == result.outputs


def test_gcb_case_alert_sla_set_command_success_without_critical_time(mock_client, requests_mock):
    """Test gcb_case_alert_sla_set_command succeeds without critical_time."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_SLA_SET'].format(case_id='1001', alert_id='1142656')}",
        text="",
        status_code=200,
    )

    result = gcb_case_alert_sla_set_command(
        mock_client,
        {"case_id": "1001", "alert_id": "1142656", "total_time": "2 days"},
    )

    assert result.readable_output == "SLA for Alert `1142656` successfully set."
    assert result.outputs["alertId"] == "1142656"
    assert result.outputs["caseId"] == 1001
    assert isinstance(result.outputs["slaExpirationTime"], str)
    assert "slaCriticalExpirationTime" not in result.outputs


def test_gcb_case_alert_sla_set_command_api_error(mock_client, requests_mock):
    """Test gcb_case_alert_sla_set_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_SLA_SET'].format(case_id='1001', alert_id='1142656')}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_alert_sla_set_command(
            mock_client,
            {"case_id": "1001", "alert_id": "1142656", "total_time": "2 days", "critical_time": "1 day"},
        )

    assert PERMISSION_DENIED_TEXT in str(error.value)


def test_gcb_case_alert_sla_set_command_total_not_greater_than_critical(mock_client):
    """Test gcb_case_alert_sla_set_command raises when total_time <= critical_time."""

    with pytest.raises(ValueError, match="total_time must be greater than critical_time"):
        gcb_case_alert_sla_set_command(
            mock_client,
            {"case_id": "1001", "alert_id": "1142656", "total_time": "1 day", "critical_time": "2 days"},
        )


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "1001", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "1001", "alert_id": "1142656"}, MESSAGES["REQUIRED_ARGUMENT"].format("total_time")),
        (
            {"case_id": "1001", "alert_id": "1142656", "total_time": ""},
            MESSAGES["REQUIRED_ARGUMENT"].format("total_time"),
        ),
        (
            {"case_id": "abc", "alert_id": "1142656", "total_time": "2 days"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "abc", "total_time": "2 days"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
    ],
)
def test_gcb_case_alert_sla_set_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_sla_set_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_sla_set_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_sla_set_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-sla-set command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-sla-set")
    mocker.patch.object(
        demisto, "args", return_value={"case_id": "1001", "alert_id": "1142656", "total_time": "2 days", "critical_time": "1 day"}
    )
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_sla_set_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_alert_recommendation_create_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_case_alert_recommendation_create_command should return recommendation details."""

    mock_response = {"recommendationId": "00000000-0000-0000-0000-000000000001"}

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_RECOMMENDATION_CREATE'].format(case_id='1001', alert_id='1000001')}",
        json=mock_response,
    )

    expected_readable_output = (
        "Successfully created the recommendation for the alert 1000001.\n\n"
        "Recommendation ID: 00000000-0000-0000-0000-000000000001"
    )

    result = gcb_case_alert_recommendation_create_command(mock_client, {"case_id": "1001", "alert_id": "1000001"})

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["AlertRecommendation"]
    assert result.outputs_key_field == "recommendationId"
    assert result.outputs == mock_response
    assert result.raw_response == mock_response
    assert result.readable_output == expected_readable_output


def test_gcb_case_alert_recommendation_create_command_api_error(mock_client, requests_mock):
    """Test gcb_case_alert_recommendation_create_command when API returns a permission denied error."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_RECOMMENDATION_CREATE'].format(case_id='1001', alert_id='1000001')}",
        json={"error": {"message": PERMISSION_DENIED_TEXT}},
        status_code=403,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_alert_recommendation_create_command(mock_client, {"case_id": "1001", "alert_id": "1000001"})

    assert PERMISSION_DENIED_TEXT in str(error.value)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "1001", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "abc", "alert_id": "1000001"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        ({"case_id": "-5", "alert_id": "1000001"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY)),
        ({"case_id": "0", "alert_id": "1000001"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY)),
        (
            {"case_id": "1001", "alert_id": "abc"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        ({"case_id": "1001", "alert_id": "-5"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-5", ALERT_ID_DISPLAY)),
        ({"case_id": "1001", "alert_id": "0"}, MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "0", ALERT_ID_DISPLAY)),
    ],
)
def test_gcb_case_alert_recommendation_create_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_recommendation_create_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_recommendation_create_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_recommendation_create_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-recommendation-create command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-recommendation-create")
    mocker.patch.object(demisto, "args", return_value={"case_id": "1001", "alert_id": "1000001"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_recommendation_create_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_alert_recommendation_fetch_command_success(mock_client, requests_mock):
    """Test gcb_case_alert_recommendation_fetch_command with a successful SUCCEEDED response."""

    mock_response = util_load_json("test_data/case_alert_recommendation_fetch_response.json")
    expected_outputs = util_load_json("test_data/case_alert_recommendation_fetch_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_recommendation_fetch_hr.md")

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_FETCH_RECOMMENDATION'].format(case_id='1001')}",
        json=mock_response,
    )

    result = gcb_case_alert_recommendation_fetch_command(
        mock_client, {"case_id": "1001", "recommendation_id": "00000000-0000-0000-0000-000000001000"}
    )

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["AlertRecommendation"]
    assert result.outputs_key_field == "recommendationId"
    assert result.outputs == expected_outputs
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


def test_gcb_case_alert_recommendation_fetch_command_empty_response(mock_client, requests_mock):
    """Test gcb_case_alert_recommendation_fetch_command when API returns an empty response."""

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASE_ALERT_FETCH_RECOMMENDATION'].format(case_id='1001')}", json={})

    result = gcb_case_alert_recommendation_fetch_command(
        mock_client, {"case_id": "1001", "recommendation_id": "00000000-0000-0000-0000-000000001000"}
    )

    assert result.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("alert recommendation")


def test_gcb_case_alert_recommendation_fetch_command_api_error(mock_client, requests_mock):
    """Test gcb_case_alert_recommendation_fetch_command when API returns a 404 for a non-existent recommendation."""

    error_message = "Recommendation not found"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_FETCH_RECOMMENDATION'].format(case_id='1001')}",
        json={"error": {"message": error_message}},
        status_code=404,
    )

    with pytest.raises(ValueError) as error:
        gcb_case_alert_recommendation_fetch_command(mock_client, {"case_id": "1001", "recommendation_id": "rec-nonexistent"})

    assert str(error.value) == MESSAGES["HTTP_ERROR"].format(404, error_message)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("recommendation_id")),
        ({"case_id": "1001", "recommendation_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("recommendation_id")),
        (
            {"case_id": "abc", "recommendation_id": "00000000-0000-0000-0000-000000001000"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "recommendation_id": "00000000-0000-0000-0000-000000001000"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "0", "recommendation_id": "00000000-0000-0000-0000-000000001000"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "0", CASE_ID_DISPLAY),
        ),
    ],
)
def test_gcb_case_alert_recommendation_fetch_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_recommendation_fetch_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_recommendation_fetch_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_recommendation_fetch_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-recommendation-fetch command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-recommendation-fetch")
    mocker.patch.object(
        demisto, "args", return_value={"case_id": "1001", "recommendation_id": "00000000-0000-0000-0000-000000001000"}
    )
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_recommendation_fetch_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_alert_customfield_list_command_success(mock_client, requests_mock):
    """When a valid response is received, gcb_case_alert_customfield_list_command should return custom field values."""

    mock_response = util_load_json("test_data/case_alert_customfield_list_success_response.json")
    expected_outputs = util_load_json("test_data/case_alert_customfield_list_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_customfield_list_hr.md")
    mock_custom_fields = util_load_json("test_data/case_alert_customfield_list_custom_fields_response.json")

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_CUSTOMFIELD_VALUES'].format(case_id='1001', alert_id='2001')}", json=mock_response
    )
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CUSTOM_FIELDS']}",
        json=mock_custom_fields,
    )

    result = gcb_case_alert_customfield_list_command(mock_client, {"case_id": "1001", "alert_id": "2001"})

    assert result.outputs == expected_outputs
    assert result.readable_output == expected_hr
    assert result.raw_response == mock_response


def test_gcb_case_alert_customfield_list_command_empty_response(mock_client, requests_mock):
    """When no custom field values are found, gcb_case_alert_customfield_list_command should return appropriate message."""

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['CASE_ALERT_CUSTOMFIELD_VALUES'].format(case_id='1001', alert_id='2001')}", json={})

    result = gcb_case_alert_customfield_list_command(mock_client, {"case_id": "1001", "alert_id": "2001"})

    assert result.outputs is None
    assert result.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("custom field values")


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "1001", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "abc", "alert_id": "2001"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-1", "alert_id": "2001"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-1", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "abc"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "-1"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-1", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "1001", "alert_id": "2001", "page_size": "0"},
            MESSAGES["INVALID_INT_RANGE"].format(0, "page_size", 1, MAX_PAGE_SIZE),
        ),
        (
            {"case_id": "1001", "alert_id": "2001", "page_size": "1001"},
            MESSAGES["INVALID_INT_RANGE"].format(1001, "page_size", 1, MAX_PAGE_SIZE),
        ),
    ],
)
def test_gcb_case_alert_customfield_list_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_customfield_list_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_customfield_list_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_customfield_list_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-customfield-list command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-customfield-list")
    mocker.patch.object(demisto, "args", return_value={"case_id": "1001", "alert_id": "2001"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_customfield_list_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_alert_customfield_list_command_list_custom_fields_failure(mock_client, requests_mock):
    """When list_custom_fields raises an exception, the command should not hard-fail
    but return results with empty display names."""

    mock_response = util_load_json("test_data/case_alert_customfield_list_success_response.json")

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_CUSTOMFIELD_VALUES'].format(case_id='1001', alert_id='2001')}", json=mock_response
    )
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CUSTOM_FIELDS']}",
        exc=Exception("network error"),
    )

    with pytest.raises(Exception, match="network error"):
        gcb_case_alert_customfield_list_command(mock_client, {"case_id": "1001", "alert_id": "2001"})


def test_gcb_case_alert_customfield_list_command_empty_display_name_fallback(mock_client, requests_mock):
    """When list_custom_fields returns no matching fields, display names should fall back to empty string."""

    mock_response = util_load_json("test_data/case_alert_customfield_list_success_response.json")

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_CUSTOMFIELD_VALUES'].format(case_id='1001', alert_id='2001')}", json=mock_response
    )
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CUSTOM_FIELDS']}",
        json={"customFields": []},
    )

    result = gcb_case_alert_customfield_list_command(mock_client, {"case_id": "1001", "alert_id": "2001"})

    cfv_key = next(k for k in result.outputs if "AlertCustomFieldValue" in k)
    for entry in result.outputs[cfv_key]:
        assert entry.get("displayName", "") == ""


def test_gcb_case_alert_entity_list_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_case_alert_entity_list_command should return alert entities."""

    mock_response = util_load_json("test_data/case_alert_entity_list_success_response.json")
    outputs = util_load_json("test_data/case_alert_entity_list_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_entity_list_hr.md")

    requests_mock.get(
        (
            f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITIES'].format(case_id='306082', alert_id='1001')}"
            "?pageSize=50&orderBy=id%20desc"
        ),
        json=mock_response,
    )

    result = gcb_case_alert_entity_list_command(mock_client, {"case_id": "306082", "alert_id": "1001"})

    assert result.outputs == outputs
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


def test_gcb_case_alert_entity_list_command_empty_response(mock_client, requests_mock):
    """When empty response is received, gcb_case_alert_entity_list_command should return appropriate message."""

    mock_response = {}

    requests_mock.get(
        (
            f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITIES'].format(case_id='306082', alert_id='1001')}"
            "?pageSize=50&orderBy=id%20desc"
        ),
        json=mock_response,
    )

    result = gcb_case_alert_entity_list_command(mock_client, {"case_id": "306082", "alert_id": "1001"})

    assert result.raw_response == {}
    assert "No alert entities found" in result.readable_output


def test_gcb_case_alert_entity_list_command_with_pagination(mock_client, requests_mock):
    """Test gcb_case_alert_entity_list_command with pagination parameters and next page token in response."""

    mock_response = util_load_json("test_data/case_alert_entity_list_paginated_response.json")

    requests_mock.get(
        (
            f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITIES'].format(case_id='306082', alert_id='1001')}"
            "?pageSize=1&pageToken=prev-token&orderBy=id%20asc"
        ),
        json=mock_response,
    )

    result = gcb_case_alert_entity_list_command(
        mock_client,
        {"case_id": "306082", "alert_id": "1001", "page_size": "1", "page_token": "prev-token", "sort_order": "Asc"},
    )

    assert result.raw_response == mock_response
    assert len(result.outputs) == 2
    assert "mock-entity-page-token" in result.readable_output


def test_gcb_case_alert_entity_list_command_with_advanced_filter(mock_client, requests_mock):
    """Test gcb_case_alert_entity_list_command passes advanced_filter directly to API."""

    mock_response = util_load_json("test_data/case_alert_entity_list_success_response.json")

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITIES'].format(case_id='306082', alert_id='1001')}",
        json=mock_response,
    )

    result = gcb_case_alert_entity_list_command(
        mock_client,
        {"case_id": "306082", "alert_id": "1001", "advanced_filter": "entityType='ADDRESS' AND suspicious=true"},
    )

    assert result.raw_response == mock_response
    assert "filter=entityType" in requests_mock.last_request.url


def test_gcb_case_alert_entity_list_command_with_filter_logic_or(mock_client, requests_mock):
    """Test gcb_case_alert_entity_list_command uses OR separator when filter_logic=OR."""

    mock_response = util_load_json("test_data/case_alert_entity_list_success_response.json")

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITIES'].format(case_id='306082', alert_id='1001')}",
        json=mock_response,
    )

    result = gcb_case_alert_entity_list_command(
        mock_client,
        {"case_id": "306082", "alert_id": "1001", "suspicious": "true", "internal": "false", "filter_logic": "OR"},
    )

    assert result.raw_response == mock_response
    assert "suspicious%3Dtrue+OR+internal%3Dfalse" in requests_mock.last_request.url or "OR" in requests_mock.last_request.url


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        (
            {"case_id": "abc", "alert_id": "1001"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_id": "1001"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        ({"case_id": "306082"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "306082", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "306082", "alert_id": "abc"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "page_size": "-1"},
            MESSAGES["INVALID_INT_RANGE"].format(-1, "page_size", 1, 1000),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "page_size": "1001"},
            MESSAGES["INVALID_INT_RANGE"].format(1001, "page_size", 1, 1000),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "sort_order": "Invalid"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("sort_order", "Asc, Desc"),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "filter_logic": "XOR"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("filter_logic", ", ".join(VALID_CASE_FILTER_LOGIC)),
        ),
    ],
)
def test_gcb_case_alert_entity_list_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_entity_list_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_entity_list_command(mock_client, args)

    assert str(error.value) == expected_error_message


@pytest.mark.parametrize(
    "case_id, alert_id, page_size, sort_order, filter_logic",
    [
        ("306082", "1001", 50, "Desc", "AND"),
        ("306082", "1001", 1, "Asc", "OR"),
        ("306082", "1001", 1000, "Desc", "AND"),
    ],
)
def test_validate_case_alert_entity_list_args_valid(case_id, alert_id, page_size, sort_order, filter_logic):
    """Test validate_case_alert_entity_list_args with valid inputs."""

    result = validate_case_alert_entity_list_args(case_id, alert_id, page_size, sort_order, filter_logic)
    assert result == (case_id, alert_id, page_size, sort_order, filter_logic)


def test_main_gcb_case_alert_entity_list_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-entity-list command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-entity-list")
    mocker.patch.object(demisto, "args", return_value={"case_id": "306082", "alert_id": "1001"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_entity_list_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        (
            {"entity_types": ["ADDRESS", "HOSTNAME"]},
            '(type="ADDRESS" OR type="HOSTNAME")',
        ),
        (
            {"suspicious": True, "internal": False},
            "suspicious=true AND internal=false",
        ),
        (
            {"threat_sources": ["malware"], "environments": ["Production", "Staging"]},
            '(threatSource="malware") AND (environment="Production" OR environment="Staging")',
        ),
        (
            {"entity_types": ["ADDRESS"], "suspicious": True, "environments": ["Default Environment"]},
            '(type="ADDRESS") AND suspicious=true AND (environment="Default Environment")',
        ),
        (
            {"network_priorities": ["0", "1"]},
            "(networkPriority=0 OR networkPriority=1)",
        ),
        ({}, ""),
    ],
)
def test_prepare_alert_entity_filter(kwargs, expected):
    """Test prepare_alert_entity_filter builds correct AIP-160 filter strings."""
    assert prepare_alert_entity_filter(**kwargs) == expected


def test_gcb_case_alert_entity_get_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_case_alert_entity_get_command should return entity details."""

    mock_response = util_load_json("test_data/case_alert_entity_get_success_response.json")
    outputs = util_load_json("test_data/case_alert_entity_get_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_entity_get_hr.md")

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITY'].format(case_id='306082', alert_id='1001', entity_id='376359')}",
        json=mock_response,
    )

    result = gcb_case_alert_entity_get_command(mock_client, {"case_id": "306082", "alert_id": "1001", "entity_id": "376359"})

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["AlertEntity"]
    assert result.outputs_key_field == "id"
    assert result.outputs == outputs
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


def test_gcb_case_alert_entity_get_command_empty_response(mock_client, requests_mock):
    """When empty response is received, gcb_case_alert_entity_get_command should return appropriate message."""

    mock_response = {}

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITY'].format(case_id='306082', alert_id='1001', entity_id='376359')}",
        json=mock_response,
    )

    result = gcb_case_alert_entity_get_command(mock_client, {"case_id": "306082", "alert_id": "1001", "entity_id": "376359"})

    assert result.raw_response == {}
    assert result.outputs is None
    assert "No entity information found" in result.readable_output


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        (
            {"case_id": "abc", "alert_id": "1001", "entity_id": "376359"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_id": "1001", "entity_id": "376359"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "306082", "alert_id": "-5", "entity_id": "376359"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-5", ALERT_ID_DISPLAY),
        ),
        ({"case_id": "306082"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "306082", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "306082", "alert_id": "abc", "entity_id": "376359"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        ({"case_id": "306082", "alert_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"case_id": "306082", "alert_id": "1001", "entity_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("entity_id")),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "abc"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("entity_id", "abc", ENTITY_ID_DISPLAY),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "-1"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("entity_id", "-1", ENTITY_ID_DISPLAY),
        ),
    ],
)
def test_gcb_case_alert_entity_get_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_entity_get_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_entity_get_command(mock_client, args)

    assert str(error.value) == expected_error_message


@pytest.mark.parametrize(
    "case_id, alert_id, entity_id",
    [
        ("306082", "1001", "376359"),
        ("1", "1", "1"),
    ],
)
def test_validate_case_alert_entity_get_args_valid(case_id, alert_id, entity_id):
    """Test validate_case_alert_entity_get_args does not raise for valid inputs."""

    validate_case_alert_entity_get_args(case_id, alert_id, entity_id)


def test_main_gcb_case_alert_entity_get_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-entity-get command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-entity-get")
    mocker.patch.object(demisto, "args", return_value={"case_id": "306082", "alert_id": "1001", "entity_id": "376359"})
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_entity_get_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_alert_entity_create_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_case_alert_entity_create_command should return created entity details."""

    mock_response = util_load_json("test_data/case_alert_entity_create_success_response.json")
    outputs = util_load_json("test_data/case_alert_entity_create_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_entity_create_hr.md")

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITIES'].format(case_id='306082', alert_id='1001')}",
        json=mock_response,
    )

    result = gcb_case_alert_entity_create_command(
        mock_client,
        {"case_id": "306082", "alert_id": "1001", "identifier": MY_IP, "entity_type": "ADDRESS", "suspicious": "true"},
    )

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["AlertEntity"]
    assert result.outputs_key_field == "id"
    assert result.outputs == outputs
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


def test_gcb_case_alert_entity_create_command_network_priority(mock_client, requests_mock):
    """When network_priority is provided, it should be sent in the request body."""

    mock_response = util_load_json("test_data/case_alert_entity_create_success_response.json")
    post_mock = requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITIES'].format(case_id='306082', alert_id='1001')}",
        json=mock_response,
    )

    gcb_case_alert_entity_create_command(
        mock_client,
        {
            "case_id": "306082",
            "alert_id": "1001",
            "identifier": MY_IP,
            "entity_type": "ADDRESS",
            "network_priority": "5",
        },
    )

    assert post_mock.last_request.json().get("networkPriority") == 5


def test_gcb_case_alert_entity_create_command_empty_response(mock_client, requests_mock):
    """When empty response is received, gcb_case_alert_entity_create_command should return appropriate message."""

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITIES'].format(case_id='306082', alert_id='1001')}",
        json={},
    )

    result = gcb_case_alert_entity_create_command(
        mock_client, {"case_id": "306082", "alert_id": "1001", "identifier": MY_IP, "entity_type": "ADDRESS"}
    )

    assert result.raw_response == {}
    assert result.outputs is None
    assert "No entity information found" in result.readable_output


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        (
            {"case_id": "abc", "alert_id": "1001", "identifier": "test", "entity_type": "ADDRESS"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_id": "1001", "identifier": "test", "entity_type": "ADDRESS"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        ({"case_id": "306082"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "306082", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "306082", "alert_id": "abc", "identifier": "test", "entity_type": "ADDRESS"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "306082", "alert_id": "-5", "identifier": "test", "entity_type": "ADDRESS"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-5", ALERT_ID_DISPLAY),
        ),
        ({"case_id": "306082", "alert_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("identifier")),
        ({"case_id": "306082", "alert_id": "1001", "identifier": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("identifier")),
        (
            {"case_id": "306082", "alert_id": "1001", "identifier": "test"},
            MESSAGES["REQUIRED_ARGUMENT"].format("entity_type"),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "identifier": "test", "entity_type": ""},
            MESSAGES["REQUIRED_ARGUMENT"].format("entity_type"),
        ),
        (
            {
                "case_id": "306082",
                "alert_id": "1001",
                "identifier": "test",
                "entity_type": "ADDRESS",
                "network_priority": "-1",
            },
            MESSAGES["INVALID_NON_NEGATIVE_INTEGER"].format(-1, "network_priority"),
        ),
    ],
)
def test_gcb_case_alert_entity_create_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_entity_create_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_entity_create_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_entity_create_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-entity-create command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-entity-create")
    mocker.patch.object(
        demisto,
        "args",
        return_value={"case_id": "306082", "alert_id": "1001", "identifier": MY_IP, "entity_type": "ADDRESS"},
    )
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_entity_create_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_alert_entity_update_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_case_alert_entity_update_command should return updated entity details."""

    mock_response = util_load_json("test_data/case_alert_entity_update_success_response.json")
    outputs = util_load_json("test_data/case_alert_entity_update_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_entity_update_hr.md")

    requests_mock.patch(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITY'].format(case_id='306082', alert_id='1001', entity_id='376398')}",
        json=mock_response,
    )

    result = gcb_case_alert_entity_update_command(
        mock_client,
        {
            "case_id": "306082",
            "alert_id": "1001",
            "entity_id": "376398",
            "suspicious": "true",
            "attacker": "true",
            "network_priority": "5",
        },
    )

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["AlertEntity"]
    assert result.outputs_key_field == "id"
    assert result.outputs == outputs
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


def test_gcb_case_alert_entity_update_command_network_priority(mock_client, requests_mock):
    """When network_priority is provided, it should be sent in the request body."""

    mock_response = util_load_json("test_data/case_alert_entity_update_success_response.json")
    patch_mock = requests_mock.patch(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITY'].format(case_id='306082', alert_id='1001', entity_id='376398')}",
        json=mock_response,
    )

    gcb_case_alert_entity_update_command(
        mock_client,
        {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "network_priority": "5"},
    )

    assert patch_mock.last_request.json().get("networkPriority") == 5


def test_gcb_case_alert_entity_update_command_empty_response(mock_client, requests_mock):
    """When empty response is received, gcb_case_alert_entity_update_command should return appropriate message."""

    requests_mock.patch(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITY'].format(case_id='306082', alert_id='1001', entity_id='376398')}",
        json={},
    )

    result = gcb_case_alert_entity_update_command(
        mock_client, {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "suspicious": "true"}
    )

    assert result.raw_response == {}
    assert result.outputs is None
    assert "No entity information found" in result.readable_output


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        (
            {"case_id": "abc", "alert_id": "1001", "entity_id": "376398", "suspicious": "true"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_id": "1001", "entity_id": "376398", "suspicious": "true"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        ({"case_id": "306082"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "306082", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "306082", "alert_id": "abc", "entity_id": "376398", "suspicious": "true"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "306082", "alert_id": "-5", "entity_id": "376398", "suspicious": "true"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-5", ALERT_ID_DISPLAY),
        ),
        ({"case_id": "306082", "alert_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"case_id": "306082", "alert_id": "1001", "entity_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("entity_id")),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "abc", "suspicious": "true"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("entity_id", "abc", ENTITY_ID_DISPLAY),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "-5", "suspicious": "true"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("entity_id", "-5", ENTITY_ID_DISPLAY),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "376398"},
            MESSAGES["AT_LEAST_ONE_REQUIRED"].format(", ".join(CASE_ALERT_ENTITY_UPDATE_ARGS)),
        ),
        (
            {
                "case_id": "306082",
                "alert_id": "1001",
                "entity_id": "376398",
                "suspicious": "true",
                "network_priority": "-1",
            },
            MESSAGES["INVALID_NON_NEGATIVE_INTEGER"].format(-1, "network_priority"),
        ),
    ],
)
def test_gcb_case_alert_entity_update_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_entity_update_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_entity_update_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_gcb_case_alert_entity_update_command_false_boolean_only(mock_client, requests_mock):
    """When suspicious=false is the only arg, command should succeed (not raise AT_LEAST_ONE_REQUIRED)."""
    mock_response = util_load_json("test_data/case_alert_entity_update_success_response.json")
    requests_mock.patch(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITY'].format(case_id='111111', alert_id='2222', entity_id='333333')}",
        json=mock_response,
    )

    result = gcb_case_alert_entity_update_command(
        mock_client,
        {"case_id": "111111", "alert_id": "2222", "entity_id": "333333", "suspicious": "false"},
    )

    assert result.outputs is not None


def test_gcb_case_alert_entity_update_command_network_priority_zero(mock_client, requests_mock):
    """When network_priority=0, command should succeed (zero is a valid non-negative value)."""
    mock_response = util_load_json("test_data/case_alert_entity_update_success_response.json")
    patch_mock = requests_mock.patch(
        f"{BASE_URL}{ENDPOINTS['CASE_ALERT_INVOLVED_ENTITY'].format(case_id='111111', alert_id='2222', entity_id='333333')}",
        json=mock_response,
    )

    gcb_case_alert_entity_update_command(
        mock_client,
        {"case_id": "111111", "alert_id": "2222", "entity_id": "333333", "network_priority": "0"},
    )

    assert patch_mock.last_request.json().get("networkPriority") == 0


def test_main_gcb_case_alert_entity_update_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-entity-update command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-entity-update")
    mocker.patch.object(
        demisto,
        "args",
        return_value={"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "suspicious": "true"},
    )
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_entity_update_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_alert_entity_property_add_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_case_alert_entity_property_add_command should return entity with property added."""

    mock_response = util_load_json("test_data/case_alert_entity_property_add_success_response.json")
    outputs = util_load_json("test_data/case_alert_entity_property_add_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_entity_property_add_hr.md")

    endpoint = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITY_ADD_PROPERTY"]
    url = f"{BASE_URL}{endpoint.format(case_id='306082', alert_id='1001', entity_id='376398')}"
    requests_mock.post(url, json=mock_response)

    result = gcb_case_alert_entity_property_add_command(
        mock_client,
        {
            "case_id": "306082",
            "alert_id": "1001",
            "entity_id": "376398",
            "key": "total_score",
            "value": "42/72",
        },
    )

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["AlertEntity"]
    assert result.outputs_key_field == "id"
    assert result.outputs == outputs
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


def test_gcb_case_alert_entity_property_add_command_request_body(mock_client, requests_mock):
    """When key and value are provided, they should be sent in the request body."""

    mock_response = util_load_json("test_data/case_alert_entity_property_add_success_response.json")
    endpoint = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITY_ADD_PROPERTY"]
    url = f"{BASE_URL}{endpoint.format(case_id='306082', alert_id='1001', entity_id='376398')}"
    post_mock = requests_mock.post(url, json=mock_response)

    gcb_case_alert_entity_property_add_command(
        mock_client,
        {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "key": "total_score", "value": "42/72"},
    )

    assert post_mock.last_request.json() == {"key": "total_score", "value": "42/72"}


def test_gcb_case_alert_entity_property_add_command_empty_response(mock_client, requests_mock):
    """When empty response is received, gcb_case_alert_entity_property_add_command should return appropriate message."""

    endpoint = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITY_ADD_PROPERTY"]
    url = f"{BASE_URL}{endpoint.format(case_id='306082', alert_id='1001', entity_id='376398')}"
    requests_mock.post(url, json={})

    result = gcb_case_alert_entity_property_add_command(
        mock_client,
        {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "key": "total_score", "value": "42/72"},
    )

    assert result.raw_response == {}
    assert result.outputs is None
    assert "No entity information found" in result.readable_output


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        (
            {"case_id": "abc", "alert_id": "1001", "entity_id": "376398", "key": "total_score", "value": "42/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_id": "1001", "entity_id": "376398", "key": "total_score", "value": "42/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        ({"case_id": "306082"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "306082", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "306082", "alert_id": "abc", "entity_id": "376398", "key": "total_score", "value": "42/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "306082", "alert_id": "-5", "entity_id": "376398", "key": "total_score", "value": "42/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-5", ALERT_ID_DISPLAY),
        ),
        ({"case_id": "306082", "alert_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"case_id": "306082", "alert_id": "1001", "entity_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("entity_id")),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "abc", "key": "total_score", "value": "42/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("entity_id", "abc", ENTITY_ID_DISPLAY),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "-5", "key": "total_score", "value": "42/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("entity_id", "-5", ENTITY_ID_DISPLAY),
        ),
        ({"case_id": "306082", "alert_id": "1001", "entity_id": "376398"}, MESSAGES["REQUIRED_ARGUMENT"].format("key")),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "key": ""},
            MESSAGES["REQUIRED_ARGUMENT"].format("key"),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "key": "total_score"},
            MESSAGES["REQUIRED_ARGUMENT"].format("value"),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "key": "total_score", "value": ""},
            MESSAGES["REQUIRED_ARGUMENT"].format("value"),
        ),
    ],
)
def test_gcb_case_alert_entity_property_add_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_entity_property_add_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_entity_property_add_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_entity_property_add_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-entity-property-add command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-entity-property-add")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "case_id": "306082",
            "alert_id": "1001",
            "entity_id": "376398",
            "key": "total_score",
            "value": "42/72",
        },
    )
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_entity_property_add_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


def test_gcb_case_alert_entity_property_update_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_case_alert_entity_property_update_command returns entity with property updated."""

    mock_response = util_load_json("test_data/case_alert_entity_property_update_success_response.json")
    outputs = util_load_json("test_data/case_alert_entity_property_update_context.json")
    expected_hr = util_load_text_data("test_data/case_alert_entity_property_update_hr.md")

    endpoint = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITY_UPDATE_PROPERTY"]
    url = f"{BASE_URL}{endpoint.format(case_id='306082', alert_id='1001', entity_id='376398')}"
    requests_mock.post(url, json=mock_response)

    result = gcb_case_alert_entity_property_update_command(
        mock_client,
        {
            "case_id": "306082",
            "alert_id": "1001",
            "entity_id": "376398",
            "key": "total_score",
            "value": "68/72",
        },
    )

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["AlertEntity"]
    assert result.outputs_key_field == "id"
    assert result.outputs == outputs
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


def test_gcb_case_alert_entity_property_update_command_request_body(mock_client, requests_mock):
    """When key and value are provided, they should be sent in the request body."""

    mock_response = util_load_json("test_data/case_alert_entity_property_update_success_response.json")
    endpoint = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITY_UPDATE_PROPERTY"]
    url = f"{BASE_URL}{endpoint.format(case_id='306082', alert_id='1001', entity_id='376398')}"
    post_mock = requests_mock.post(url, json=mock_response)

    gcb_case_alert_entity_property_update_command(
        mock_client,
        {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "key": "total_score", "value": "68/72"},
    )

    assert post_mock.last_request.json() == {"key": "total_score", "value": "68/72"}


def test_gcb_case_alert_entity_property_update_command_empty_response(mock_client, requests_mock):
    """When empty response is received, gcb_case_alert_entity_property_update_command returns appropriate message."""

    endpoint = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITY_UPDATE_PROPERTY"]
    url = f"{BASE_URL}{endpoint.format(case_id='306082', alert_id='1001', entity_id='376398')}"
    requests_mock.post(url, json={})

    result = gcb_case_alert_entity_property_update_command(
        mock_client,
        {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "key": "total_score", "value": "68/72"},
    )

    assert result.raw_response == {}
    assert result.outputs is None
    assert "No entity information found" in result.readable_output


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        (
            {"case_id": "abc", "alert_id": "1001", "entity_id": "376398", "key": "total_score", "value": "68/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_id": "1001", "entity_id": "376398", "key": "total_score", "value": "68/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        ({"case_id": "306082"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"case_id": "306082", "alert_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        (
            {"case_id": "306082", "alert_id": "abc", "entity_id": "376398", "key": "total_score", "value": "68/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "abc", ALERT_ID_DISPLAY),
        ),
        (
            {"case_id": "306082", "alert_id": "-5", "entity_id": "376398", "key": "total_score", "value": "68/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", "-5", ALERT_ID_DISPLAY),
        ),
        ({"case_id": "306082", "alert_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("entity_id")),
        ({"case_id": "306082", "alert_id": "1001", "entity_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("entity_id")),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "abc", "key": "total_score", "value": "68/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("entity_id", "abc", ENTITY_ID_DISPLAY),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "-5", "key": "total_score", "value": "68/72"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("entity_id", "-5", ENTITY_ID_DISPLAY),
        ),
        ({"case_id": "306082", "alert_id": "1001", "entity_id": "376398"}, MESSAGES["REQUIRED_ARGUMENT"].format("key")),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "key": ""},
            MESSAGES["REQUIRED_ARGUMENT"].format("key"),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "key": "total_score"},
            MESSAGES["REQUIRED_ARGUMENT"].format("value"),
        ),
        (
            {"case_id": "306082", "alert_id": "1001", "entity_id": "376398", "key": "total_score", "value": ""},
            MESSAGES["REQUIRED_ARGUMENT"].format("value"),
        ),
    ],
)
def test_gcb_case_alert_entity_property_update_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_case_alert_entity_property_update_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_case_alert_entity_property_update_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_case_alert_entity_property_update_command_success(mocker, mock_client):
    """Test main() routes gcb-case-alert-entity-property-update command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-case-alert-entity-property-update")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "case_id": "306082",
            "alert_id": "1001",
            "entity_id": "376398",
            "key": "total_score",
            "value": "68/72",
        },
    )
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_case_alert_entity_property_update_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)


@pytest.mark.parametrize(
    "args",
    [
        ({"execution_scope": "alert"}),
        ({"execution_scope": "CASE", "environment": "Production"}),
    ],
)
def test_gcb_playbook_list_command_success(mock_client, requests_mock, args):
    """When valid response is received, gcb_playbook_list_command should return playbook list."""

    mock_response = util_load_json("test_data/playbook_list_success_response.json")
    expected_outputs = util_load_json("test_data/playbook_list_context.json")
    expected_hr = util_load_text_data("test_data/playbook_list_hr.md")

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['LEGACY_PLAYBOOKS']}", json=mock_response)

    result = gcb_playbook_list_command(mock_client, args)

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["Playbook"]
    assert result.outputs_key_field == "workflowDefinitionIdentifier"
    assert result.outputs == expected_outputs
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


def test_gcb_playbook_list_command_empty_response(mock_client, requests_mock):
    """When empty payload is received, gcb_playbook_list_command should return no records message."""

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['LEGACY_PLAYBOOKS']}", json={})

    result = gcb_playbook_list_command(mock_client, {})

    assert result.outputs is None
    assert result.raw_response == {}
    assert "No enabled playbooks found" in result.readable_output


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        (
            {"execution_scope": "INVALID"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("execution_scope", ", ".join(VALID_EXECUTION_SCOPES)),
        )
    ],
)
def test_gcb_playbook_list_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_playbook_list_command raises ValueError for invalid execution_scope values."""

    with pytest.raises(ValueError) as error:
        gcb_playbook_list_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_gcb_playbook_attach_command_success(mock_client, requests_mock):
    """When valid response is received, gcb_playbook_attach_command should return confirmation message."""

    args = {
        "case_id": "1001",
        "alert_group_identifier": "Access Disabled Accounts_00000000-0000-0000-0000-000000000001",
        "alert_identifier": "ACCESS DISABLED ACCOUNTS_00000000-0000-0000-0000-000000000002",
        "playbook_name": "Phishing Investigation",
        "original_workflow_definition_identifier": "00000000-0000-0000-0000-000000000001",
    }
    mock_response = {"payload": True}
    context = util_load_json("test_data/playbook_attach_context.json")
    expected_hr = (
        "Playbook 'Phishing Investigation' successfully attached to alert "
        "ACCESS DISABLED ACCOUNTS_00000000-0000-0000-0000-000000000002 in case 1001."
    )

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['LEGACY_PLAYBOOK_ATTACH']}",
        json=mock_response,
    )

    result = gcb_playbook_attach_command(mock_client, args)

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["PlaybookAttach"]
    assert result.outputs_key_field == "alertIdentifier"
    assert result.outputs == context.get("success")
    assert result.raw_response == mock_response
    assert result.readable_output == expected_hr


def test_gcb_playbook_attach_command_api_failure(mock_client, requests_mock):
    """When API returns payload false, gcb_playbook_attach_command should return failure HR."""

    args = {
        "case_id": "1001",
        "alert_group_identifier": "Access Disabled Accounts_00000000-0000-0000-0000-000000000006",
        "alert_identifier": "ACCESS DISABLED ACCOUNTS_00000000-0000-0000-0000-000000000007",
        "playbook_name": "Phishing Investigation",
    }

    context = util_load_json("test_data/playbook_attach_context.json")
    mock_response = {"payload": False}
    expected_hr = (
        "Failed to attach playbook 'Phishing Investigation' to alert "
        "ACCESS DISABLED ACCOUNTS_00000000-0000-0000-0000-000000000007 in case 1001."
    )

    requests_mock.post(f"{BASE_URL}{ENDPOINTS['LEGACY_PLAYBOOK_ATTACH']}", json=mock_response)

    result = gcb_playbook_attach_command(mock_client, args)

    assert result.outputs_prefix == SECOPS_OUTPUT_PATHS["PlaybookAttach"]
    assert result.outputs_key_field == "alertIdentifier"
    assert result.raw_response == mock_response
    assert result.outputs == context.get("failed")
    assert result.readable_output == expected_hr


def test_gcb_playbook_attach_command_api_error(mock_client, requests_mock):
    """When API returns 400, gcb_playbook_attach_command should raise ValueError."""

    args = {
        "case_id": "1001",
        "alert_group_identifier": "Access Disabled Accounts_00000000-0000-0000-0000-000000000106",
        "alert_identifier": "ACCESS DISABLED ACCOUNTS_00000000-0000-0000-0000-000000000207",
        "playbook_name": "Phishing Investigation",
    }

    requests_mock.post(
        f"{BASE_URL}{ENDPOINTS['LEGACY_PLAYBOOK_ATTACH']}",
        status_code=404,
        json={"error": {"message": "Case not found.", "code": 404}},
    )

    with pytest.raises(ValueError, match="Case not found."):
        gcb_playbook_attach_command(mock_client, args)


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        ({"case_id": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("case_id")),
        (
            {"case_id": "abc", "alert_group_identifier": "grp", "alert_identifier": "alert", "playbook_name": "pb"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "abc", CASE_ID_DISPLAY),
        ),
        (
            {"case_id": "-5", "alert_group_identifier": "grp", "alert_identifier": "alert", "playbook_name": "pb"},
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", "-5", CASE_ID_DISPLAY),
        ),
        ({"case_id": "1001"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_group_identifier")),
        ({"case_id": "1001", "alert_group_identifier": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_group_identifier")),
        ({"case_id": "1001", "alert_group_identifier": "grp"}, MESSAGES["REQUIRED_ARGUMENT"].format("alert_identifier")),
        (
            {"case_id": "1001", "alert_group_identifier": "grp", "alert_identifier": ""},
            MESSAGES["REQUIRED_ARGUMENT"].format("alert_identifier"),
        ),
        (
            {"case_id": "1001", "alert_group_identifier": "grp", "alert_identifier": "alert"},
            MESSAGES["REQUIRED_ARGUMENT"].format("playbook_name"),
        ),
        (
            {"case_id": "1001", "alert_group_identifier": "grp", "alert_identifier": "alert", "playbook_name": ""},
            MESSAGES["REQUIRED_ARGUMENT"].format("playbook_name"),
        ),
    ],
)
def test_gcb_playbook_attach_command_invalid_args(mock_client, args, expected_error_message):
    """Test gcb_playbook_attach_command with invalid arguments."""

    with pytest.raises(ValueError) as error:
        gcb_playbook_attach_command(mock_client, args)

    assert str(error.value) == expected_error_message


def test_main_gcb_playbook_attach_command_success(mocker, mock_client):
    """Test main() routes gcb-playbook-attach command correctly."""

    mocker.patch.object(demisto, "params", return_value=VALID_PARAMS)
    mocker.patch.object(demisto, "command", return_value="gcb-playbook-attach")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "case_id": "1001",
            "alert_group_identifier": "Access Disabled Accounts_00000000-0000-0000-0000-000000000003",
            "alert_identifier": "ACCESS DISABLED ACCOUNTS_00000000-0000-0000-0000-000000000004",
            "playbook_name": "Phishing Investigation",
        },
    )
    mocker.patch("GoogleSecOpsCases.validate_configuration_parameters")
    mocker.patch("GoogleSecOpsCases.Client", return_value=mock_client)
    mock_command = mocker.patch("GoogleSecOpsCases.gcb_playbook_attach_command", return_value=mock.MagicMock())
    mock_return_results = mocker.patch("GoogleSecOpsCases.return_results")

    main()

    mock_command.assert_called_once()
    mock_return_results.assert_called_once_with(mock_command.return_value)
