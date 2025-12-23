# pylint: disable=E9010, E9011
"""CyberArk Identity Security Platform Integration - Unit Tests
Pytest Unit Tests: all function names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing
"""

import json
import os
import re
import time
from datetime import datetime, timezone  # noqa: UP017

import pytest
from CommonServerPython import *

import CyberArkISP  # noqa: E402
from CyberArkISP import (  # noqa: E402
    APIKeys,
    APIValues,
    Client,
    Config,
    ContextKeys,
    add_time_to_events,
    deduplicate_events,
    fetch_events_command,
    fetch_events_with_pagination,
    generate_telemetry_header,
    get_events_command,
    get_formatted_time,
    parse_date_or_use_current,
    parse_integration_params,
    test_module,
)

# ========================================
# Constants
# ========================================

SERVER_URL = "https://audit-api.cyberark.cloud"
IDENTITY_URL = "https://tenant.cyberark.cloud"
WEB_APP_ID = "test-web-app-id"
TOKEN_URL = f"{IDENTITY_URL}/OAuth2/Token/{WEB_APP_ID}"
TEST_DATA_PATH_SUFFIX = "test_data"
INTEGRATION_DIR_REL = "Packs/CyberArkPAS/Integrations/CyberArkISP/"

MOCK_CLIENT_ID = "test-client-id"
MOCK_CLIENT_SECRET = "test-client-secret"
MOCK_API_KEY = "test-api-key-12345"
MOCK_ACCESS_TOKEN = "mock_access_token_12345"


# ========================================
# Helper Functions
# ========================================


def get_full_path_unified(file_name):
    """Calculates the full path for a file in the test_data folder."""
    path = os.path.join(os.path.dirname(__file__), TEST_DATA_PATH_SUFFIX, file_name)

    if not os.path.exists(path):
        fallback_path = os.path.join(os.getcwd(), INTEGRATION_DIR_REL, TEST_DATA_PATH_SUFFIX, file_name)
        if os.path.exists(fallback_path):
            path = fallback_path

    if not os.path.exists(path):
        raise FileNotFoundError(f"Mock file not found: {file_name} in {TEST_DATA_PATH_SUFFIX}.")

    return path


def util_load_json(file_name):
    """Loads a JSON file from the test_data directory."""
    path = get_full_path_unified(file_name)
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


# ========================================
# Fixtures
# ========================================


@pytest.fixture()
def client(mocker):
    """Returns a mocked Client instance for testing.

    This fixture provides a default client that can be used by any test,
    including the test_module function from CyberArkISP.py that pytest discovers.
    The client is mocked to prevent actual HTTP requests.
    """
    client_instance = Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        api_key=MOCK_API_KEY,
        verify=True,
        proxy=False,
    )

    # Mock the methods that make HTTP requests to prevent actual network calls
    mocker.patch.object(client_instance, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(client_instance, "create_stream_query", return_value="test_cursor")
    mocker.patch.object(client_instance, "get_stream_results", return_value=([], None))

    return client_instance


@pytest.fixture
def mock_context():
    """Fixture to ensure integration context is initialized and cleaned up."""
    set_integration_context({})
    yield
    set_integration_context({})


# ========================================
# Tests: Helper Functions
# ========================================


@pytest.mark.parametrize(
    "date_string,expected_type",
    [
        ("2024-01-01T00:00:00Z", datetime),
        ("2025-09-15 17:10:00", datetime),
        ("3 days ago", datetime),
        ("1 week", datetime),
        (None, datetime),
        ("", datetime),
    ],
)
def test_parse_date_or_use_current_success(date_string, expected_type):
    """Tests parse_date_or_use_current returns datetime for valid inputs."""
    result = parse_date_or_use_current(date_string)
    assert isinstance(result, expected_type)
    assert result.tzinfo == timezone.utc  # noqa: UP017


def test_parse_date_or_use_current_invalid_returns_current():
    """Tests parse_date_or_use_current returns current time for invalid date."""
    before = datetime.now(timezone.utc)  # noqa: UP017
    result = parse_date_or_use_current("invalid_date_string_12345")
    after = datetime.now(timezone.utc)  # noqa: UP017
    assert before <= result <= after


@pytest.mark.parametrize(
    "date_input,expected_format_pattern",
    [
        ("2024-01-01T00:00:00Z", r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"),
        ("3 days ago", r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"),
        (None, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"),
    ],
)
def test_get_formatted_time(date_input, expected_format_pattern):
    """Tests get_formatted_time returns properly formatted string."""
    import re

    result = get_formatted_time(date_input)
    assert isinstance(result, str)
    assert re.match(expected_format_pattern, result)


def test_generate_telemetry_header():
    """Tests generate_telemetry_header returns base64 encoded string."""
    import base64

    result = generate_telemetry_header()
    assert isinstance(result, str)

    # Verify it's valid base64
    decoded = base64.b64decode(result).decode()
    assert "CyberArk Identity Security Platform" in decoded
    assert "SIEM" in decoded
    assert "Palo Alto Networks" in decoded


# ========================================
# Tests: parse_integration_params
# ========================================


@pytest.mark.parametrize(
    "params,expected_error",
    [
        ({}, r"(?i)server url is required"),
        ({"url": ""}, r"(?i)server url is required"),
        ({"url": SERVER_URL}, r"(?i)identity url is required"),
        ({"url": SERVER_URL, "identity_url": ""}, r"(?i)identity url is required"),
        ({"url": SERVER_URL, "identity_url": IDENTITY_URL}, r"(?i)oauth2 web app id is required"),
        ({"url": SERVER_URL, "identity_url": IDENTITY_URL, "web_app_id": ""}, r"(?i)oauth2 web app id is required"),
        (
            {"url": SERVER_URL, "identity_url": IDENTITY_URL, "web_app_id": WEB_APP_ID},
            r"(?i)client id is required",
        ),
        (
            {"url": SERVER_URL, "identity_url": IDENTITY_URL, "web_app_id": WEB_APP_ID, "client_id": ""},
            r"(?i)client id is required",
        ),
        (
            {
                "url": SERVER_URL,
                "identity_url": IDENTITY_URL,
                "web_app_id": WEB_APP_ID,
                "client_id": MOCK_CLIENT_ID,
            },
            r"(?i)client secret is required",
        ),
        (
            {
                "url": SERVER_URL,
                "identity_url": IDENTITY_URL,
                "web_app_id": WEB_APP_ID,
                "client_id": MOCK_CLIENT_ID,
                "client_secret": {"password": ""},
            },
            r"(?i)client secret is required",
        ),
        (
            {
                "url": SERVER_URL,
                "identity_url": IDENTITY_URL,
                "web_app_id": WEB_APP_ID,
                "client_id": MOCK_CLIENT_ID,
                "client_secret": {"password": MOCK_CLIENT_SECRET},
            },
            r"(?i)api key is required",
        ),
    ],
)
def test_parse_integration_params_missing_required_fail(params, expected_error):
    """Tests parse_integration_params fails if required fields are missing."""
    with pytest.raises(DemistoException, match=expected_error):
        parse_integration_params(params)


@pytest.mark.parametrize(
    "params,expected_verify,expected_proxy",
    [
        (
            {
                "url": SERVER_URL,
                "identity_url": IDENTITY_URL,
                "web_app_id": WEB_APP_ID,
                "client_id": MOCK_CLIENT_ID,
                "client_secret": {"password": MOCK_CLIENT_SECRET},
                "api_key": MOCK_API_KEY,
                "insecure": True,
                "proxy": True,
            },
            False,
            True,
        ),
        (
            {
                "url": f"{SERVER_URL}/",
                "identity_url": f"{IDENTITY_URL}/",
                "web_app_id": WEB_APP_ID,
                "client_id": MOCK_CLIENT_ID,
                "client_secret": {"password": MOCK_CLIENT_SECRET},
                "api_key": MOCK_API_KEY,
                "insecure": False,
                "proxy": False,
            },
            True,
            False,
        ),
    ],
)
def test_parse_integration_params_success(params, expected_verify, expected_proxy):
    """Tests parse_integration_params handles valid configurations."""
    result = parse_integration_params(params)

    assert result["base_url"] == SERVER_URL
    assert result["token_url"] == TOKEN_URL
    assert result["verify"] == expected_verify
    assert result["proxy"] == expected_proxy
    assert result["client_id"] == MOCK_CLIENT_ID
    assert result["client_secret"] == MOCK_CLIENT_SECRET
    assert result["api_key"] == MOCK_API_KEY


# ========================================
# Tests: Client Initialization
# ========================================


def test_client_initialization(client):
    """Tests Client initialization."""
    assert client.client_id == MOCK_CLIENT_ID
    assert client.client_secret == MOCK_CLIENT_SECRET
    assert client.api_key == MOCK_API_KEY
    assert client.token_url == TOKEN_URL
    assert client._base_url == f"{SERVER_URL}/"
    assert isinstance(client.telemetry_header, str)


# ========================================
# Tests: Token Management
# ========================================


def test_get_access_token_uses_cached_token(mocker, mock_context, client):
    """Tests _get_access_token uses valid token from cache."""
    mock_time = int(time.time()) + 3600
    set_integration_context({ContextKeys.ACCESS_TOKEN.value: "CACHED_TOKEN", ContextKeys.VALID_UNTIL.value: str(mock_time)})

    mocker.patch.object(CyberArkISP.time, "time", return_value=int(time.time()) + 10)

    # Stop all mocks from fixture and test cache-only logic
    mocker.stopall()

    # Recreate client without mocks
    client_instance = Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        api_key=MOCK_API_KEY,
        verify=True,
        proxy=False,
    )

    token = client_instance._get_access_token()
    assert token == "CACHED_TOKEN"


def test_get_access_token_expired_renewal(mocker, mock_context, client):
    """Tests token renewal when cache is expired."""
    mock_time = int(time.time()) - 3600
    set_integration_context({ContextKeys.ACCESS_TOKEN.value: "EXPIRED_TOKEN", ContextKeys.VALID_UNTIL.value: str(mock_time)})

    # Stop fixture mocks
    mocker.stopall()

    # Recreate client and mock _http_request
    client_instance = Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        api_key=MOCK_API_KEY,
        verify=True,
        proxy=False,
    )

    mocker.patch.object(
        client_instance,
        "_http_request",
        return_value={ContextKeys.ACCESS_TOKEN.value: MOCK_ACCESS_TOKEN, ContextKeys.EXPIRES_IN.value: 3600},
    )

    token = client_instance._get_access_token()

    assert token == MOCK_ACCESS_TOKEN
    assert get_integration_context().get(ContextKeys.ACCESS_TOKEN.value) == MOCK_ACCESS_TOKEN


def test_get_access_token_invalid_cache_renewal(mocker, mock_context, client):
    """Tests token renewal when cache has invalid expiration value."""
    set_integration_context({ContextKeys.ACCESS_TOKEN.value: "BAD_TOKEN", ContextKeys.VALID_UNTIL.value: "NOT_A_NUMBER"})

    # Stop fixture mocks
    mocker.stopall()

    # Recreate client and mock _http_request
    client_instance = Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        api_key=MOCK_API_KEY,
        verify=True,
        proxy=False,
    )

    mocker.patch.object(
        client_instance,
        "_http_request",
        return_value={ContextKeys.ACCESS_TOKEN.value: MOCK_ACCESS_TOKEN, ContextKeys.EXPIRES_IN.value: 3600},
    )

    token = client_instance._get_access_token()
    assert token == MOCK_ACCESS_TOKEN


@pytest.mark.parametrize(
    "mock_response,expected_error",
    [
        ({"error": "failed"}, r"(?i)failed to obtain access token"),
        ({}, r"(?i)response missing access_token"),
    ],
)
def test_get_access_token_failure_cases(mocker, mock_context, client, mock_response, expected_error):
    """Tests token request failures for various error conditions."""
    # Stop fixture mocks
    mocker.stopall()

    # Recreate client and mock _http_request
    client_instance = Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        api_key=MOCK_API_KEY,
        verify=True,
        proxy=False,
    )

    mocker.patch.object(client_instance, "_http_request", return_value=mock_response)

    with pytest.raises(DemistoException, match=expected_error):
        client_instance._get_access_token()


def test_get_access_token_http_error(mocker, mock_context, client, capfd):
    """Tests token request handles HTTP errors."""
    # Stop fixture mocks
    mocker.stopall()

    # Recreate client and mock _http_request
    client_instance = Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        api_key=MOCK_API_KEY,
        verify=True,
        proxy=False,
    )

    mocker.patch.object(client_instance, "_http_request", side_effect=DemistoException("HTTP Error 500"))

    with capfd.disabled(), pytest.raises(DemistoException, match=r"(?i)failed to obtain access token"):
        client_instance._get_access_token()


# ========================================
# Tests: HTTP Request Methods
# ========================================


@pytest.mark.parametrize(
    "status_code,json_data,json_error,return_full_response,expected_result,should_fail,expected_error",
    [
        (200, {"data": "success"}, None, False, {"data": "success"}, False, None),
        (
            200,
            {"data": "success"},
            None,
            True,
            ({"data": "success"}, {"Content-Type": "application/json"}),
            False,
            None,
        ),
        (204, None, None, False, {}, False, None),
        (
            200,
            None,
            ValueError("Invalid JSON"),
            False,
            None,
            True,
            r"(?i)api returned non-json response",
        ),
    ],
)
def test_http_request(
    mocker,
    client,
    status_code,
    json_data,
    json_error,
    return_full_response,
    expected_result,
    should_fail,
    expected_error,
):
    """Tests http_request handles various response scenarios."""
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)

    mock_response = mocker.Mock()
    mock_response.status_code = status_code
    mock_response.headers = {"Content-Type": "application/json"}

    if json_error:
        mock_response.json.side_effect = json_error
        mock_response.text = "Not a JSON response"
    else:
        mock_response.json.return_value = json_data

    mocker.patch.object(client, "_http_request", return_value=mock_response)

    if should_fail:
        with pytest.raises(DemistoException, match=expected_error):
            client.http_request("GET", "/test", return_full_response=return_full_response)
    else:
        result = client.http_request("GET", "/test", return_full_response=return_full_response)
        assert result == expected_result


@pytest.mark.parametrize(
    "error_code,error_message",
    [
        ("401", "Error [401] - Unauthorized"),
        ("403", "Error [403] - Forbidden"),
    ],
)
def test_http_request_auth_error_handling(mocker, capfd, client, error_code, error_message):
    """Tests http_request properly handles 401/403 authentication errors."""
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(client, "_http_request", side_effect=DemistoException(error_message))

    with capfd.disabled(), pytest.raises(DemistoException, match=r"(?i)authentication error"):
        client.http_request("GET", "/test")


def test_http_request_retries_on_server_errors(mocker, client):
    """Tests http_request uses retries and backoff for server errors."""
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)

    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "success"}
    mock_response.headers = {}

    mock_http = mocker.patch.object(client, "_http_request", return_value=mock_response)

    client.http_request("GET", "/test")

    call_kwargs = mock_http.call_args[1]
    assert call_kwargs.get("retries") == 3
    assert call_kwargs.get("backoff_factor") == 2


# ========================================
# Tests: create_stream_query
# ========================================


@pytest.mark.parametrize(
    "date_from,date_to,expected_filter_keys",
    [
        ("2024-01-01 00:00:00", None, [APIKeys.DATE_FROM.value]),
        ("2024-01-01 00:00:00", "2024-01-02 00:00:00", [APIKeys.DATE_FROM.value, APIKeys.DATE_TO.value]),
    ],
)
def test_create_stream_query_success(mocker, client, date_from, date_to, expected_filter_keys):
    """Tests create_stream_query creates query with correct parameters."""
    mock_response = {APIKeys.CURSOR_REF.value: "test_cursor_ref_12345"}

    # Stop fixture mocks and recreate client
    mocker.stopall()
    client_instance = Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        api_key=MOCK_API_KEY,
        verify=True,
        proxy=False,
    )

    mock_http_request = mocker.patch.object(client_instance, "http_request", return_value=mock_response)

    cursor_ref = client_instance.create_stream_query(date_from, date_to)

    assert cursor_ref == "test_cursor_ref_12345"

    call_args = mock_http_request.call_args
    assert call_args[1]["method"] == "POST"
    assert call_args[1]["url_suffix"] == APIValues.CREATE_QUERY_ENDPOINT.value

    json_data = call_args[1]["json_data"]
    assert APIKeys.FILTER_MODEL.value in json_data
    assert APIKeys.SORT_MODEL.value in json_data

    filter_model = json_data[APIKeys.FILTER_MODEL.value]
    for key in expected_filter_keys:
        assert key in filter_model


def test_create_stream_query_missing_cursor_ref(mocker, client):
    """Tests create_stream_query fails when response missing cursorRef."""
    # Stop fixture mocks and recreate client
    mocker.stopall()
    client_instance = Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        api_key=MOCK_API_KEY,
        verify=True,
        proxy=False,
    )

    mocker.patch.object(client_instance, "http_request", return_value={})

    with pytest.raises(DemistoException, match=r"(?i)response missing cursorref"):
        client_instance.create_stream_query("2024-01-01 00:00:00")


# ========================================
# Tests: get_stream_results
# ========================================


@pytest.mark.parametrize(
    "response_data,expected_event_count,expected_next_cursor",
    [
        (
            {
                APIKeys.DATA.value: [{"uuid": "1"}, {"uuid": "2"}],
                APIKeys.PAGING.value: {APIKeys.CURSOR.value: {APIKeys.CURSOR_REF.value: "next_cursor"}},
            },
            2,
            "next_cursor",
        ),
        (
            {APIKeys.DATA.value: [{"uuid": "1"}], APIKeys.PAGING.value: {}},
            1,
            None,
        ),
        (
            {APIKeys.DATA.value: []},
            0,
            None,
        ),
    ],
)
def test_get_stream_results_scenarios(mocker, client, response_data, expected_event_count, expected_next_cursor):
    """Tests get_stream_results handles various response scenarios."""
    # Stop fixture mocks and recreate client
    mocker.stopall()
    client_instance = Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        api_key=MOCK_API_KEY,
        verify=True,
        proxy=False,
    )

    mocker.patch.object(client_instance, "http_request", return_value=response_data)

    events, next_cursor = client_instance.get_stream_results("test_cursor")

    assert len(events) == expected_event_count
    assert next_cursor == expected_next_cursor


# ========================================
# Tests: fetch_events_with_pagination
# ========================================


def test_fetch_events_with_pagination_single_page(mocker, client):
    """Tests fetch_events_with_pagination with single page of results."""
    mock_events = [{"uuid": f"event{i}", "timestamp": 1000 * i} for i in range(1, 4)]

    mocker.patch.object(client, "create_stream_query", return_value="cursor1")
    mocker.patch.object(client, "get_stream_results", return_value=(mock_events, None))

    events = fetch_events_with_pagination(client, "2024-01-01 00:00:00", None, 10)

    assert len(events) == 3
    assert events[0]["uuid"] == "event1"


def test_fetch_events_with_pagination_multiple_pages(mocker, client):
    """Tests fetch_events_with_pagination handles multiple pages."""
    page1 = [{"uuid": f"event{i}", "timestamp": 1000 * i} for i in range(1, 6)]
    page2 = [{"uuid": f"event{i}", "timestamp": 1000 * i} for i in range(6, 11)]

    mocker.patch.object(client, "create_stream_query", return_value="cursor1")
    mocker.patch.object(
        client,
        "get_stream_results",
        side_effect=[(page1, "cursor2"), (page2, None)],
    )

    events = fetch_events_with_pagination(client, "2024-01-01 00:00:00", None, 10)

    assert len(events) == 10
    assert client.get_stream_results.call_count == 2


def test_fetch_events_with_pagination_stops_at_max(mocker, client):
    """Tests fetch_events_with_pagination stops at max_events."""
    page1 = [{"uuid": f"event{i}", "timestamp": 1000 * i} for i in range(1, 6)]
    page2 = [{"uuid": f"event{i}", "timestamp": 1000 * i} for i in range(6, 9)]

    mocker.patch.object(client, "create_stream_query", return_value="cursor1")
    mocker.patch.object(
        client,
        "get_stream_results",
        side_effect=[(page1, "cursor2"), (page2, None)],
    )

    events = fetch_events_with_pagination(client, "2024-01-01 00:00:00", None, 7)

    assert len(events) == 7


def test_fetch_events_with_pagination_empty_page(mocker, client):
    """Tests fetch_events_with_pagination handles empty page."""
    mocker.patch.object(client, "create_stream_query", return_value="cursor1")
    mocker.patch.object(client, "get_stream_results", return_value=([], None))

    events = fetch_events_with_pagination(client, "2024-01-01 00:00:00", None, 10)

    assert len(events) == 0


def test_fetch_events_with_pagination_exact_limit_reached(mocker, client):
    """Tests fetch_events_with_pagination stops when exactly max_events is reached."""
    page1 = [{"uuid": f"event{i}", "timestamp": 1000 * i} for i in range(1, 11)]

    mocker.patch.object(client, "create_stream_query", return_value="cursor1")
    mocker.patch.object(
        client,
        "get_stream_results",
        return_value=(page1, "cursor_exists_but_should_not_fetch"),
    )

    events = fetch_events_with_pagination(client, "2024-01-01 00:00:00", None, 10)

    assert len(events) == 10
    assert client.get_stream_results.call_count == 1


def test_fetch_events_with_pagination_slices_excess_events(mocker, client):
    """Tests fetch_events_with_pagination slices excess events."""
    page1 = [{"uuid": f"event{i}", "timestamp": 1000 * i} for i in range(1, 11)]
    page2 = [{"uuid": f"event{i}", "timestamp": 1000 * i} for i in range(11, 16)]

    mocker.patch.object(client, "create_stream_query", return_value="cursor1")
    mocker.patch.object(
        client,
        "get_stream_results",
        side_effect=[(page1, "cursor2"), (page2, None)],
    )

    events = fetch_events_with_pagination(client, "2024-01-01 00:00:00", None, 12)

    assert len(events) == 12
    assert events[0]["uuid"] == "event1"
    assert events[-1]["uuid"] == "event12"


@pytest.mark.parametrize(
    "date_from,date_to",
    [
        ("2024-01-01 00:00:00", None),
        ("2024-01-01 00:00:00", "2024-01-02 00:00:00"),
    ],
)
def test_fetch_events_with_pagination_date_parameters(mocker, client, date_from, date_to):
    """Tests fetch_events_with_pagination passes date parameters correctly."""
    mocker.patch.object(client, "create_stream_query", return_value="cursor1")
    mocker.patch.object(client, "get_stream_results", return_value=([], None))

    fetch_events_with_pagination(client, date_from, date_to, 10)

    call_args = client.create_stream_query.call_args
    assert call_args.kwargs["date_from"] == date_from
    assert call_args.kwargs["date_to"] == date_to


# ========================================
# Tests: add_time_to_events
# ========================================


@pytest.mark.parametrize(
    "input_events,expected_results",
    [
        (
            [
                {"uuid": "1", "timestamp": 1704067200000, "user": "test@example.com"},
                {"uuid": "2", "timestamp": 1704153600000, "action": "login"},
            ],
            [
                {"uuid": "1", "timestamp": 1704067200000, "user": "test@example.com", "_time": 1704067200000},
                {"uuid": "2", "timestamp": 1704153600000, "action": "login", "_time": 1704153600000},
            ],
        ),
        (
            [
                {"uuid": "1", "user": "test@example.com"},
                {"uuid": "2", "action": "login"},
            ],
            [
                {"uuid": "1", "user": "test@example.com"},
                {"uuid": "2", "action": "login"},
            ],
        ),
        ([], []),
        (
            [
                {"uuid": "1", "timestamp": 1704067200000},
                {"uuid": "2", "timestamp": 1704153600000},
                {"uuid": "3"},
            ],
            [
                {"uuid": "1", "timestamp": 1704067200000, "_time": 1704067200000},
                {"uuid": "2", "timestamp": 1704153600000, "_time": 1704153600000},
                {"uuid": "3"},
            ],
        ),
    ],
)
def test_add_time_to_events(input_events, expected_results):
    """Tests add_time_to_events copies timestamp field to _time."""
    add_time_to_events(input_events)
    assert input_events == expected_results


def test_add_time_to_events_preserves_all_fields():
    """Tests add_time_to_events preserves all other event fields."""
    events = [
        {
            "uuid": "123",
            "timestamp": 1704067200000,
            "user": "test@example.com",
            "action": "login",
            "ip": "192.168.1.1",
        }
    ]

    add_time_to_events(events)

    assert events[0]["uuid"] == "123"
    assert events[0]["timestamp"] == 1704067200000
    assert events[0]["user"] == "test@example.com"
    assert events[0]["action"] == "login"
    assert events[0]["ip"] == "192.168.1.1"
    assert events[0]["_time"] == 1704067200000


# ========================================
# Tests: deduplicate_events
# ========================================


@pytest.mark.parametrize(
    "events,last_fetched_uuids,expected_count,expected_first_uuid,description",
    [
        (
            [{"uuid": "1", "timestamp": 1000}, {"uuid": "2", "timestamp": 2000}],
            None,
            2,
            "1",
            "first_run_no_last_uuids_none",
        ),
        (
            [{"uuid": "1", "timestamp": 1000}, {"uuid": "2", "timestamp": 2000}],
            [],
            2,
            "1",
            "first_run_no_last_uuids_empty",
        ),
        ([], ["last_uuid"], 0, None, "empty_events"),
        (
            [
                {"uuid": "1", "timestamp": 1000},
                {"uuid": "2", "timestamp": 2000},
                {"uuid": "3", "timestamp": 3000},
            ],
            ["1"],
            2,
            "2",
            "single_uuid_filtered",
        ),
        (
            [
                {"uuid": "1", "timestamp": 1000},
                {"uuid": "2", "timestamp": 2000},
                {"uuid": "3", "timestamp": 3000},
            ],
            ["1", "2"],
            1,
            "3",
            "multiple_uuids_filtered",
        ),
        (
            [
                {"uuid": "1", "timestamp": 1000},
                {"uuid": "2", "timestamp": 2000},
                {"uuid": "3", "timestamp": 3000},
            ],
            ["1", "2", "3"],
            0,
            None,
            "all_duplicates",
        ),
        (
            [
                {"uuid": "4", "timestamp": 4000},
                {"uuid": "5", "timestamp": 5000},
            ],
            ["1", "2", "3"],
            2,
            "4",
            "no_matches_all_new",
        ),
        (
            [
                {"timestamp": 1000, "data": "event1"},
                {"uuid": "2", "timestamp": 2000},
            ],
            ["1"],
            2,
            None,
            "events_without_uuid",
        ),
    ],
)
def test_deduplicate_events(events, last_fetched_uuids, expected_count, expected_first_uuid, description):
    """Tests deduplicate_events function with various scenarios."""
    result = deduplicate_events(events, last_fetched_uuids)

    assert len(result) == expected_count, f"Failed for {description}"
    if expected_first_uuid:
        assert result[0]["uuid"] == expected_first_uuid


def test_deduplicate_events_preserves_order():
    """Tests that deduplicate_events preserves event order."""
    events = [
        {"uuid": "1", "timestamp": 1000, "data": "first"},
        {"uuid": "2", "timestamp": 2000, "data": "second"},
        {"uuid": "3", "timestamp": 3000, "data": "third"},
        {"uuid": "4", "timestamp": 4000, "data": "fourth"},
    ]

    result = deduplicate_events(events, ["1", "2"])

    assert len(result) == 2
    assert result[0]["uuid"] == "3"
    assert result[0]["data"] == "third"
    assert result[1]["uuid"] == "4"
    assert result[1]["data"] == "fourth"


# ========================================
# Tests: test_module Command
# ========================================


@pytest.mark.parametrize(
    "should_succeed,mock_return,mock_exception,expected_result",
    [
        (True, [{"uuid": "test"}], None, "ok"),
        (
            False,
            None,
            DemistoException("Error [401] - Unauthorized"),
            r"(?i)authorization error",
        ),
        (
            False,
            None,
            DemistoException("Error [403] - Forbidden"),
            r"(?i)authorization error",
        ),
        (False, None, DemistoException("Error [500] - Internal Server Error"), None),
    ],
)
def test_test_module_command(mocker, client, should_succeed, mock_return, mock_exception, expected_result):
    """Tests test_module returns 'ok' on success, auth error message for 401/403, or raises other errors."""
    # Mock the specific methods called by test_module to prevent actual API calls
    mocker.patch.object(client, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(client, "create_stream_query", return_value="test_cursor")
    mocker.patch.object(client, "get_stream_results", return_value=([], None))

    if should_succeed:
        mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=mock_return)
        result = test_module(client)
        assert result == expected_result
    elif expected_result:
        mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", side_effect=mock_exception)
        result = test_module(client)
        assert re.match(expected_result, result, re.IGNORECASE)
    else:
        mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", side_effect=mock_exception)
        with pytest.raises(DemistoException, match=r"(?i)internal server error"):
            test_module(client)


# ========================================
# Tests: get_events_command
# ========================================


def test_get_events_command_success(mocker, client):
    """Tests get_events_command returns correct CommandResults when should_push_events=False."""
    mock_events = [{"uuid": "123", "user": "test@example.com", "timestamp": 1704067200000}]

    mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=mock_events)

    args = {"date_from": "3 days ago", "limit": "10", "should_push_events": "false"}
    result = get_events_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "CyberArkISP.Event"
    assert result.outputs_key_field == "uuid"
    assert result.outputs == mock_events


def test_get_events_command_with_push_events(mocker, client):
    """Tests get_events_command pushes events to XSIAM when should_push_events=True."""
    mock_events = [{"uuid": "123", "user": "test@example.com", "timestamp": 1704067200000}]

    mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(CyberArkISP, "add_time_to_events")
    mocker.patch.object(CyberArkISP, "send_events_to_xsiam")

    args = {"date_from": "3 days ago", "limit": "10", "should_push_events": "true"}
    result = get_events_command(client, args)

    assert isinstance(result, str)
    assert "1 events" in result.lower()
    CyberArkISP.add_time_to_events.assert_called_once_with(mock_events)  # type: ignore[attr-defined]
    CyberArkISP.send_events_to_xsiam.assert_called_once_with(  # type: ignore[attr-defined]
        events=mock_events, vendor=Config.VENDOR, product=Config.PRODUCT
    )


def test_get_events_command_default_values(mocker, client):
    """Tests get_events_command uses default values."""
    mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=[])

    result = get_events_command(client, {})

    assert isinstance(result, CommandResults)
    assert result.outputs == []


def test_get_events_command_with_date_to(mocker, client):
    """Tests get_events_command handles date_to parameter."""
    mock_fetch = mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=[])

    args = {"date_from": "1 hour ago", "date_to": "now", "should_push_events": "false"}
    result = get_events_command(client, args)

    assert isinstance(result, CommandResults)
    call_args = mock_fetch.call_args
    assert call_args[0][2] is not None  # date_to


# ========================================
# Tests: fetch_events_command
# ========================================


@pytest.mark.parametrize(
    "test_case,last_run,params,mock_events,expected_last_run,expected_events_sent",
    [
        (
            "first_run",
            {},
            {"max_fetch": 100},
            [{"uuid": "1", "timestamp": 1704067200000}, {"uuid": "2", "timestamp": 1704153600000}],
            {"last_fetch": "2024-01-02 00:00:00", "last_fetched_uuids": ["2"]},
            [{"uuid": "1", "timestamp": 1704067200000}, {"uuid": "2", "timestamp": 1704153600000}],
        ),
        (
            "with_last_run",
            {"last_fetch": "2024-01-01 00:00:00", "last_fetched_uuids": []},
            {"max_fetch": 100},
            [{"uuid": "3", "timestamp": 1704240000000}],
            {"last_fetch": "2024-01-03 00:00:00", "last_fetched_uuids": ["3"]},
            [{"uuid": "3", "timestamp": 1704240000000}],
        ),
        (
            "multiple_events_same_timestamp",
            {},
            {"max_fetch": 100},
            [
                {"uuid": "1", "timestamp": 1704067200000},
                {"uuid": "2", "timestamp": 1704067200000},
                {"uuid": "3", "timestamp": 1704067200000},
            ],
            {"last_fetch": "2024-01-01 00:00:00", "last_fetched_uuids": ["1", "2", "3"]},
            [
                {"uuid": "1", "timestamp": 1704067200000},
                {"uuid": "2", "timestamp": 1704067200000},
                {"uuid": "3", "timestamp": 1704067200000},
            ],
        ),
    ],
)
def test_fetch_events_command_scenarios(
    mocker, client, test_case, last_run, params, mock_events, expected_last_run, expected_events_sent
):
    """Tests fetch_events_command under various scenarios."""
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(CyberArkISP, "add_time_to_events")
    mocker.patch.object(CyberArkISP, "send_events_to_xsiam")

    fetch_events_command(client)

    demisto.setLastRun.assert_called_once_with(expected_last_run)  # type: ignore[attr-defined]
    CyberArkISP.add_time_to_events.assert_called_once_with(expected_events_sent)  # type: ignore[attr-defined]
    CyberArkISP.send_events_to_xsiam.assert_called_once_with(  # type: ignore[attr-defined]
        events=expected_events_sent, vendor=Config.VENDOR, product=Config.PRODUCT
    )


def test_fetch_events_command_with_deduplication(mocker, client):
    """Tests fetch_events_command deduplicates events based on last_fetched_uuids."""
    mock_events = [
        {"uuid": "1", "timestamp": 1704067200000},
        {"uuid": "2", "timestamp": 1704067200000},
        {"uuid": "3", "timestamp": 1704153600000},
    ]

    mocker.patch.object(
        demisto, "getLastRun", return_value={"last_fetch": "2024-01-01 00:00:00", "last_fetched_uuids": ["1", "2"]}
    )
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 100})
    mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(CyberArkISP, "add_time_to_events")
    mocker.patch.object(CyberArkISP, "send_events_to_xsiam")

    fetch_events_command(client)

    CyberArkISP.add_time_to_events.assert_called_once_with([{"uuid": "3", "timestamp": 1704153600000}])  # type: ignore[attr-defined]
    demisto.setLastRun.assert_called_once_with({"last_fetch": "2024-01-02 00:00:00", "last_fetched_uuids": ["3"]})  # type: ignore[attr-defined]


def test_fetch_events_command_all_duplicates(mocker, client):
    """Tests fetch_events_command when all fetched events are duplicates."""
    mock_events = [
        {"uuid": "1", "timestamp": 1704067200000},
        {"uuid": "2", "timestamp": 1704067200000},
    ]

    mocker.patch.object(
        demisto, "getLastRun", return_value={"last_fetch": "2024-01-01 00:00:00", "last_fetched_uuids": ["1", "2"]}
    )
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 100})
    mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(CyberArkISP, "add_time_to_events")
    mocker.patch.object(CyberArkISP, "send_events_to_xsiam")

    fetch_events_command(client)

    CyberArkISP.add_time_to_events.assert_not_called()  # type: ignore[attr-defined]
    CyberArkISP.send_events_to_xsiam.assert_not_called()  # type: ignore[attr-defined]
    demisto.setLastRun.assert_not_called()  # type: ignore[attr-defined]


def test_fetch_events_command_no_events(mocker, client):
    """Tests fetch_events_command when no events are fetched."""
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=[])
    mocker.patch.object(CyberArkISP, "send_events_to_xsiam")

    fetch_events_command(client)

    CyberArkISP.send_events_to_xsiam.assert_not_called()  # type: ignore[attr-defined]
    demisto.setLastRun.assert_not_called()  # type: ignore[attr-defined]


def test_fetch_events_command_timestamp_conversion_error(mocker, client):
    """Tests fetch_events_command handles timestamp conversion errors."""
    mock_events = [{"uuid": "1", "timestamp": "invalid"}]

    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(CyberArkISP, "add_time_to_events")
    mocker.patch.object(CyberArkISP, "send_events_to_xsiam")

    fetch_events_command(client)

    demisto.setLastRun.assert_called_once()  # type: ignore[attr-defined]
    call_args = demisto.setLastRun.call_args[0][0]  # type: ignore[attr-defined]
    assert call_args["last_fetch"] == "invalid"


# ========================================
# Tests: Main Function
# ========================================


def test_main_invalid_command_fail(mocker, capfd):
    """Tests main() raises error for invalid command."""
    with capfd.disabled():
        mocker.patch.object(demisto, "command", return_value="invalid-command")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": SERVER_URL,
                "identity_url": IDENTITY_URL,
                "web_app_id": WEB_APP_ID,
                "client_id": MOCK_CLIENT_ID,
                "client_secret": {"password": MOCK_CLIENT_SECRET},
                "api_key": MOCK_API_KEY,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})

        mock_return_error = mocker.patch("CyberArkISP.return_error")

        CyberArkISP.main()

        mock_return_error.assert_called_once()
        error_call_args = mock_return_error.call_args[0][0]
        assert re.search(r"invalid-command", error_call_args, re.IGNORECASE)
        assert re.search(r"not implemented", error_call_args, re.IGNORECASE)


def test_main_test_module_success(mocker):
    """Tests main() executes test-module command successfully."""
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "identity_url": IDENTITY_URL,
            "web_app_id": WEB_APP_ID,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": {"password": MOCK_CLIENT_SECRET},
            "api_key": MOCK_API_KEY,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=[])

    mock_return_results = mocker.patch("CyberArkISP.return_results")

    CyberArkISP.main()

    mock_return_results.assert_called_once_with("ok")


def test_main_get_events_success(mocker):
    """Tests main() executes cyberark-isp-get-events command successfully."""
    mocker.patch.object(demisto, "command", return_value="cyberark-isp-get-events")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "identity_url": IDENTITY_URL,
            "web_app_id": WEB_APP_ID,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": {"password": MOCK_CLIENT_SECRET},
            "api_key": MOCK_API_KEY,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=[])

    mock_return_results = mocker.patch("CyberArkISP.return_results")

    CyberArkISP.main()

    mock_return_results.assert_called_once()


def test_main_fetch_events_success(mocker):
    """Tests main() executes fetch-events command successfully."""
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "identity_url": IDENTITY_URL,
            "web_app_id": WEB_APP_ID,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": {"password": MOCK_CLIENT_SECRET},
            "api_key": MOCK_API_KEY,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", return_value=[])

    CyberArkISP.main()


def test_main_command_execution_error(mocker, capfd):
    """Tests main() handles command execution errors gracefully."""
    with capfd.disabled():
        mocker.patch.object(demisto, "command", return_value="cyberark-isp-get-events")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": SERVER_URL,
                "identity_url": IDENTITY_URL,
                "web_app_id": WEB_APP_ID,
                "client_id": MOCK_CLIENT_ID,
                "client_secret": {"password": MOCK_CLIENT_SECRET},
                "api_key": MOCK_API_KEY,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(CyberArkISP, "fetch_events_with_pagination", side_effect=Exception("API Error"))

        mock_return_error = mocker.patch("CyberArkISP.return_error")

        CyberArkISP.main()

        mock_return_error.assert_called_once()
        error_message = mock_return_error.call_args[0][0]
        assert re.search(r"cyberark-isp-get-events", error_message, re.IGNORECASE)


@pytest.mark.parametrize(
    "command_name,expected_in_map",
    [
        ("test-module", True),
        ("cyberark-isp-get-events", True),
        ("fetch-events", True),
        ("non-existent-command", False),
        ("", False),
    ],
)
def test_command_map_completeness(command_name, expected_in_map):
    """Tests that COMMAND_MAP contains all expected commands."""
    assert (command_name in CyberArkISP.COMMAND_MAP) == expected_in_map


def test_main_parse_params_error(mocker, capfd):
    """Tests main() handles parameter parsing errors."""
    with capfd.disabled():
        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "args", return_value={})

        mock_return_error = mocker.patch("CyberArkISP.return_error")

        CyberArkISP.main()

        mock_return_error.assert_called_once()
        error_message = mock_return_error.call_args[0][0]
        assert re.search(r"server url is required", error_message, re.IGNORECASE)
