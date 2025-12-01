import json
import os
import time
from datetime import datetime

import pytest
from CommonServerPython import *

# Import SAPBTP after CommonServerPython
import SAPBTP  # noqa: E402
from SAPBTP import (  # noqa: E402
    AuthType,
    Client,
    ContextKeys,
    IntegrationConfig,
    create_mtls_cert_files,
    fetch_events_command,
    fetch_events_with_pagination,
    get_events_command,
    parse_date_or_use_current,
    parse_integration_params,
    test_module,
)

# ========================================
# Constants
# ========================================

SERVER_URL = "https://test.sap.example.com"
TOKEN_URL = f"{SERVER_URL}/oauth/token"
TEST_DATA_PATH_SUFFIX = "test_data"
INTEGRATION_DIR_REL = "Packs/SAP_BTP/Integrations/SAPBTP/"

MOCK_CLIENT_ID = "test-client-id"
MOCK_CLIENT_SECRET = "test-client-secret"
MOCK_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMOCK_CERT_DATA\n-----END CERTIFICATE-----"
MOCK_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMOCK_KEY_DATA\n-----END PRIVATE KEY-----"
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
def client_non_mtls():
    """Returns a Client instance for Non-mTLS testing."""
    return Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        verify=True,
        proxy=False,
        auth_type=AuthType.NON_MTLS,
        cert_data=None,
    )


@pytest.fixture()
def client_mtls():
    """Returns a Client instance for mTLS testing."""
    return Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=None,
        verify=True,
        proxy=False,
        auth_type=AuthType.MTLS,
        cert_data=("/tmp/cert.pem", "/tmp/key.pem"),
    )


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


def test_parse_date_or_use_current_invalid_returns_current():
    """Tests parse_date_or_use_current returns current time for invalid date."""
    before = datetime.now()
    result = parse_date_or_use_current("invalid_date_string")
    after = datetime.now()
    assert before <= result <= after


def test_create_mtls_cert_files_success():
    """Tests create_mtls_cert_files creates temporary files."""
    cert_path, key_path = create_mtls_cert_files(MOCK_CERTIFICATE, MOCK_PRIVATE_KEY)

    assert os.path.exists(cert_path)
    assert os.path.exists(key_path)
    assert cert_path.endswith(".pem")
    assert key_path.endswith(".key")

    # Cleanup
    os.remove(cert_path)
    os.remove(key_path)


def test_create_mtls_cert_files_failure(mocker):
    """Tests create_mtls_cert_files raises DemistoException on failure."""
    mocker.patch("tempfile.NamedTemporaryFile", side_effect=Exception("File creation failed"))

    with pytest.raises(DemistoException, match="Failed to create mTLS certificate files"):
        create_mtls_cert_files(MOCK_CERTIFICATE, MOCK_PRIVATE_KEY)


# ========================================
# Tests: parse_integration_params
# ========================================


@pytest.mark.parametrize(
    "params,expected_error",
    [
        ({"url": ""}, "Server URL is required"),
        ({}, "Server URL is required"),
        ({"url": SERVER_URL}, "Client ID is required"),
        ({"url": SERVER_URL, "client_id": ""}, "Client ID is required"),
    ],
)
def test_parse_integration_params_missing_required_fail(params, expected_error):
    """Tests parse_integration_params fails if required fields are missing."""
    with pytest.raises(DemistoException, match=expected_error):
        parse_integration_params(params)


@pytest.mark.parametrize(
    "params,expected_error",
    [
        (
            {"url": SERVER_URL, "client_id": MOCK_CLIENT_ID, "auth_type": AuthType.MTLS},
            "mTLS authentication selected but missing required fields: Certificate, Private Key",
        ),
        (
            {"url": SERVER_URL, "client_id": MOCK_CLIENT_ID, "auth_type": AuthType.MTLS, "certificate": MOCK_CERTIFICATE},
            "mTLS authentication selected but missing required fields: Private Key",
        ),
        (
            {"url": SERVER_URL, "client_id": MOCK_CLIENT_ID, "auth_type": AuthType.NON_MTLS},
            "Non-mTLS authentication selected but Client Secret is missing",
        ),
        (
            {"url": SERVER_URL, "client_id": MOCK_CLIENT_ID, "auth_type": "InvalidAuth"},
            "Invalid authentication type 'InvalidAuth'",
        ),
    ],
)
def test_parse_integration_params_auth_validation_fail(params, expected_error):
    """Tests parse_integration_params validates authentication requirements."""
    with pytest.raises(DemistoException, match=expected_error):
        parse_integration_params(params)


@pytest.mark.parametrize(
    "params,expected_auth_type,expected_verify,expected_proxy",
    [
        (
            {
                "url": SERVER_URL,
                "client_id": MOCK_CLIENT_ID,
                "client_secret": MOCK_CLIENT_SECRET,
                "auth_type": AuthType.NON_MTLS,
                "insecure": True,
                "proxy": True,
            },
            AuthType.NON_MTLS,
            False,
            True,
        ),
        (
            {
                "url": f"{SERVER_URL}/",
                "client_id": MOCK_CLIENT_ID,
                "certificate": MOCK_CERTIFICATE,
                "key": MOCK_PRIVATE_KEY,
                "auth_type": AuthType.MTLS,
                "insecure": False,
                "proxy": False,
            },
            AuthType.MTLS,
            True,
            False,
        ),
    ],
)
def test_parse_integration_params_success(params, expected_auth_type, expected_verify, expected_proxy):
    """Tests parse_integration_params handles valid configurations."""
    result = parse_integration_params(params)

    assert result["base_url"] == SERVER_URL
    assert result["token_url"] == TOKEN_URL
    assert result["auth_type"] == expected_auth_type
    assert result["verify"] == expected_verify
    assert result["proxy"] == expected_proxy
    assert result["client_id"] == MOCK_CLIENT_ID


# ========================================
# Tests: Client Initialization
# ========================================


def test_client_init_non_mtls(client_non_mtls):
    """Tests Client initialization for Non-mTLS."""
    assert client_non_mtls.client_id == MOCK_CLIENT_ID
    assert client_non_mtls.client_secret == MOCK_CLIENT_SECRET
    assert client_non_mtls.auth_type == AuthType.NON_MTLS
    assert client_non_mtls.cert_data is None


def test_client_init_mtls(client_mtls):
    """Tests Client initialization for mTLS."""
    assert client_mtls.client_id == MOCK_CLIENT_ID
    assert client_mtls.client_secret is None
    assert client_mtls.auth_type == AuthType.MTLS
    assert client_mtls.cert_data == ("/tmp/cert.pem", "/tmp/key.pem")


# ========================================
# Tests: Token Management
# ========================================


def test_get_access_token_uses_cached_token(mocker, mock_context, client_non_mtls):
    """Tests _get_access_token uses valid token from cache."""
    mock_time = int(time.time()) + 3600
    set_integration_context({ContextKeys.ACCESS_TOKEN: "CACHED_TOKEN", ContextKeys.VALID_UNTIL: str(mock_time)})

    mocker.patch.object(SAPBTP.time, "time", return_value=int(time.time()) + 10)

    token = client_non_mtls._get_access_token()
    assert token == "CACHED_TOKEN"


def test_get_access_token_expired_renewal_non_mtls(mocker, mock_context, client_non_mtls):
    """Tests token renewal for Non-mTLS when cache is expired."""
    mock_time = int(time.time()) - 3600
    set_integration_context({ContextKeys.ACCESS_TOKEN: "EXPIRED_TOKEN", ContextKeys.VALID_UNTIL: str(mock_time)})

    mocker.patch.object(
        client_non_mtls,
        "_http_request",
        return_value={ContextKeys.ACCESS_TOKEN: MOCK_ACCESS_TOKEN, ContextKeys.EXPIRES_IN: 3600},
    )

    token = client_non_mtls._get_access_token()

    assert token == MOCK_ACCESS_TOKEN
    assert get_integration_context().get(ContextKeys.ACCESS_TOKEN) == MOCK_ACCESS_TOKEN


def test_get_access_token_renewal_mtls(mocker, mock_context, client_mtls):
    """Tests token renewal for mTLS authentication."""
    mocker.patch.object(
        client_mtls,
        "_http_request",
        return_value={ContextKeys.ACCESS_TOKEN: MOCK_ACCESS_TOKEN, ContextKeys.EXPIRES_IN: 3600},
    )

    token = client_mtls._get_access_token()

    assert token == MOCK_ACCESS_TOKEN
    client_mtls._http_request.assert_called_once()


def test_get_access_token_mtls_without_cert_data_fail(mock_context):
    """Tests mTLS token request fails without certificate data."""
    client = Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=None,
        verify=True,
        proxy=False,
        auth_type=AuthType.MTLS,
        cert_data=None,
    )

    with pytest.raises(DemistoException, match="mTLS authentication requires certificate files"):
        client._get_access_token()


def test_get_access_token_no_token_in_response_fail(mocker, mock_context, client_non_mtls):
    """Tests token renewal fails if API doesn't return access_token."""
    mocker.patch.object(client_non_mtls, "_http_request", return_value={"error": "failed"})

    with pytest.raises(DemistoException, match="Failed to obtain access token from SAP BTP"):
        client_non_mtls._get_access_token()


def test_get_access_token_invalid_cache_renewal(mocker, mock_context, client_non_mtls):
    """Tests token renewal when cache has invalid expiration value."""
    set_integration_context({ContextKeys.ACCESS_TOKEN: "BAD_TOKEN", ContextKeys.VALID_UNTIL: "NOT_A_NUMBER"})

    mocker.patch.object(
        client_non_mtls,
        "_http_request",
        return_value={ContextKeys.ACCESS_TOKEN: MOCK_ACCESS_TOKEN, ContextKeys.EXPIRES_IN: 3600},
    )

    token = client_non_mtls._get_access_token()
    assert token == MOCK_ACCESS_TOKEN


# ========================================
# Tests: HTTP Request Methods
# ========================================


def test_http_request_success(mocker, client_non_mtls):
    """Tests http_request executes successfully."""
    mocker.patch.object(client_non_mtls, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)

    # When return_full_response=False, _http_request returns response object with status_code
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mocker.patch.object(client_non_mtls, "_http_request", return_value=mock_response)

    result = client_non_mtls.http_request("GET", "/test")

    assert result == mock_response


def test_http_request_with_full_response(mocker, client_non_mtls):
    """Tests http_request returns full response with headers."""
    mocker.patch.object(client_non_mtls, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)

    mock_response = mocker.Mock()
    mock_response.json.return_value = {"data": "success"}
    mock_response.headers = {"Content-Type": "application/json"}

    mocker.patch.object(client_non_mtls, "_http_request", return_value=mock_response)

    body, headers = client_non_mtls.http_request("GET", "/test", return_full_response=True)

    assert body == {"data": "success"}
    assert headers == {"Content-Type": "application/json"}


# ========================================
# Tests: get_audit_log_events
# ========================================


def test_get_audit_log_events_first_page(mocker, client_non_mtls):
    """Tests get_audit_log_events fetches first page correctly."""
    mock_response_body = [{"uuid": "event1", "time": "2024-01-01T00:00:00Z"}]
    mock_response_headers = {"Paging": "handle=next_page_handle"}

    mocker.patch.object(client_non_mtls, "http_request", return_value=(mock_response_body, mock_response_headers))

    events, next_handle = client_non_mtls.get_audit_log_events(created_after="2024-01-01T00:00:00Z", limit=100)

    assert len(events) == 1
    assert events[0]["uuid"] == "event1"
    assert next_handle == "next_page_handle"


def test_get_audit_log_events_with_pagination_handle(mocker, client_non_mtls):
    """Tests get_audit_log_events uses pagination handle."""
    mock_response_body = [{"uuid": "event2"}]
    mock_response_headers = {}

    mocker.patch.object(client_non_mtls, "http_request", return_value=(mock_response_body, mock_response_headers))

    events, next_handle = client_non_mtls.get_audit_log_events(
        created_after="2024-01-01T00:00:00Z", limit=100, pagination_handle="existing_handle"
    )

    assert len(events) == 1
    assert next_handle is None


def test_get_audit_log_events_response_with_value_key(mocker, client_non_mtls):
    """Tests get_audit_log_events handles response with 'value' key."""
    mock_response_body = {"value": [{"uuid": "event1"}]}
    mock_response_headers = {}

    mocker.patch.object(client_non_mtls, "http_request", return_value=(mock_response_body, mock_response_headers))

    events, _ = client_non_mtls.get_audit_log_events(created_after="2024-01-01T00:00:00Z", limit=100)

    assert len(events) == 1
    assert events[0]["uuid"] == "event1"


@pytest.mark.parametrize(
    "paging_header,expected_handle",
    [
        ("handle=abc123", "abc123"),
        ("handle=xyz789 ", "xyz789"),
        ("", None),
        (None, None),
        ("no_handle_here", None),
    ],
)
def test_extract_pagination_handle(client_non_mtls, paging_header, expected_handle):
    """Tests _extract_pagination_handle parses various header formats."""
    headers = {"Paging": paging_header} if paging_header is not None else {}
    result = client_non_mtls._extract_pagination_handle(headers)
    assert result == expected_handle


def test_extract_pagination_handle_case_insensitive(client_non_mtls):
    """Tests _extract_pagination_handle handles lowercase header name."""
    headers = {"paging": "handle=test123"}
    result = client_non_mtls._extract_pagination_handle(headers)
    assert result == "test123"


# ========================================
# Tests: fetch_events_with_pagination
# ========================================


def test_fetch_events_with_pagination_single_page(mocker, client_non_mtls):
    """Tests fetch_events_with_pagination with single page of results."""
    mock_events = [{"uuid": f"event{i}", "time": f"2024-01-0{i}T00:00:00Z"} for i in range(1, 4)]

    mocker.patch.object(client_non_mtls, "get_audit_log_events", return_value=(mock_events, None))

    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", 10)

    assert len(events) == 3
    assert events[0]["uuid"] == "event1"


def test_fetch_events_with_pagination_multiple_pages(mocker, client_non_mtls):
    """Tests fetch_events_with_pagination handles multiple pages."""
    page1 = [{"uuid": f"event{i}"} for i in range(1, 6)]
    page2 = [{"uuid": f"event{i}"} for i in range(6, 11)]

    mocker.patch.object(
        client_non_mtls,
        "get_audit_log_events",
        side_effect=[(page1, "handle1"), (page2, None)],
    )

    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", 10)

    assert len(events) == 10
    assert client_non_mtls.get_audit_log_events.call_count == 2


def test_fetch_events_with_pagination_stops_at_max(mocker, client_non_mtls):
    """Tests fetch_events_with_pagination stops at max_events."""
    page1 = [{"uuid": f"event{i}"} for i in range(1, 6)]  # 5 events
    page2 = [{"uuid": f"event{i}"} for i in range(6, 9)]  # 3 events (to reach exactly 7 with page1)

    mocker.patch.object(
        client_non_mtls,
        "get_audit_log_events",
        side_effect=[(page1, "handle1"), (page2, None)],
    )

    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", 8)

    # Should get all 8 events (5 from page1 + 3 from page2)
    assert len(events) == 8


def test_fetch_events_with_pagination_empty_page(mocker, client_non_mtls):
    """Tests fetch_events_with_pagination handles empty page."""
    mocker.patch.object(client_non_mtls, "get_audit_log_events", return_value=([], None))

    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", 10)

    assert len(events) == 0


# ========================================
# Tests: test_module Command
# ========================================


def test_test_module_success(mocker, client_non_mtls):
    """Tests test_module returns 'ok' on success."""
    mocker.patch.object(client_non_mtls, "get_audit_log_events", return_value=([{"uuid": "test"}], None))

    result = test_module(client_non_mtls)

    assert result == "ok"


def test_test_module_auth_error_401(mocker, client_non_mtls):
    """Tests test_module returns auth error message for 401."""
    mocker.patch.object(
        client_non_mtls,
        "get_audit_log_events",
        side_effect=DemistoException("Error [401] - Unauthorized"),
    )

    result = test_module(client_non_mtls)

    assert result == "Authorization Error: Verify Client ID, Secret, or Certificates."


def test_test_module_auth_error_403(mocker, client_non_mtls):
    """Tests test_module returns auth error message for 403."""
    mocker.patch.object(
        client_non_mtls,
        "get_audit_log_events",
        side_effect=DemistoException("Error [403] - Forbidden"),
    )

    result = test_module(client_non_mtls)

    assert result == "Authorization Error: Verify Client ID, Secret, or Certificates."


def test_test_module_other_error_raises(mocker, client_non_mtls):
    """Tests test_module raises other errors."""
    mocker.patch.object(
        client_non_mtls,
        "get_audit_log_events",
        side_effect=DemistoException("Error [500] - Internal Server Error"),
    )

    with pytest.raises(DemistoException, match="Internal Server Error"):
        test_module(client_non_mtls)


# ========================================
# Tests: get_events_command
# ========================================


def test_get_events_command_success(mocker, client_non_mtls):
    """Tests get_events_command returns correct CommandResults."""
    mock_events = [{"uuid": "123", "user": "test@example.com", "time": "2024-01-01T00:00:00Z"}]

    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=mock_events)

    args = {"from": "3 days", "limit": "10"}
    result = get_events_command(client_non_mtls, args)

    assert result.outputs_prefix == "SAPBTP.Event"
    assert result.outputs_key_field == "uuid"
    assert result.outputs == mock_events
    assert len(result.outputs) == 1


def test_get_events_command_default_values(mocker, client_non_mtls):
    """Tests get_events_command uses default values."""
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    result = get_events_command(client_non_mtls, {})

    assert result.outputs == []
    SAPBTP.fetch_events_with_pagination.assert_called_once()


def test_get_events_command_with_from_now(mocker, client_non_mtls):
    """Tests get_events_command handles 'now' as from value."""
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    args = {"from": "now"}
    result = get_events_command(client_non_mtls, args)

    assert result.outputs == []


# ========================================
# Tests: fetch_events_command
# ========================================


def test_fetch_events_command_first_run(mocker, client_non_mtls):
    """Tests fetch_events_command on first run (no last_run)."""
    mock_events = [
        {"uuid": "1", "time": "2024-01-01T00:00:00Z"},
        {"uuid": "2", "time": "2024-01-01T01:00:00Z"},
    ]

    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 100})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    fetch_events_command(client_non_mtls, {})

    demisto.setLastRun.assert_called_once_with({"last_fetch": "2024-01-01T01:00:00Z"})
    SAPBTP.send_events_to_xsiam.assert_called_once_with(
        mock_events, vendor=IntegrationConfig.VENDOR, product=IntegrationConfig.PRODUCT
    )


def test_fetch_events_command_with_last_run(mocker, client_non_mtls):
    """Tests fetch_events_command with existing last_run."""
    mock_events = [{"uuid": "3", "time": "2024-01-02T00:00:00Z"}]

    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00Z"})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 100})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    fetch_events_command(client_non_mtls, {})

    demisto.setLastRun.assert_called_once_with({"last_fetch": "2024-01-02T00:00:00Z"})


def test_fetch_events_command_no_events(mocker, client_non_mtls):
    """Tests fetch_events_command when no events are fetched."""
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    fetch_events_command(client_non_mtls, {})

    demisto.setLastRun.assert_not_called()
    SAPBTP.send_events_to_xsiam.assert_not_called()


def test_fetch_events_command_events_without_time(mocker, client_non_mtls):
    """Tests fetch_events_command handles events without time field."""
    mock_events = [{"uuid": "1"}, {"uuid": "2"}]

    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    fetch_events_command(client_non_mtls, {})

    # Should not update last_run if events have no time field
    demisto.setLastRun.assert_not_called()
    SAPBTP.send_events_to_xsiam.assert_called_once()


# ========================================
# Tests: Main Function
# ========================================


def test_main_invalid_command_fail(mocker):
    """Tests main() raises error for invalid command."""
    mocker.patch.object(demisto, "command", return_value="invalid-command")
    mocker.patch.object(
        demisto,
        "params",
        return_value={"url": SERVER_URL, "client_id": MOCK_CLIENT_ID, "client_secret": MOCK_CLIENT_SECRET},
    )
    mocker.patch.object(demisto, "args", return_value={})

    mock_return_error = mocker.patch("SAPBTP.return_error")

    SAPBTP.main()

    mock_return_error.assert_called_once()
    error_call_args = mock_return_error.call_args[0][0]
    assert "invalid-command" in error_call_args
    assert "not implemented" in error_call_args.lower()


def test_main_test_module_success(mocker):
    """Tests main() executes test-module command successfully."""
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": MOCK_CLIENT_SECRET,
            "auth_type": AuthType.NON_MTLS,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    mock_return_results = mocker.patch("SAPBTP.return_results")

    SAPBTP.main()

    mock_return_results.assert_called_once_with("ok")


def test_main_get_events_success(mocker):
    """Tests main() executes sap-btp-get-events command successfully."""
    mocker.patch.object(demisto, "command", return_value="sap-btp-get-events")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": MOCK_CLIENT_SECRET,
            "auth_type": AuthType.NON_MTLS,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    mock_return_results = mocker.patch("SAPBTP.return_results")

    SAPBTP.main()

    mock_return_results.assert_called_once()


def test_main_fetch_events_success(mocker):
    """Tests main() executes fetch-events command successfully."""
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": MOCK_CLIENT_SECRET,
            "auth_type": AuthType.NON_MTLS,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    SAPBTP.main()

    # Should complete without error


def test_main_command_execution_error(mocker):
    """Tests main() handles command execution errors gracefully."""
    mocker.patch.object(demisto, "command", return_value="sap-btp-get-events")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": MOCK_CLIENT_SECRET,
            "auth_type": AuthType.NON_MTLS,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", side_effect=Exception("API Error"))

    mock_return_error = mocker.patch("SAPBTP.return_error")

    SAPBTP.main()

    mock_return_error.assert_called_once()
    error_message = mock_return_error.call_args[0][0]
    assert "sap-btp-get-events" in error_message.lower()


@pytest.mark.parametrize(
    "command_name,expected_in_map",
    [
        ("test-module", True),
        ("sap-btp-get-events", True),
        ("fetch-events", True),
        ("non-existent-command", False),
        ("", False),
    ],
)
def test_command_map_completeness(command_name, expected_in_map):
    """Tests that COMMAND_MAP contains all expected commands."""
    assert (command_name in SAPBTP.COMMAND_MAP) == expected_in_map
