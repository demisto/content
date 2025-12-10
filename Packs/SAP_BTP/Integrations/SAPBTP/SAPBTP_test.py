# pylint: disable=E9010, E9011
import json
import os
import time
from datetime import datetime, timezone  # noqa: UP017

import pytest
from CommonServerPython import *

import SAPBTP  # noqa: E402
from SAPBTP import (  # noqa: E402
    APIKeys,
    APIValues,
    AuthType,
    Client,
    Config,
    ContextKeys,
    add_time_to_events,
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

SERVER_URL = "https://auditlog-management.cfapps.test.hana.ondemand.com"
AUTH_SERVER_URL = "https://test-subdomain.authentication.test.hana.ondemand.com"
TOKEN_URL = f"{AUTH_SERVER_URL}/oauth/token"
TEST_DATA_PATH_SUFFIX = "test_data"
INTEGRATION_DIR_REL = "Packs/SAP_BTP/Integrations/SAPBTP/"

MOCK_CLIENT_ID = "test-client-id"
MOCK_CLIENT_SECRET = "test-client-secret"
MOCK_CERTIFICATE = "MOCK_CERTIFICATE_CONTENT_FOR_TESTING"
MOCK_PRIVATE_KEY = "MOCK_PRIVATE_KEY_CONTENT_FOR_TESTING"
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
        auth_type=AuthType.NON_MTLS.value,
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
        auth_type=AuthType.MTLS.value,
        cert_data=("/tmp/cert.pem", "/tmp/key.pem"),
    )


@pytest.fixture()
def client(mocker):
    """Returns a mocked Client instance for testing.

    This fixture provides a default client that can be used by any test,
    including the test_module function from SAPBTP.py that pytest discovers.
    The client is mocked to prevent actual HTTP requests.
    """
    client_instance = Client(
        base_url=SERVER_URL,
        token_url=TOKEN_URL,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        verify=True,
        proxy=False,
        auth_type=AuthType.NON_MTLS.value,
        cert_data=None,
    )

    # Mock the methods that make HTTP requests to prevent actual network calls
    mocker.patch.object(client_instance, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(client_instance, "get_audit_log_events", return_value=([], None))

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

    before = datetime.now(timezone.utc)  # noqa: UP017
    result = parse_date_or_use_current("invalid_date_string")
    after = datetime.now(timezone.utc)  # noqa: UP017
    assert before <= result <= after


@pytest.mark.parametrize(
    "should_fail,mock_exception,expected_error",
    [
        (False, None, None),  # Success case
        (True, Exception("File creation failed"), "Failed to create mTLS certificate files"),  # Failure case
    ],
)
def test_create_mtls_cert_files(mocker, should_fail, mock_exception, expected_error):
    """Tests create_mtls_cert_files creates temporary files or raises DemistoException on failure."""
    if should_fail:
        mocker.patch("tempfile.NamedTemporaryFile", side_effect=mock_exception)
        with pytest.raises(DemistoException, match=expected_error):
            create_mtls_cert_files(MOCK_CERTIFICATE, MOCK_PRIVATE_KEY)
    else:
        cert_path, key_path = create_mtls_cert_files(MOCK_CERTIFICATE, MOCK_PRIVATE_KEY)
        assert os.path.exists(cert_path)
        assert os.path.exists(key_path)
        assert cert_path.endswith(".pem")
        assert key_path.endswith(".key")
        # Cleanup
        os.remove(cert_path)
        os.remove(key_path)


# ========================================
# Tests: parse_integration_params
# ========================================


@pytest.mark.parametrize(
    "params,expected_error",
    [
        ({"url": ""}, "API URL is required"),
        ({}, "API URL is required"),
        ({"url": SERVER_URL}, "Token URL is required"),
        ({"url": SERVER_URL, "token_url": ""}, "Token URL is required"),
        ({"url": SERVER_URL, "token_url": AUTH_SERVER_URL}, "Client ID is required"),
        ({"url": SERVER_URL, "token_url": AUTH_SERVER_URL, "client_id": ""}, "Client ID is required"),
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
            {"url": SERVER_URL, "token_url": AUTH_SERVER_URL, "client_id": MOCK_CLIENT_ID, "auth_type": AuthType.MTLS.value},
            "mTLS authentication requires both Certificate and Private Key",
        ),
        (
            {
                "url": SERVER_URL,
                "token_url": AUTH_SERVER_URL,
                "client_id": MOCK_CLIENT_ID,
                "auth_type": AuthType.MTLS.value,
                "certificate": MOCK_CERTIFICATE,
            },
            "mTLS authentication requires both Certificate and Private Key",
        ),
        (
            {"url": SERVER_URL, "token_url": AUTH_SERVER_URL, "client_id": MOCK_CLIENT_ID, "auth_type": AuthType.NON_MTLS.value},
            "Non-mTLS authentication requires Client Secret",
        ),
        (
            {"url": SERVER_URL, "token_url": AUTH_SERVER_URL, "client_id": MOCK_CLIENT_ID, "auth_type": "InvalidAuth"},
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
                "token_url": AUTH_SERVER_URL,
                "client_id": MOCK_CLIENT_ID,
                "client_secret": {"password": MOCK_CLIENT_SECRET},
                "auth_type": AuthType.NON_MTLS.value,
                "insecure": True,
                "proxy": True,
            },
            AuthType.NON_MTLS.value,
            False,
            True,
        ),
        (
            {
                "url": f"{SERVER_URL}/",
                "token_url": f"{AUTH_SERVER_URL}/",
                "client_id": MOCK_CLIENT_ID,
                "certificate": MOCK_CERTIFICATE,
                "private_key": MOCK_PRIVATE_KEY,
                "auth_type": AuthType.MTLS.value,
                "insecure": False,
                "proxy": False,
            },
            AuthType.MTLS.value,
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


@pytest.mark.parametrize(
    "insecure,expected_verify",
    [
        (True, False),  # insecure=True means verify=False
        (False, True),  # insecure=False means verify=True
    ],
)
def test_parse_integration_params_mtls_verify_settings(insecure, expected_verify):
    """Tests parse_integration_params handles mTLS verify settings correctly."""
    params = {
        "url": SERVER_URL,
        "token_url": AUTH_SERVER_URL,
        "client_id": MOCK_CLIENT_ID,
        "auth_type": AuthType.MTLS.value,
        "certificate": MOCK_CERTIFICATE,
        "private_key": MOCK_PRIVATE_KEY,
        "insecure": insecure,
    }

    result = parse_integration_params(params)

    assert result["auth_type"] == AuthType.MTLS.value
    assert result["verify"] is expected_verify
    assert result["certificate"] == MOCK_CERTIFICATE
    assert result["private_key"] == MOCK_PRIVATE_KEY


# ========================================
# Tests: Client Initialization
# ========================================


@pytest.mark.parametrize(
    "fixture_name,expected_auth_type,expected_secret,expected_cert",
    [
        ("client_non_mtls", AuthType.NON_MTLS.value, MOCK_CLIENT_SECRET, None),
        ("client_mtls", AuthType.MTLS.value, None, ("/tmp/cert.pem", "/tmp/key.pem")),
    ],
)
def test_client_initialization(fixture_name, expected_auth_type, expected_secret, expected_cert, request):
    """Tests Client initialization for both Non-mTLS and mTLS."""
    client = request.getfixturevalue(fixture_name)

    assert client.client_id == MOCK_CLIENT_ID
    assert client.client_secret == expected_secret
    assert client.auth_type == expected_auth_type
    assert client.cert_data == expected_cert


# ========================================
# Tests: Token Management
# ========================================


def test_get_access_token_uses_cached_token(mocker, mock_context, client_non_mtls):
    """Tests _get_access_token uses valid token from cache."""
    mock_time = int(time.time()) + 3600
    set_integration_context({ContextKeys.ACCESS_TOKEN.value: "CACHED_TOKEN", ContextKeys.VALID_UNTIL.value: str(mock_time)})

    mocker.patch.object(SAPBTP.time, "time", return_value=int(time.time()) + 10)

    token = client_non_mtls._get_access_token()
    assert token == "CACHED_TOKEN"


def test_get_access_token_expired_renewal_non_mtls(mocker, mock_context, client_non_mtls):
    """Tests token renewal for Non-mTLS when cache is expired."""
    mock_time = int(time.time()) - 3600
    set_integration_context({ContextKeys.ACCESS_TOKEN.value: "EXPIRED_TOKEN", ContextKeys.VALID_UNTIL.value: str(mock_time)})

    mocker.patch.object(
        client_non_mtls,
        "_http_request",
        return_value={ContextKeys.ACCESS_TOKEN.value: MOCK_ACCESS_TOKEN, ContextKeys.EXPIRES_IN.value: 3600},
    )

    token = client_non_mtls._get_access_token()

    assert token == MOCK_ACCESS_TOKEN
    assert get_integration_context().get(ContextKeys.ACCESS_TOKEN.value) == MOCK_ACCESS_TOKEN


def test_get_access_token_renewal_mtls(mocker, mock_context, client_mtls):
    """Tests token renewal for mTLS authentication."""
    mocker.patch.object(
        client_mtls,
        "_http_request",
        return_value={ContextKeys.ACCESS_TOKEN.value: MOCK_ACCESS_TOKEN, ContextKeys.EXPIRES_IN.value: 3600},
    )

    token = client_mtls._get_access_token()

    assert token == MOCK_ACCESS_TOKEN

    # Verify the request was made with correct parameters
    call_args = client_mtls._http_request.call_args
    assert call_args[1]["method"] == "POST"
    assert call_args[1]["full_url"] == TOKEN_URL
    assert call_args[1]["cert"] == ("/tmp/cert.pem", "/tmp/key.pem")
    assert call_args[1]["data"][APIKeys.GRANT_TYPE.value] == APIValues.GRANT_TYPE_CLIENT_CREDENTIALS.value
    assert call_args[1]["data"][APIKeys.CLIENT_ID.value] == MOCK_CLIENT_ID


@pytest.mark.parametrize(
    "test_case,cert_data,mock_response,expected_error",
    [
        ("mtls_without_cert", None, None, "mTLS authentication requires certificate files"),
        (
            "no_token_in_response",
            ("/tmp/cert.pem", "/tmp/key.pem"),
            {"error": "failed"},
            "Failed to obtain access token from SAP BTP",
        ),
    ],
)
def test_get_access_token_failure_cases(mocker, mock_context, test_case, cert_data, mock_response, expected_error):
    """Tests token request failures for various error conditions."""
    if test_case == "mtls_without_cert":
        client = Client(
            base_url=SERVER_URL,
            token_url=TOKEN_URL,
            client_id=MOCK_CLIENT_ID,
            client_secret=None,
            verify=True,
            proxy=False,
            auth_type=AuthType.MTLS.value,
            cert_data=cert_data,
        )
    else:  # no_token_in_response
        client = Client(
            base_url=SERVER_URL,
            token_url=TOKEN_URL,
            client_id=MOCK_CLIENT_ID,
            client_secret=MOCK_CLIENT_SECRET,
            verify=True,
            proxy=False,
            auth_type=AuthType.NON_MTLS.value,
            cert_data=None,
        )
        mocker.patch.object(client, "_http_request", return_value=mock_response)

    with pytest.raises(DemistoException, match=expected_error):
        client._get_access_token()


def test_get_access_token_invalid_cache_renewal(mocker, mock_context, client_non_mtls):
    """Tests token renewal when cache has invalid expiration value."""
    set_integration_context({ContextKeys.ACCESS_TOKEN.value: "BAD_TOKEN", ContextKeys.VALID_UNTIL.value: "NOT_A_NUMBER"})

    mocker.patch.object(
        client_non_mtls,
        "_http_request",
        return_value={ContextKeys.ACCESS_TOKEN.value: MOCK_ACCESS_TOKEN, ContextKeys.EXPIRES_IN.value: 3600},
    )

    token = client_non_mtls._get_access_token()
    assert token == MOCK_ACCESS_TOKEN


def test_get_access_token_non_mtls_vs_mtls_request_structure(mocker, mock_context, client_non_mtls, client_mtls):
    """Tests that Non-mTLS and mTLS use different authentication methods."""
    # Mock for Non-mTLS
    mock_non_mtls_request = mocker.patch.object(
        client_non_mtls,
        "_http_request",
        return_value={ContextKeys.ACCESS_TOKEN.value: "non_mtls_token", ContextKeys.EXPIRES_IN.value: 3600},
    )

    # Mock for mTLS
    mock_mtls_request = mocker.patch.object(
        client_mtls,
        "_http_request",
        return_value={ContextKeys.ACCESS_TOKEN.value: "mtls_token", ContextKeys.EXPIRES_IN.value: 3600},
    )

    # Get tokens
    non_mtls_token = client_non_mtls._get_access_token()

    # Clear the integration context to prevent cache hit for mTLS client
    set_integration_context({})

    mtls_token = client_mtls._get_access_token()

    # Verify tokens
    assert non_mtls_token == "non_mtls_token"
    assert mtls_token == "mtls_token"

    # Verify Non-mTLS uses Basic Auth (auth parameter)
    non_mtls_call = mock_non_mtls_request.call_args[1]
    assert "auth" in non_mtls_call
    assert non_mtls_call["auth"] == (MOCK_CLIENT_ID, MOCK_CLIENT_SECRET)
    assert "params" in non_mtls_call
    assert "cert" not in non_mtls_call

    # Verify mTLS uses certificate (cert parameter) and data body
    mtls_call = mock_mtls_request.call_args[1]
    assert "cert" in mtls_call
    assert mtls_call["cert"] == ("/tmp/cert.pem", "/tmp/key.pem")
    assert "data" in mtls_call
    assert mtls_call["data"][APIKeys.CLIENT_ID.value] == MOCK_CLIENT_ID
    assert "auth" not in mtls_call


# ========================================
# Tests: HTTP Request Methods
# ========================================


@pytest.mark.parametrize(
    "status_code,json_data,json_error,return_full_response,expected_result,should_fail,expected_error",
    [
        (200, {"data": "success"}, None, False, {"data": "success"}, False, None),  # Success
        (
            200,
            {"data": "success"},
            None,
            True,
            ({"data": "success"}, {"Content-Type": "application/json"}),
            False,
            None,
        ),  # Full response
        (204, None, None, False, {}, False, None),  # 204 No Content
        (
            200,
            None,
            ValueError("Invalid JSON"),
            False,
            None,
            True,
            "API returned non-JSON response with status 200",
        ),  # JSON parse failure
    ],
)
def test_http_request(
    mocker,
    client_non_mtls,
    status_code,
    json_data,
    json_error,
    return_full_response,
    expected_result,
    should_fail,
    expected_error,
):
    """Tests http_request handles various response scenarios."""
    mocker.patch.object(client_non_mtls, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)

    mock_response = mocker.Mock()
    mock_response.status_code = status_code
    mock_response.headers = {"Content-Type": "application/json"}

    if json_error:
        mock_response.json.side_effect = json_error
        mock_response.text = "Not a JSON response"
    else:
        mock_response.json.return_value = json_data

    mocker.patch.object(client_non_mtls, "_http_request", return_value=mock_response)

    if should_fail:
        with pytest.raises(DemistoException, match=expected_error):
            client_non_mtls.http_request("GET", "/test", return_full_response=return_full_response)
    else:
        result = client_non_mtls.http_request("GET", "/test", return_full_response=return_full_response)
        assert result == expected_result


@pytest.mark.parametrize(
    "error_code,error_message",
    [
        ("401", "Error [401] - Unauthorized"),
        ("403", "Error [403] - Forbidden"),
    ],
)
def test_http_request_auth_error_handling(mocker, capfd, client_non_mtls, error_code, error_message):
    """Tests http_request properly handles 401/403 authentication errors."""
    mocker.patch.object(client_non_mtls, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)
    mocker.patch.object(client_non_mtls, "_http_request", side_effect=DemistoException(error_message))

    with capfd.disabled(), pytest.raises(DemistoException, match="Authentication error"):
        client_non_mtls.http_request("GET", "/test")


def test_http_request_retries_on_server_errors(mocker, client_non_mtls):
    """Tests http_request uses retries and backoff for server errors."""
    mocker.patch.object(client_non_mtls, "_get_access_token", return_value=MOCK_ACCESS_TOKEN)

    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "success"}
    mock_response.headers = {}

    # Mock _http_request to verify retry parameters are passed
    mock_http = mocker.patch.object(client_non_mtls, "_http_request", return_value=mock_response)

    client_non_mtls.http_request("GET", "/test")

    # Verify retries and backoff_factor were passed
    call_kwargs = mock_http.call_args[1]
    assert call_kwargs.get("retries") == 3
    assert call_kwargs.get("backoff_factor") == 2


# ========================================
# Tests: _parse_events_from_response
# ========================================


@pytest.mark.parametrize(
    "response_body,expected_count,expected_first_uuid",
    [
        # Direct list format
        ([{"uuid": "event1"}, {"uuid": "event2"}], 2, "event1"),
        # Dictionary with 'results' key
        ({"results": [{"uuid": "event1"}]}, 1, "event1"),
        # Nested 'd.results' (OData format)
        ({"d": {"results": [{"uuid": "event1"}, {"uuid": "event2"}]}}, 2, "event1"),
        # Single object with message_uuid
        ({"message_uuid": "msg1", "uuid": "event1"}, 1, "event1"),
        # Empty results
        ({"results": []}, 0, None),
        # Empty dict
        ({}, 0, None),
    ],
)
def test_parse_events_from_response_formats(client_non_mtls, response_body, expected_count, expected_first_uuid):
    """Tests _parse_events_from_response handles various response formats."""
    events = client_non_mtls._parse_events_from_response(response_body)

    assert len(events) == expected_count
    if expected_count > 0:
        assert events[0]["uuid"] == expected_first_uuid


# ========================================
# Tests: get_formatted_utc_time
# ========================================


@pytest.mark.parametrize(
    "date_input,expected_format",
    [
        ("2024-01-01T00:00:00Z", True),
        ("3 days ago", True),
        (None, True),
        ("", True),
    ],
)
def test_get_formatted_utc_time(date_input, expected_format):
    """Tests get_formatted_utc_time returns properly formatted UTC string."""
    from SAPBTP import get_formatted_utc_time, Config

    result = get_formatted_utc_time(date_input)

    # Verify it's a string
    assert isinstance(result, str)

    # Verify it matches the expected format
    if expected_format:
        # Should be able to parse it back
        parsed = datetime.strptime(result, Config.DATE_FORMAT)
        assert isinstance(parsed, datetime)


def test_get_formatted_utc_time_invalid_date():
    """Tests get_formatted_utc_time handles invalid date gracefully."""
    from SAPBTP import get_formatted_utc_time, Config

    result = get_formatted_utc_time("not_a_valid_date_12345")

    # Should still return a valid formatted string (current time)
    assert isinstance(result, str)
    parsed = datetime.strptime(result, Config.DATE_FORMAT)
    assert isinstance(parsed, datetime)


# ========================================
# Tests: get_audit_log_events
# ========================================


@pytest.mark.parametrize(
    "response_body,response_headers,pagination_handle,expected_count,expected_next_handle,expected_first_uuid",
    [
        # First page with pagination
        (
            [{"uuid": "event1", "time": "2024-01-01T00:00:00Z"}],
            {"Paging": "handle=next_page_handle"},
            None,
            1,
            "next_page_handle",
            "event1",
        ),
        # Using pagination handle (last page)
        (
            [{"uuid": "event2"}],
            {},
            "existing_handle",
            1,
            None,
            "event2",
        ),
        # Response with 'results' key
        (
            {"results": [{"uuid": "event1"}]},
            {},
            None,
            1,
            None,
            "event1",
        ),
        # Response with nested 'd.results' key
        (
            {"d": {"results": [{"uuid": "event1"}, {"uuid": "event2"}]}},
            {},
            None,
            2,
            None,
            "event1",
        ),
        # Single event with message_uuid
        (
            {"message_uuid": "msg123", "uuid": "event1", "data": "test"},
            {},
            None,
            1,
            None,
            "event1",
        ),
        # Empty response
        (
            {"results": []},
            {},
            None,
            0,
            None,
            None,
        ),
    ],
)
def test_get_audit_log_events_scenarios(
    mocker,
    client_non_mtls,
    response_body,
    response_headers,
    pagination_handle,
    expected_count,
    expected_next_handle,
    expected_first_uuid,
):
    """Tests get_audit_log_events handles various response scenarios."""
    mocker.patch.object(client_non_mtls, "http_request", return_value=(response_body, response_headers))

    events, next_handle = client_non_mtls.get_audit_log_events(
        created_after="2024-01-01T00:00:00Z", limit=100, pagination_handle=pagination_handle
    )

    assert len(events) == expected_count
    assert next_handle == expected_next_handle
    if expected_count > 0 and expected_first_uuid:
        assert events[0]["uuid"] == expected_first_uuid


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


@pytest.mark.parametrize(
    "headers,expected_result,description",
    [
        ({"paging": "handle=test123"}, "test123", "lowercase header name"),
        ({"Paging": "handle="}, "", "malformed header (empty value)"),
        ({"Paging": "handle=abc=def=123"}, "abc=def=123", "multiple equals signs"),
    ],
)
def test_extract_pagination_handle_special_cases(client_non_mtls, headers, expected_result, description):
    """Tests _extract_pagination_handle handles special cases."""
    result = client_non_mtls._extract_pagination_handle(headers)
    assert result == expected_result, f"Failed for: {description}"


# ========================================
# Tests: fetch_events_with_pagination
# ========================================


def test_fetch_events_with_pagination_single_page(mocker, client_non_mtls):
    """Tests fetch_events_with_pagination with single page of results."""
    mock_events = [{"uuid": f"event{i}", "time": f"2024-01-0{i}T00:00:00Z"} for i in range(1, 4)]

    mocker.patch.object(client_non_mtls, "get_audit_log_events", return_value=(mock_events, None))

    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", None, 10)

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

    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", None, 10)

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

    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", None, 8)

    # Should get all 8 events (5 from page1 + 3 from page2)
    assert len(events) == 8


def test_fetch_events_with_pagination_empty_page(mocker, client_non_mtls):
    """Tests fetch_events_with_pagination handles empty page."""
    mocker.patch.object(client_non_mtls, "get_audit_log_events", return_value=([], None))

    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", None, 10)

    assert len(events) == 0


@pytest.mark.parametrize(
    "created_before,expected_in_call",
    [
        ("2024-01-02T00:00:00Z", True),
        (None, False),
    ],
)
def test_fetch_events_with_pagination_created_before_parameter(mocker, client_non_mtls, created_before, expected_in_call):
    """Tests fetch_events_with_pagination handles created_before parameter correctly."""
    mock_events = [{"uuid": "event1", "time": "2024-01-01T00:00:00Z"}]
    mock_get_events = mocker.patch.object(client_non_mtls, "get_audit_log_events", return_value=(mock_events, None))

    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", created_before, 10)

    assert len(events) == 1
    call_args = mock_get_events.call_args
    if expected_in_call:
        assert call_args[1]["created_before"] == created_before
    else:
        assert call_args[1]["created_before"] is None


@pytest.mark.parametrize(
    "created_before,should_have_time_to",
    [
        ("2024-01-02T00:00:00Z", True),
        (None, False),
    ],
)
def test_get_audit_log_events_created_before_in_params(mocker, client_non_mtls, created_before, should_have_time_to):
    """Tests get_audit_log_events includes created_before in request params when provided."""
    mock_response_body = [{"uuid": "event1"}]
    mock_response_headers: dict[str, str] = {}
    mocker.patch.object(client_non_mtls, "http_request", return_value=(mock_response_body, mock_response_headers))

    events, _ = client_non_mtls.get_audit_log_events(
        created_after="2024-01-01T00:00:00Z", created_before=created_before, limit=100
    )

    assert len(events) == 1
    call_args = client_non_mtls.http_request.call_args
    params = call_args[1]["params"]

    if should_have_time_to:
        assert APIKeys.TIME_TO.value in params
        assert params[APIKeys.TIME_TO.value] == created_before
    else:
        assert APIKeys.TIME_TO.value not in params


@pytest.mark.parametrize(
    "paging_header,expected_result",
    [
        ("handle=", ""),  # IndexError case - empty after split
        ("handle=abc123", "abc123"),  # Normal case
        ("", None),  # No header
        ("no_handle_here", None),  # Missing handle= prefix
    ],
)
def test_extract_pagination_handle_edge_cases(client_non_mtls, paging_header, expected_result):
    """Tests _extract_pagination_handle handles various edge cases including IndexError."""
    headers = {"Paging": paging_header} if paging_header else {}
    result = client_non_mtls._extract_pagination_handle(headers)

    if expected_result == "":
        # For empty string case, accept either empty string or None
        assert result == "" or result is None
    else:
        assert result == expected_result


def test_extract_pagination_handle_index_error_coverage(client_non_mtls):
    """Tests _extract_pagination_handle IndexError exception path (lines 423-425)."""
    # This header will cause split to return a list with only one element
    # When trying to access index [1], it will raise IndexError
    headers = {"Paging": "handle="}
    result = client_non_mtls._extract_pagination_handle(headers)
    # Should return None or empty string when IndexError occurs
    assert result == "" or result is None


@pytest.mark.parametrize(
    "page_data,expected_count,expected_calls",
    [
        # Single page with no more pages
        ([(3, None)], 3, 1),
        # Multiple pages but stops when no handle
        ([(5, "handle1"), (3, None)], 8, 2),
        # Empty first page
        ([(0, None)], 0, 1),
    ],
)
def test_fetch_events_with_pagination_stopping_conditions(mocker, client_non_mtls, page_data, expected_count, expected_calls):
    """Tests fetch_events_with_pagination stops correctly under various conditions."""
    # Create mock events for each page
    side_effect_data = []
    for count, handle in page_data:
        events = [{"uuid": f"event{i}", "time": f"2024-01-0{i}T00:00:00Z"} for i in range(1, count + 1)]
        side_effect_data.append((events, handle))

    mocker.patch.object(client_non_mtls, "get_audit_log_events", side_effect=side_effect_data)

    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", None, 100)

    assert len(events) == expected_count
    assert client_non_mtls.get_audit_log_events.call_count == expected_calls


def test_fetch_events_with_pagination_exact_limit_reached(mocker, client_non_mtls):
    """Tests fetch_events_with_pagination stops when exactly max_events is reached (lines 496-497)."""
    # Create exactly 10 events in first page
    page1 = [{"uuid": f"event{i}", "time": f"2024-01-0{i}T00:00:00Z"} for i in range(1, 11)]

    mocker.patch.object(
        client_non_mtls,
        "get_audit_log_events",
        return_value=(page1, "handle_exists_but_should_not_fetch"),
    )

    # Request exactly 10 events
    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", None, 10)

    # Should get exactly 10 events and stop (not fetch next page)
    assert len(events) == 10
    # Should only call once since we reached the limit
    assert client_non_mtls.get_audit_log_events.call_count == 1


def test_fetch_events_with_pagination_discards_newer_events(mocker, client_non_mtls):
    """Tests fetch_events_with_pagination discards newer events when over limit (lines 509-511)."""
    # Create 15 events across two pages
    page1 = [{"uuid": f"event{i}", "time": f"2024-01-{i:02d}T00:00:00Z"} for i in range(1, 11)]
    page2 = [{"uuid": f"event{i}", "time": f"2024-01-{i:02d}T00:00:00Z"} for i in range(11, 16)]

    mocker.patch.object(
        client_non_mtls,
        "get_audit_log_events",
        side_effect=[(page1, "handle1"), (page2, None)],
    )

    # Request only 12 events (should discard 3 newest)
    events = fetch_events_with_pagination(client_non_mtls, "2024-01-01T00:00:00Z", None, 12)

    # Should get exactly 12 events (oldest ones)
    assert len(events) == 12
    # First event should be event1
    assert events[0]["uuid"] == "event1"
    # Last event should be event12 (not event15)
    assert events[-1]["uuid"] == "event12"
    # Verify we fetched both pages
    assert client_non_mtls.get_audit_log_events.call_count == 2


# ========================================
# Tests: add_time_to_events
# ========================================


@pytest.mark.parametrize(
    "input_events,expected_results",
    [
        # Success case with Z suffix
        (
            [
                {"uuid": "1", "time": "2024-01-01T00:00:00Z", "user": "test@example.com"},
                {"uuid": "2", "time": "2024-01-02T12:30:45Z", "action": "login"},
            ],
            [
                {"uuid": "1", "time": "2024-01-01T00:00:00Z", "user": "test@example.com", "_time": "2024-01-01T00:00:00"},
                {"uuid": "2", "time": "2024-01-02T12:30:45Z", "action": "login", "_time": "2024-01-02T12:30:45"},
            ],
        ),
        # SAP BTP format (no Z suffix)
        (
            [
                {"uuid": "1", "time": "2024-01-01T00:00:00", "user": "test@example.com"},
                {"uuid": "2", "time": "2024-01-02T12:30:45", "action": "login"},
            ],
            [
                {"uuid": "1", "time": "2024-01-01T00:00:00", "user": "test@example.com", "_time": "2024-01-01T00:00:00"},
                {"uuid": "2", "time": "2024-01-02T12:30:45", "action": "login", "_time": "2024-01-02T12:30:45"},
            ],
        ),
        # Missing time field
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
        # Invalid time format (fallback to original)
        (
            [{"uuid": "1", "time": "invalid-time-format", "user": "test@example.com"}],
            [{"uuid": "1", "time": "invalid-time-format", "user": "test@example.com", "_time": "invalid-time-format"}],
        ),
        # Empty list
        ([], []),
        # Time with microseconds
        (
            [{"uuid": "1", "time": "2024-01-01T00:00:00.123456Z"}],
            [{"uuid": "1", "time": "2024-01-01T00:00:00.123456Z", "_time": "2024-01-01T00:00:00"}],
        ),
        # Multiple events with mixed scenarios
        (
            [
                {"uuid": "1", "time": "2024-01-01T00:00:00Z"},
                {"uuid": "2", "time": "2024-01-02T00:00:00Z"},
                {"uuid": "3", "time": "2024-01-03T00:00:00Z"},
                {"uuid": "4"},  # Missing time
                {"uuid": "5", "time": "invalid"},  # Invalid time
            ],
            [
                {"uuid": "1", "time": "2024-01-01T00:00:00Z", "_time": "2024-01-01T00:00:00"},
                {"uuid": "2", "time": "2024-01-02T00:00:00Z", "_time": "2024-01-02T00:00:00"},
                {"uuid": "3", "time": "2024-01-03T00:00:00Z", "_time": "2024-01-03T00:00:00"},
                {"uuid": "4"},
                {"uuid": "5", "time": "invalid", "_time": "invalid"},
            ],
        ),
    ],
)
def test_add_time_to_events(input_events, expected_results):
    """Tests add_time_to_events handles various scenarios correctly."""
    add_time_to_events(input_events)
    assert input_events == expected_results


def test_add_time_to_events_preserves_all_fields():
    """Tests add_time_to_events preserves all other event fields."""
    events = [
        {
            "uuid": "123",
            "time": "2024-01-01T00:00:00Z",
            "user": "test@example.com",
            "action": "login",
            "ip": "192.168.1.1",
        }
    ]

    add_time_to_events(events)

    # All original fields should be preserved
    assert events[0]["uuid"] == "123"
    assert events[0]["time"] == "2024-01-01T00:00:00Z"
    assert events[0]["user"] == "test@example.com"
    assert events[0]["action"] == "login"
    assert events[0]["ip"] == "192.168.1.1"
    # _time should be added
    assert events[0]["_time"] == "2024-01-01T00:00:00"


# ========================================
# Tests: test_module Command
# ========================================


@pytest.mark.parametrize(
    "should_succeed,mock_return,mock_exception,expected_result",
    [
        (True, [{"uuid": "test"}], None, "ok"),  # Success case
        (
            False,
            None,
            DemistoException("Error [401] - Unauthorized"),
            "Authorization Error: Verify Client ID, Secret, or Certificates.",
        ),  # 401 error
        (
            False,
            None,
            DemistoException("Error [403] - Forbidden"),
            "Authorization Error: Verify Client ID, Secret, or Certificates.",
        ),  # 403 error
        (False, None, DemistoException("Error [500] - Internal Server Error"), None),  # Other error - should raise
    ],
)
def test_test_module(mocker, client_non_mtls, should_succeed, mock_return, mock_exception, expected_result):
    """Tests test_module returns 'ok' on success, auth error message for 401/403, or raises other errors."""
    if should_succeed:
        mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=mock_return)
        result = test_module(client_non_mtls)
        assert result == expected_result
    elif expected_result:  # Auth errors (401/403)
        mocker.patch.object(SAPBTP, "fetch_events_with_pagination", side_effect=mock_exception)
        result = test_module(client_non_mtls)
        assert result == expected_result
    else:  # Other errors should raise
        mocker.patch.object(SAPBTP, "fetch_events_with_pagination", side_effect=mock_exception)
        with pytest.raises(DemistoException, match="Internal Server Error"):
            test_module(client_non_mtls)


# ========================================
# Tests: get_events_command
# ========================================


def test_get_events_command_success(mocker, client_non_mtls):
    """Tests get_events_command returns correct CommandResults when should_push_events=False."""
    mock_events = [{"uuid": "123", "user": "test@example.com", "time": "2024-01-01T00:00:00Z"}]

    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=mock_events)

    args = {"start_time": "3 days ago", "limit": "10", "should_push_events": "false"}
    result = get_events_command(client_non_mtls, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SAPBTP.Event"
    assert result.outputs_key_field == "uuid"
    assert result.outputs == mock_events
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 1


def test_get_events_command_with_push_events(mocker, client_non_mtls):
    """Tests get_events_command pushes events to Cortex environment when should_push_events=True."""
    mock_events = [{"uuid": "123", "user": "test@example.com", "time": "2024-01-01T00:00:00Z"}]

    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(SAPBTP, "add_time_to_events")
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    args = {"start_time": "3 days ago", "limit": "10", "should_push_events": "true"}
    result = get_events_command(client_non_mtls, args)

    assert isinstance(result, str)
    assert "1 events" in result
    SAPBTP.add_time_to_events.assert_called_once_with(mock_events)  # type: ignore[attr-defined]
    SAPBTP.send_events_to_xsiam.assert_called_once_with(events=mock_events, vendor=Config.VENDOR, product=Config.PRODUCT)  # type: ignore[attr-defined]


def test_get_events_command_default_values(mocker, client_non_mtls):
    """Tests get_events_command uses default values."""
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    # Default should_push_events is true, but with empty events it returns CommandResults
    result = get_events_command(client_non_mtls, {})

    assert isinstance(result, CommandResults)
    assert result.outputs == []


def test_get_events_command_with_end_time(mocker, client_non_mtls):
    """Tests get_events_command handles end_time parameter."""
    mock_fetch = mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    args = {"start_time": "1 hour ago", "end_time": "now", "should_push_events": "false"}
    result = get_events_command(client_non_mtls, args)

    assert isinstance(result, CommandResults)
    assert result.outputs == []
    # Verify fetch_events_with_pagination was called with created_before parameter
    call_args = mock_fetch.call_args
    assert call_args[0][2] is not None  # max_events
    assert call_args[0][3] is not None  # created_before


# ========================================
# Tests: fetch_events_command
# ========================================


@pytest.mark.parametrize(
    "test_case,last_run,params,mock_events,expected_last_run,expected_events_sent",
    [
        (
            "first_run_no_config",
            {},
            {"max_fetch": 100},
            [{"uuid": "1", "time": "2024-01-01T00:00:00Z"}, {"uuid": "2", "time": "2024-01-01T01:00:00Z"}],
            {"last_fetch": "2024-01-01T01:00:00Z", "last_event_uuid": "2"},
            [{"uuid": "1", "time": "2024-01-01T00:00:00Z"}, {"uuid": "2", "time": "2024-01-01T01:00:00Z"}],
        ),
        (
            "with_last_run",
            {"last_fetch": "2024-01-01T00:00:00Z"},
            {"max_fetch": 100},
            [{"uuid": "3", "time": "2024-01-02T00:00:00Z"}],
            {"last_fetch": "2024-01-02T00:00:00Z", "last_event_uuid": "3"},
            [{"uuid": "3", "time": "2024-01-02T00:00:00Z"}],
        ),
        (
            "first_run_with_first_fetch",
            {},
            {"first_fetch": "7 days", "max_fetch": 100},
            [{"uuid": "1", "time": "2024-01-01T00:00:00Z"}],
            {"last_fetch": "2024-01-01T00:00:00Z", "last_event_uuid": "1"},
            [{"uuid": "1", "time": "2024-01-01T00:00:00Z"}],
        ),
        (
            "first_run_empty_first_fetch",
            {},
            {"first_fetch": ""},
            [{"uuid": "1", "time": "2024-01-01T00:00:00Z"}],
            {"last_fetch": "2024-01-01T00:00:00Z", "last_event_uuid": "1"},
            [{"uuid": "1", "time": "2024-01-01T00:00:00Z"}],
        ),
    ],
)
def test_fetch_events_command_scenarios(
    mocker, client_non_mtls, test_case, last_run, params, mock_events, expected_last_run, expected_events_sent
):
    """Tests fetch_events_command under various scenarios."""
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(SAPBTP, "add_time_to_events")
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    fetch_events_command(client_non_mtls)

    demisto.setLastRun.assert_called_once_with(expected_last_run)  # type: ignore[attr-defined]
    SAPBTP.add_time_to_events.assert_called_once_with(expected_events_sent)  # type: ignore[attr-defined]
    SAPBTP.send_events_to_xsiam.assert_called_once_with(  # type: ignore[attr-defined]
        events=expected_events_sent, vendor=Config.VENDOR, product=Config.PRODUCT
    )


# ========================================
# Tests: deduplicate_events
# ========================================


@pytest.mark.parametrize(
    "events,last_uuid,expected_count,expected_first_uuid,description",
    [
        # No deduplication needed - first run
        (
            [{"uuid": "1", "time": "2024-01-01T00:00:00Z"}, {"uuid": "2", "time": "2024-01-01T01:00:00Z"}],
            None,
            2,
            "1",
            "first_run_no_last_uuid",
        ),
        # No deduplication needed - empty events
        ([], "last_uuid", 0, None, "empty_events"),
        # Deduplication - last UUID found at beginning
        (
            [
                {"uuid": "1", "time": "2024-01-01T00:00:00Z"},
                {"uuid": "2", "time": "2024-01-01T01:00:00Z"},
                {"uuid": "3", "time": "2024-01-01T02:00:00Z"},
            ],
            "1",
            2,
            "2",
            "last_uuid_at_start",
        ),
        # Deduplication - last UUID found in middle
        (
            [
                {"uuid": "1", "time": "2024-01-01T00:00:00Z"},
                {"uuid": "2", "time": "2024-01-01T01:00:00Z"},
                {"uuid": "3", "time": "2024-01-01T02:00:00Z"},
            ],
            "2",
            1,
            "3",
            "last_uuid_in_middle",
        ),
        # Deduplication - last UUID found at end (all duplicates)
        (
            [
                {"uuid": "1", "time": "2024-01-01T00:00:00Z"},
                {"uuid": "2", "time": "2024-01-01T01:00:00Z"},
                {"uuid": "3", "time": "2024-01-01T02:00:00Z"},
            ],
            "3",
            0,
            None,
            "last_uuid_at_end",
        ),
        # Deduplication - last UUID not found (all new events)
        (
            [
                {"uuid": "4", "time": "2024-01-01T03:00:00Z"},
                {"uuid": "5", "time": "2024-01-01T04:00:00Z"},
            ],
            "3",
            2,
            "4",
            "last_uuid_not_found",
        ),
    ],
)
def test_deduplicate_events(events, last_uuid, expected_count, expected_first_uuid, description):
    """Tests deduplicate_events function with various scenarios."""
    from SAPBTP import deduplicate_events

    result = deduplicate_events(events, last_uuid)

    assert len(result) == expected_count, f"Failed for {description}: expected {expected_count} events, got {len(result)}"
    if expected_first_uuid:
        assert result[0]["uuid"] == expected_first_uuid, f"Failed for {description}: expected first UUID {expected_first_uuid}"


def test_deduplicate_events_preserves_order():
    """Tests that deduplicate_events preserves event order."""
    from SAPBTP import deduplicate_events

    events = [
        {"uuid": "1", "time": "2024-01-01T00:00:00Z", "data": "first"},
        {"uuid": "2", "time": "2024-01-01T01:00:00Z", "data": "second"},
        {"uuid": "3", "time": "2024-01-01T02:00:00Z", "data": "third"},
        {"uuid": "4", "time": "2024-01-01T03:00:00Z", "data": "fourth"},
    ]

    result = deduplicate_events(events, "2")

    assert len(result) == 2
    assert result[0]["uuid"] == "3"
    assert result[0]["data"] == "third"
    assert result[1]["uuid"] == "4"
    assert result[1]["data"] == "fourth"


# ========================================
# Tests: fetch_events_command with deduplication
# ========================================


def test_fetch_events_command_with_deduplication(mocker, client_non_mtls):
    """Tests fetch_events_command deduplicates events based on last_event_uuid."""
    # Simulate fetching events where some are duplicates
    mock_events = [
        {"uuid": "1", "time": "2024-01-01T00:00:00Z"},
        {"uuid": "2", "time": "2024-01-01T00:00:00Z"},  # Same timestamp as event 1
        {"uuid": "3", "time": "2024-01-01T01:00:00Z"},  # New event
    ]

    # Last run has UUID "2" - so we should skip events 1 and 2
    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00Z", "last_event_uuid": "2"})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 100})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(SAPBTP, "add_time_to_events")
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    fetch_events_command(client_non_mtls)

    # Should only send event 3 (new event after UUID "2")
    SAPBTP.add_time_to_events.assert_called_once_with([{"uuid": "3", "time": "2024-01-01T01:00:00Z"}])  # type: ignore[attr-defined]
    SAPBTP.send_events_to_xsiam.assert_called_once_with(  # type: ignore[attr-defined]
        events=[{"uuid": "3", "time": "2024-01-01T01:00:00Z"}], vendor=Config.VENDOR, product=Config.PRODUCT
    )
    # Last run should be updated to the last event in the original list (not filtered)
    demisto.setLastRun.assert_called_once_with({"last_fetch": "2024-01-01T01:00:00Z", "last_event_uuid": "3"})  # type: ignore[attr-defined]


def test_fetch_events_command_all_duplicates(mocker, client_non_mtls):
    """Tests fetch_events_command when all fetched events are duplicates."""
    mock_events = [
        {"uuid": "1", "time": "2024-01-01T00:00:00Z"},
        {"uuid": "2", "time": "2024-01-01T00:00:00Z"},
    ]

    # Last run has UUID "2" - all events are duplicates
    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00Z", "last_event_uuid": "2"})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 100})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(SAPBTP, "add_time_to_events")
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    fetch_events_command(client_non_mtls)

    # Should not send any events
    SAPBTP.add_time_to_events.assert_not_called()  # type: ignore[attr-defined]
    SAPBTP.send_events_to_xsiam.assert_not_called()  # type: ignore[attr-defined]
    # Last run should not be updated when no new events
    demisto.setLastRun.assert_not_called()  # type: ignore[attr-defined]


def test_fetch_events_command_no_events(mocker, client_non_mtls):
    """Tests fetch_events_command when no events are fetched."""
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    fetch_events_command(client_non_mtls)

    demisto.setLastRun.assert_not_called()  # type: ignore[attr-defined]
    SAPBTP.send_events_to_xsiam.assert_not_called()  # type: ignore[attr-defined]


def test_fetch_events_command_events_without_time(mocker, client_non_mtls):
    """Tests fetch_events_command handles events without time field."""
    mock_events = [{"uuid": "1"}, {"uuid": "2"}]

    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(SAPBTP, "add_time_to_events")
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    fetch_events_command(client_non_mtls)

    # Should not update last_run if events have no time field
    demisto.setLastRun.assert_not_called()  # type: ignore[attr-defined]
    SAPBTP.add_time_to_events.assert_called_once_with(mock_events)  # type: ignore[attr-defined]
    SAPBTP.send_events_to_xsiam.assert_called_once()  # type: ignore[attr-defined]


def test_fetch_events_command_state_protection_on_error(mocker, client_non_mtls):
    """Tests fetch_events_command does not update last_run when fetch fails."""
    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00Z"})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", side_effect=Exception("API Error"))
    mocker.patch.object(SAPBTP, "send_events_to_xsiam")

    # Should raise the exception
    with pytest.raises(Exception, match="API Error"):
        fetch_events_command(client_non_mtls)

    # Verify last_run was NOT updated (state protection)
    demisto.setLastRun.assert_not_called()  # type: ignore[attr-defined]


# ========================================
# Tests: Main Function
# ========================================


def test_main_invalid_command_fail(mocker):
    """Tests main() raises error for invalid command."""
    mocker.patch.object(demisto, "command", return_value="invalid-command")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "token_url": AUTH_SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": {"password": MOCK_CLIENT_SECRET},
        },
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
            "token_url": AUTH_SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": {"password": MOCK_CLIENT_SECRET},
            "auth_type": AuthType.NON_MTLS.value,
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
            "token_url": AUTH_SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": {"password": MOCK_CLIENT_SECRET},
            "auth_type": AuthType.NON_MTLS.value,
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
            "token_url": AUTH_SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": {"password": MOCK_CLIENT_SECRET},
            "auth_type": AuthType.NON_MTLS.value,
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
            "token_url": AUTH_SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": {"password": MOCK_CLIENT_SECRET},
            "auth_type": AuthType.NON_MTLS.value,
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


def test_main_with_mtls_cert_creation(mocker):
    """Tests main() creates mTLS certificates when auth_type is mTLS."""
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "token_url": AUTH_SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "certificate": MOCK_CERTIFICATE,
            "private_key": MOCK_PRIVATE_KEY,
            "auth_type": AuthType.MTLS.value,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    mock_create_cert = mocker.patch("SAPBTP.create_mtls_cert_files", return_value=("/tmp/cert.pem", "/tmp/key.pem"))
    mock_return_results = mocker.patch("SAPBTP.return_results")

    SAPBTP.main()

    mock_create_cert.assert_called_once_with(MOCK_CERTIFICATE, MOCK_PRIVATE_KEY)
    mock_return_results.assert_called_once_with("ok")


def test_main_mtls_client_receives_cert_data(mocker):
    """Tests that Client is initialized with cert_data tuple for mTLS."""
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "token_url": AUTH_SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "certificate": MOCK_CERTIFICATE,
            "private_key": MOCK_PRIVATE_KEY,
            "auth_type": AuthType.MTLS.value,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    mock_create_cert = mocker.patch("SAPBTP.create_mtls_cert_files", return_value=("/tmp/test_cert.pem", "/tmp/test_key.pem"))

    # Spy on Client initialization
    original_client = SAPBTP.Client
    client_instances = []

    def client_spy(*args, **kwargs):
        instance = original_client(*args, **kwargs)
        client_instances.append(instance)
        return instance

    mocker.patch("SAPBTP.Client", side_effect=client_spy)
    mocker.patch("SAPBTP.return_results")

    SAPBTP.main()

    # Verify cert files were created
    mock_create_cert.assert_called_once_with(MOCK_CERTIFICATE, MOCK_PRIVATE_KEY)

    # Verify Client was initialized with cert_data
    assert len(client_instances) == 1
    client = client_instances[0]
    assert client.cert_data == ("/tmp/test_cert.pem", "/tmp/test_key.pem")
    assert client.auth_type == AuthType.MTLS.value
    assert client.client_secret is None


def test_main_non_mtls_client_no_cert_data(mocker):
    """Tests that Client is initialized without cert_data for Non-mTLS."""
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "token_url": AUTH_SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "client_secret": {"password": MOCK_CLIENT_SECRET},
            "auth_type": AuthType.NON_MTLS.value,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    # Spy on Client initialization
    original_client = SAPBTP.Client
    client_instances = []

    def client_spy(*args, **kwargs):
        instance = original_client(*args, **kwargs)
        client_instances.append(instance)
        return instance

    mocker.patch("SAPBTP.Client", side_effect=client_spy)
    mocker.patch("SAPBTP.return_results")

    SAPBTP.main()

    # Verify Client was initialized without cert_data
    assert len(client_instances) == 1
    client = client_instances[0]
    assert client.cert_data is None
    assert client.auth_type == AuthType.NON_MTLS.value
    assert client.client_secret == MOCK_CLIENT_SECRET


def test_main_parse_params_error(mocker):
    """Tests main() handles parameter parsing errors."""
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "params", return_value={})  # Missing required params
    mocker.patch.object(demisto, "args", return_value={})

    mock_return_error = mocker.patch("SAPBTP.return_error")

    SAPBTP.main()

    mock_return_error.assert_called_once()
    error_message = mock_return_error.call_args[0][0]
    assert "API URL is required" in error_message


def test_main_cleans_up_mtls_cert_files(mocker):
    """Tests main() cleans up temporary mTLS certificate files in finally block."""
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "token_url": AUTH_SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "certificate": MOCK_CERTIFICATE,
            "private_key": MOCK_PRIVATE_KEY,
            "auth_type": AuthType.MTLS.value,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    # Mock cert file creation
    mock_cert_path = "/tmp/test_cert_cleanup.pem"
    mock_key_path = "/tmp/test_key_cleanup.key"
    mocker.patch("SAPBTP.create_mtls_cert_files", return_value=(mock_cert_path, mock_key_path))

    # Mock os.path.exists and os.remove
    mocker.patch("os.path.exists", return_value=True)
    mock_remove = mocker.patch("os.remove")
    mocker.patch("SAPBTP.return_results")

    SAPBTP.main()

    # Verify cleanup was called for both files
    assert mock_remove.call_count == 2
    mock_remove.assert_any_call(mock_cert_path)
    mock_remove.assert_any_call(mock_key_path)


def test_main_cleanup_handles_missing_files(mocker):
    """Tests main() cleanup handles case where files don't exist."""
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "token_url": AUTH_SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "certificate": MOCK_CERTIFICATE,
            "private_key": MOCK_PRIVATE_KEY,
            "auth_type": AuthType.MTLS.value,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    mock_cert_path = "/tmp/test_cert_missing.pem"
    mock_key_path = "/tmp/test_key_missing.key"
    mocker.patch("SAPBTP.create_mtls_cert_files", return_value=(mock_cert_path, mock_key_path))

    # Mock files don't exist
    mocker.patch("os.path.exists", return_value=False)
    mock_remove = mocker.patch("os.remove")
    mocker.patch("SAPBTP.return_results")

    # Should not raise an error
    SAPBTP.main()

    # os.remove should not be called since files don't exist
    mock_remove.assert_not_called()


def test_main_cleanup_handles_removal_error(mocker):
    """Tests main() cleanup handles errors during file removal gracefully."""
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "token_url": AUTH_SERVER_URL,
            "client_id": MOCK_CLIENT_ID,
            "certificate": MOCK_CERTIFICATE,
            "private_key": MOCK_PRIVATE_KEY,
            "auth_type": AuthType.MTLS.value,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(SAPBTP, "fetch_events_with_pagination", return_value=[])

    mock_cert_path = "/tmp/test_cert_error.pem"
    mock_key_path = "/tmp/test_key_error.key"
    mocker.patch("SAPBTP.create_mtls_cert_files", return_value=(mock_cert_path, mock_key_path))

    mocker.patch("os.path.exists", return_value=True)
    # Simulate error during removal
    mocker.patch("os.remove", side_effect=OSError("Permission denied"))
    mocker.patch("SAPBTP.return_results")

    # Should not raise an error - cleanup errors are logged but not raised
    SAPBTP.main()
