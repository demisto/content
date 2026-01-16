import json
import os
import sys
import time
import types

import pytest
from CommonServerPython import *

# Mock DemistoClassApiModule before CapeSandbox is imported
mock_demisto_class_api_module = types.ModuleType("DemistoClassApiModule")
sys.modules["DemistoClassApiModule"] = mock_demisto_class_api_module

# Import CapeSandbox after mock setup - this is intentional and required
import CapeSandbox  # noqa: E402
from CapeSandbox import (  # noqa: E402
    FILE_TYPE_FILE,
    FILE_TYPE_NETWORK_DUMP,
    FILE_TYPE_REPORT,
    FILE_TYPE_SCREENSHOT,
    CapeSandboxClient,
    build_file_name,
    build_submit_form,
    cape_cuckoo_status_get_command,
    cape_file_submit_command,
    cape_file_view_command,
    cape_machines_list_command,
    cape_pcap_file_download_command,
    cape_sample_file_download_command,
    cape_task_delete_command,
    cape_task_report_get_command,
    cape_task_screenshot_download_command,
    cape_tasks_list_command,
    cape_url_submit_command,
    extract_entry_file_data,
    is_valid_md5,
    is_valid_sha1,
    is_valid_sha256,
    parse_integration_params,
)

# ========================================
# Constants
# ========================================

SERVER_URL = "http://test.example.com"
TEST_DATA_PATH_SUFFIX = "test_data"
INTEGRATION_DIR_REL = "Packs/CapeSandbox/Integrations/CapeSandbox/"

MOCK_MD5 = "00112233445566778899aabbccddeeff"
MOCK_SHA1 = "0011223344556677889900112233445566778899"
MOCK_SHA256 = "0011223344556677889900112233445566778899001122334455667788990011"


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


def util_load_file(file_name):
    """Loads a binary file from the test_data directory."""
    path = get_full_path_unified(file_name)
    with open(path, "rb") as f:
        return f.read()


def compare_string_ignore_case(actual, expected):
    """Compares two strings ignoring case."""
    if actual is None or expected is None:
        return actual == expected
    return str(actual).lower() == str(expected).lower()


# ========================================
# Fixtures
# ========================================


@pytest.fixture()
def client():
    """Returns a CapeSandboxClient instance for testing."""
    return CapeSandboxClient(
        base_url=SERVER_URL,
        verify=True,
        proxy=True,
        api_token="MOCK_API_TOKEN_FOR_TESTING",
        username=None,
        password=None,
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
    "params,expected_error",
    [
        ({"url": ""}, "Server URL.+is required"),
        ({}, "Server URL.+is required"),
    ],
)
def test_parse_integration_params_missing_url_fail(params, expected_error):
    """Tests parse_integration_params fails if 'url' is missing or empty."""
    with pytest.raises(DemistoException, match=expected_error):
        parse_integration_params(params)


@pytest.mark.parametrize(
    "params,expected_api_token,expected_username,expected_verify,expected_proxy",
    [
        # API token takes precedence over username/password
        (
            {
                "url": SERVER_URL,
                "api_token": "API_TOKEN",
                "username": "user",
                "password": "pwd",
                "insecure": True,
                "proxy": True,
                "credentials": {"identifier": "user_cred", "password": "pwd_cred"},
            },
            "API_TOKEN",
            "user_cred",
            False,
            True,
        ),
        # token_credentials takes precedence over api_token
        (
            {
                "url": SERVER_URL,
                "token_credentials": {"password": "TOKEN_FROM_CREDS"},
                "api_token": "API_TOKEN_DIRECT",
                "insecure": False,
                "proxy": False,
            },
            "TOKEN_FROM_CREDS",
            None,
            True,
            False,
        ),
        # URL with trailing slash is stripped
        (
            {"url": f"{SERVER_URL}/", "api_token": "TOKEN"},
            "TOKEN",
            None,
            True,
            False,
        ),
        # credentials identifier takes precedence over username
        (
            {
                "url": SERVER_URL,
                "credentials": {"identifier": "cred_user", "password": "cred_pwd"},
                "username": "direct_user",
                "password": "direct_pwd",
            },
            None,
            "cred_user",
            True,
            False,
        ),
    ],
)
def test_parse_integration_params_various_configs(params, expected_api_token, expected_username, expected_verify, expected_proxy):
    """Tests parse_integration_params handles various configuration scenarios."""
    result = parse_integration_params(params)
    assert result["api_token"] == expected_api_token
    assert result["username"] == expected_username
    assert result["verify_certificate"] == expected_verify
    assert result["proxy"] == expected_proxy
    assert result["base_url"] == SERVER_URL


def test_build_submit_form_full_and_url_mode():
    """Tests build_submit_form correctly assigns all optional args and handles URL mode."""
    args = {
        "url": "http://test.example.com",
        "package": "win_exe",
        "timeout": 120,
        "priority": 2,
        "memory": "True",
        "enforce_timeout": "false",
        "tags": "test_tag",
    }

    form_url = build_submit_form(args, url_mode=True)
    assert form_url["url"] == "http://test.example.com"
    assert form_url["package"] == "win_exe"
    assert form_url["timeout"] == 120
    assert form_url["priority"] == 2
    assert form_url["memory"] == "1"
    assert "enforce_timeout" not in form_url

    form_file = build_submit_form(args, url_mode=False)
    assert "url" not in form_file
    assert "memory" in form_file


@pytest.mark.parametrize(
    "args,url_mode,check_keys_present,check_keys_absent",
    [
        # All optional parameters with URL mode
        (
            {
                "url": "http://test.example.com",
                "package": "win_exe",
                "timeout": 120,
                "priority": 2,
                "memory": "True",
                "enforce_timeout": "True",
                "tags": "test_tag",
                "options": "opt1,opt2",
                "machine": "win10",
                "platform": "windows",
                "custom": "custom_data",
                "clock": "1970-01-01 12:00:00",
            },
            True,
            [
                "url",
                "package",
                "timeout",
                "priority",
                "memory",
                "enforce_timeout",
                "tags",
                "options",
                "machine",
                "platform",
                "custom",
                "clock",
            ],
            [],
        ),
        # File mode excludes URL
        (
            {"package": "win_exe", "memory": "True", "url": "http://test.example.com"},
            False,
            ["package", "memory"],
            ["url"],
        ),
        # Empty args
        ({}, False, [], []),
        # Boolean false values excluded
        (
            {"memory": "false", "enforce_timeout": "False", "package": "exe"},
            False,
            ["package"],
            ["memory", "enforce_timeout"],
        ),
    ],
)
def test_build_submit_form_all_parameters(args, url_mode, check_keys_present, check_keys_absent):
    """Tests build_submit_form with comprehensive parameter combinations."""
    form = build_submit_form(args, url_mode=url_mode)

    for key in check_keys_present:
        assert key in form, f"Expected key '{key}' not in form"

    for key in check_keys_absent:
        assert key not in form, f"Unexpected key '{key}' found in form"


@pytest.mark.parametrize(
    "identifier,file_type_info,file_format,screenshot_number,expected",
    [
        (101, FILE_TYPE_SCREENSHOT, None, 5, "cape_task_101_screenshot_5.png"),
        (102, FILE_TYPE_REPORT, "csv", None, "cape_task_102_report.csv"),
        (MOCK_MD5, FILE_TYPE_FILE, None, None, f"cape_task_{MOCK_MD5}_file.json"),
        (103, FILE_TYPE_NETWORK_DUMP, None, None, "cape_task_103_network_dump.pcap"),
        ("12345", None, "txt", None, "cape_task_12345.txt"),
        ("404", None, None, None, "cape_task_404.dat"),
    ],
)
def test_build_file_name_all_types(identifier, file_type_info, file_format, screenshot_number, expected):
    """Tests build_file_name constructs filenames for all supported types."""
    result = build_file_name(
        identifier,
        file_type_info=file_type_info,
        file_format=file_format,
        screenshot_number=screenshot_number,
    )
    assert result == expected


@pytest.mark.parametrize(
    "identifier,file_type_info,file_format,expected",
    [
        # Report with different formats
        (101, FILE_TYPE_REPORT, "pdf", "cape_task_101_report.pdf"),
        (102, FILE_TYPE_REPORT, "html", "cape_task_102_report.html"),
        (103, FILE_TYPE_REPORT, "zip", "cape_task_103_report.zip"),
        # File with different formats
        (201, FILE_TYPE_FILE, "bin", "cape_task_201_file.bin"),
        (202, FILE_TYPE_FILE, "exe", "cape_task_202_file.exe"),
    ],
)
def test_build_file_name_report_formats(identifier, file_type_info, file_format, expected):
    """Tests build_file_name with various report and file formats."""
    result = build_file_name(identifier, file_type_info=file_type_info, file_format=file_format)
    assert result == expected


@pytest.mark.parametrize(
    "status,expected",
    [
        ("reported", True),
        ("running", False),
        ("pending", False),
        ("completed", False),
        ("", False),
        ("REPORTED", False),
    ],
)
def test_status_is_reported(status, expected):
    """Tests status_is_reported function correctly identifies reported status."""
    assert CapeSandbox.status_is_reported(status) is expected


def test_extract_entry_file_data_not_found_fail(mocker):
    """Tests extract_entry_file_data raises DemistoException on missing entry."""
    mocker.patch.object(demisto, "getFilePath", return_value={})
    with pytest.raises(DemistoException, match="Could not find file or entry"):
        extract_entry_file_data("not_an_entry")


def test_extract_entry_file_data_general_exception_fail(mocker):
    """Tests extract_entry_file_data handles generic exceptions."""
    mocker.patch.object(demisto, "getFilePath", side_effect=Exception("API error"))
    with pytest.raises(DemistoException, match="An unexpected error occurred"):
        extract_entry_file_data("entry_id")


def test_extract_entry_file_data_uses_name_field(mocker):
    """Tests extract_entry_file_data uses 'name' key when available."""
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "/tmp/a.txt", "name": "custom.txt"},
    )
    path, name = extract_entry_file_data("entry_id")
    assert name == "custom.txt"


def test_extract_entry_file_data_uses_basename_fallback(mocker):
    """Tests extract_entry_file_data uses os.path.basename if 'name' is missing."""
    mocker.patch.object(demisto, "getFilePath", return_value={"path": "/tmp/file.exe"})
    path, name = extract_entry_file_data("entry_id")
    assert name == "file.exe"


@pytest.mark.parametrize(
    "validator_func,valid_hash,invalid_hash",
    [
        (is_valid_md5, MOCK_MD5, "BADHASH"),
        (is_valid_sha1, MOCK_SHA1, MOCK_MD5),
        (is_valid_sha256, MOCK_SHA256, MOCK_MD5),
    ],
)
def test_hash_validators(validator_func, valid_hash, invalid_hash):
    """Tests all hash format validation functions."""
    assert validator_func(valid_hash)
    assert not validator_func(invalid_hash)
    assert not validator_func(None)


# ========================================
# Tests: Client Initialization & Authentication
# ========================================


@pytest.mark.parametrize(
    "api_token,username,password",
    [
        (None, None, None),
        (None, "user", None),
    ],
)
def test_client_init_auth_fail(api_token, username, password):
    """Tests client initialization fails if auth is missing or incomplete."""
    with pytest.raises(
        DemistoException,
        match=r"Either API token or Username \+ Password must be provided",
    ):
        CapeSandboxClient(
            base_url=SERVER_URL,
            verify=True,
            proxy=True,
            api_token=api_token,
            username=username,
            password=password,
        )


def test_ensure_token_uses_api_token(client):
    """Tests ensure_token returns api_token when available."""
    assert client.ensure_token() == "MOCK_API_TOKEN_FOR_TESTING"


def test_ensure_token_uses_cached_token(mocker, mock_context):
    """Tests ensure_token uses valid token from cache."""
    mock_time = int(time.time()) + 3600
    set_integration_context({"auth_info": {"token": "CACHED_TOKEN", "valid_until": str(mock_time)}})

    client_auth = CapeSandboxClient(
        base_url=SERVER_URL,
        verify=True,
        proxy=True,
        api_token=None,
        username="user",
        password="pwd",
    )

    mocker.patch.object(CapeSandbox.time, "time", return_value=int(time.time()) + 10)

    assert client_auth.ensure_token() == "CACHED_TOKEN"


def test_ensure_token_invalid_cache_renewal(mocker, mock_context, requests_mock):
    """Tests token renewal logic when cache is invalid."""
    set_integration_context({"auth_info": {"token": "BAD_TOKEN", "valid_until": "NOT_A_NUMBER"}})

    requests_mock.post(
        f"{SERVER_URL}/{CapeSandbox.API_AUTH}",
        json={"token": "NEW_TOKEN"},
        status_code=200,
    )

    client_auth = CapeSandboxClient(
        base_url=SERVER_URL,
        verify=True,
        proxy=True,
        api_token=None,
        username="user",
        password="pwd",
    )
    token = client_auth.ensure_token()

    assert token == "NEW_TOKEN"
    assert get_integration_context().get("auth_info", {}).get("token") == "NEW_TOKEN"


def test_ensure_token_expired_renewal(mocker, mock_context, requests_mock):
    """Tests token renewal logic when cache is expired."""
    mock_time = int(time.time()) - 3600
    set_integration_context({"auth_info": {"token": "EXPIRED_TOKEN", "valid_until": str(mock_time)}})

    requests_mock.post(
        f"{SERVER_URL}/{CapeSandbox.API_AUTH}",
        json={"token": "NEW_TOKEN_2"},
        status_code=200,
    )

    client_auth = CapeSandboxClient(
        base_url=SERVER_URL,
        verify=True,
        proxy=True,
        api_token=None,
        username="user",
        password="pwd",
    )
    token = client_auth.ensure_token()

    assert token == "NEW_TOKEN_2"


def test_ensure_token_renewal_api_fail(mocker, requests_mock):
    """Tests token renewal fails if API doesn't return a token key."""
    requests_mock.post(
        f"{SERVER_URL}/{CapeSandbox.API_AUTH}",
        json={"error": "failed"},
        status_code=200,
    )

    client_auth = CapeSandboxClient(
        base_url=SERVER_URL,
        verify=True,
        proxy=True,
        api_token=None,
        username="user",
        password="pwd",
    )

    with pytest.raises(DemistoException, match="Failed to obtain API token from CAPE response"):
        client_auth.ensure_token()


# ========================================
# Tests: Client HTTP & Error Handling
# ========================================


@pytest.mark.parametrize(
    "error_response,expected_match",
    [
        ({"error": True, "error_value": "Task not found."}, "Task not found"),
        ({"error": True, "message": "Internal Server Error."}, "Internal Server Error"),
        ({"error": True}, "Unknown API error occurred"),
    ],
)
def test_http_request_api_error_check(error_response, expected_match):
    """Tests _check_for_api_error successfully detects and raises DemistoException."""
    client = CapeSandboxClient(base_url=SERVER_URL, verify=True, proxy=True, api_token="TOKEN")
    with pytest.raises(DemistoException, match=expected_match):
        client._check_for_api_error(error_response, "test-suffix", "json")


@pytest.mark.parametrize(
    "binary_response,resp_type,expected_match",
    [
        # Binary content that contains JSON error
        (
            b'{"error": true, "error_value": "No screenshots created for task 23"}',
            "content",
            "No screenshots created",
        ),
        # Binary content that contains JSON error with message field
        (b'{"error": true, "message": "File not found"}', "content", "File not found"),
        # Binary content that contains JSON error without specific message
        (b'{"error": true}', "content", "Unknown API error occurred"),
    ],
)
def test_check_for_api_error_binary_json_error(binary_response, resp_type, expected_match):
    """Tests _check_for_api_error detects JSON errors in binary content responses."""
    client = CapeSandboxClient(base_url=SERVER_URL, verify=True, proxy=True, api_token="TOKEN")
    with pytest.raises(DemistoException, match=expected_match):
        client._check_for_api_error(binary_response, "test-suffix", resp_type)


@pytest.mark.parametrize(
    "binary_response,resp_type",
    [
        # Valid binary content (not JSON)
        (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "content"),
        # Binary content with invalid JSON
        (b"{invalid json}", "content"),
        # Binary content that's valid JSON but no error
        (b'{"status": "success", "data": "test"}', "content"),
        # Empty binary content
        (b"", "content"),
    ],
)
def test_check_for_api_error_binary_valid_content(binary_response, resp_type):
    """Tests _check_for_api_error doesn't raise for valid binary content."""
    client = CapeSandboxClient(base_url=SERVER_URL, verify=True, proxy=True, api_token="TOKEN")
    # Should not raise any exception
    client._check_for_api_error(binary_response, "test-suffix", resp_type)


def test_check_for_api_error_json_response_type():
    """Tests _check_for_api_error handles dict responses for json resp_type."""
    client = CapeSandboxClient(base_url=SERVER_URL, verify=True, proxy=True, api_token="TOKEN")
    # Should raise for error dict
    with pytest.raises(DemistoException, match="Task not found"):
        client._check_for_api_error({"error": True, "error_value": "Task not found"}, "test-suffix", "json")

    # Should not raise for non-error dict
    client._check_for_api_error({"status": "success", "data": []}, "test-suffix", "json")


@pytest.mark.parametrize(
    "limit,offset,expected_match",
    [
        (0, 0, "limit must be > 0"),
        (1, -1, "offset must be >= 0"),
    ],
)
def test_list_tasks_invalid_pagination_fail(client, limit, offset, expected_match):
    """Tests list_tasks fails on invalid limit/offset."""
    with pytest.raises(DemistoException, match=expected_match):
        client.list_tasks(limit=limit, offset=offset)


def test_list_tasks_happy_path(mocker, client):
    """Tests list_tasks calls API correctly."""
    mocker.patch.object(client, "_http_request", return_value={"data": []})
    client.list_tasks(limit=10, offset=5)
    client._http_request.assert_called_with(
        method="GET",
        headers=mocker.ANY,
        url_suffix=mocker.ANY,
        data=None,
        files=None,
        resp_type=mocker.ANY,
        ok_codes=mocker.ANY,
    )


@pytest.mark.parametrize(
    "method_name,hash_type",
    [
        ("files_view_by_md5", "MD5"),
        ("files_get_by_sha1", "SHA1"),
        ("files_view_by_sha256", "SHA256"),
    ],
)
def test_invalid_hash_format_fail(client, method_name, hash_type):
    """Tests that client methods fail on invalid hash format."""
    method = getattr(client, method_name)
    with pytest.raises(DemistoException, match=f"Invalid {hash_type} hash format"):
        method("bad_hash")


def test_view_machine_missing_name_fail(client):
    """Tests view_machine fails if machine_name is missing."""
    with pytest.raises(DemistoException, match="machine_name is required"):
        client.view_machine("")


# ========================================
# Tests: test-module Command
# ========================================
# Tests: 429 Rate Limit Handling
# ========================================


def test_extract_retry_wait_time_from_json_detail(client):
    """Tests _extract_retry_wait_time extracts seconds from JSON error message."""
    error_msg = 'Error in API call [429] - {"detail": "Request was throttled. Expected available in 35 seconds."}'
    wait_time = client._extract_retry_wait_time(error_msg)
    assert wait_time == 35


def test_extract_retry_wait_time_with_single_quotes(client):
    """Tests _extract_retry_wait_time handles single quotes in JSON."""
    error_msg = "Error [429] - {'detail': 'Expected available in 120 seconds.'}"
    wait_time = client._extract_retry_wait_time(error_msg)
    assert wait_time == 120


def test_extract_retry_wait_time_no_match_returns_default(client):
    """Tests _extract_retry_wait_time returns default delay when no match found."""
    error_msg = "Error [429] - Too Many Requests"
    wait_time = client._extract_retry_wait_time(error_msg)
    assert wait_time == CapeSandbox.RETRY_BASE_DELAY


def test_extract_retry_wait_time_invalid_json_returns_default(client):
    """Tests _extract_retry_wait_time returns default on invalid JSON."""
    error_msg = "Error [429] - {invalid json"
    wait_time = client._extract_retry_wait_time(error_msg)
    assert wait_time == CapeSandbox.RETRY_BASE_DELAY


def test_handle_429_error_should_retry(mocker, client):
    """Tests _handle_429_error returns True for 429 error within retry limit."""
    error = DemistoException("Error [429] - Too Many Requests")
    mocker.patch.object(client, "_extract_retry_wait_time", return_value=5)
    mocker.patch.object(CapeSandbox.time, "sleep")

    should_retry = client._handle_429_error(error, attempt=0, method="GET", endpoint="/test")

    assert should_retry is True
    CapeSandbox.time.sleep.assert_called_once_with(5)


def test_handle_429_error_max_retries_exceeded(mocker, client, capfd):
    """Tests _handle_429_error returns False when max retries exceeded."""
    error = DemistoException("Error [429] - Too Many Requests")
    mocker.patch.object(client, "_extract_retry_wait_time", return_value=5)

    # Attempt 2 is the last attempt (0, 1, 2 = 3 attempts total)
    with capfd.disabled():
        should_retry = client._handle_429_error(
            error,
            attempt=CapeSandbox.MAX_RETRY_ATTEMPTS - 1,
            method="GET",
            endpoint="/test",
        )

    assert should_retry is False


def test_handle_429_error_non_429_error_no_retry(client):
    """Tests _handle_429_error returns False for non-429 errors."""
    error = DemistoException("Error [500] - Internal Server Error")

    should_retry = client._handle_429_error(error, attempt=0, method="GET", endpoint="/test")

    assert should_retry is False


def test_http_request_retries_on_429(mocker, client):
    """Tests http_request retries on 429 error and succeeds on second attempt."""
    # First call raises 429, second call succeeds
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=[
            DemistoException('Error [429] - {"detail": "Expected available in 5 seconds."}'),
            {"data": "success"},
        ],
    )
    mocker.patch.object(CapeSandbox.time, "sleep")

    result = client.http_request("GET", url_suffix="/test")

    assert result == {"data": "success"}
    assert client._http_request.call_count == 2
    CapeSandbox.time.sleep.assert_called_once()


def test_http_request_fails_after_max_retries(mocker, client, capfd):
    """Tests http_request raises error after max retry attempts."""
    error_429 = DemistoException("Error [429] - Too Many Requests")
    mocker.patch.object(client, "_http_request", side_effect=error_429)
    mocker.patch.object(CapeSandbox.time, "sleep")

    with capfd.disabled(), pytest.raises(DemistoException, match="Too Many Requests"):
        client.http_request("GET", url_suffix="/test")

    # Should attempt MAX_RETRY_ATTEMPTS times
    assert client._http_request.call_count == CapeSandbox.MAX_RETRY_ATTEMPTS


def test_http_request_non_429_error_no_retry(mocker, client):
    """Tests http_request doesn't retry on non-429 errors."""
    error_500 = DemistoException("Error [500] - Internal Server Error")
    mocker.patch.object(client, "_http_request", side_effect=error_500)

    with pytest.raises(DemistoException, match="Internal Server Error"):
        client.http_request("GET", url_suffix="/test")

    # Should only attempt once (no retries)
    assert client._http_request.call_count == 1


# ========================================


def test_test_module(mocker, client):
    """Tests test_module command returns 'ok'."""
    mocker.patch.object(client, "ensure_token", return_value="TOKEN_OK")
    result = CapeSandbox.test_module(client)
    assert result == "ok"


def test_test_module_failure(mocker, client):
    """Tests test_module command fails when connectivity fails."""
    client_auth = CapeSandboxClient(
        base_url=SERVER_URL,
        verify=True,
        proxy=True,
        api_token=None,
        username="user",
        password="pwd",
    )
    mocker.patch.object(client_auth, "ensure_token", side_effect=DemistoException("Auth server down."))

    with pytest.raises(DemistoException, match="Auth server down"):
        CapeSandbox.test_module(client_auth)


# ========================================
# Tests: File & URL Submission Commands
# ========================================


def test_cape_file_submit_command(mocker, client):
    """Tests cape_file_submit_command returns correct outputs."""
    mocker.patch.object(
        CapeSandbox,
        "extract_entry_file_data",
        return_value=("test_data/test_file.txt", "test_file.txt"),
    )
    mocker.patch.object(
        client,
        "submit_file",
        return_value={"data": {"task_ids": [123]}},
    )
    mocker.patch.object(
        CapeSandbox,
        "initiate_polling",
        return_value=CommandResults(
            readable_output="Polling initiated for task 123",
            outputs={"id": 123, "target": "test_file.txt", "status": "pending"},
            outputs_prefix="Cape.Task.File",
        ),
    )

    args = {"entry_id": "test_entry_id"}
    result = cape_file_submit_command(client, args)
    assert compare_string_ignore_case(result.readable_output, "Polling initiated for task 123")
    assert result.outputs_prefix == "Cape.Task.File"
    assert isinstance(result.outputs, dict)
    outputs = result.outputs
    assert isinstance(outputs, dict)
    assert outputs.get("id") == 123


def test_cape_file_submit_command_no_task_id_fail(mocker, client):
    """Tests submission fails if API returns no task ID."""
    mocker.patch.object(
        CapeSandbox,
        "extract_entry_file_data",
        return_value=("path/to/file", "file.exe"),
    )
    mocker.patch.object(client, "submit_file", return_value={"data": {"task_ids": []}})

    with pytest.raises(DemistoException, match="No task id returned from CAPE"):
        cape_file_submit_command(client, {"entry_id": "e_id"})


def test_cape_file_submit_command_pcap_logic(mocker, client):
    """Tests submission correctly identifies and sets the pcap flag."""
    mocker.patch.object(
        CapeSandbox,
        "extract_entry_file_data",
        return_value=("path/to/file.pcap", "file.pcap"),
    )
    mocker.patch.object(client, "submit_file", return_value={"data": {"task_ids": [100]}})
    mocker.patch.object(CapeSandbox, "initiate_polling", return_value=CommandResults())

    cape_file_submit_command(client, {"entry_id": "e_id"})

    client.submit_file.assert_called_with(form=mocker.ANY, file_path=mocker.ANY, is_pcap=True)


def test_cape_file_submit_file_not_found_fail(mocker, client):
    """Tests file submission fails when file is not found."""
    mocker.patch.object(
        CapeSandbox,
        "extract_entry_file_data",
        side_effect=DemistoException("Could not find file with entry ID 'invalid_id'."),
    )
    args = {"entry_id": "invalid_id"}

    with pytest.raises(DemistoException) as excinfo:
        cape_file_submit_command(client, args)

    assert "could not find file" in str(excinfo.value).lower()


def test_cape_url_submit_command(mocker, client):
    """Tests cape_url_submit_command returns correct outputs."""
    mocker.patch.object(
        client,
        "submit_url",
        return_value={"data": {"task_ids": [456]}},
    )
    mocker.patch.object(
        CapeSandbox,
        "initiate_polling",
        return_value=CommandResults(
            readable_output="Polling initiated for URL task 456",
            outputs={
                "id": 456,
                "target": "http://test.example.com",
                "status": "pending",
            },
            outputs_prefix="Cape.Task.Url",
        ),
    )

    args = {"url": "http://test.example.com"}
    result = cape_url_submit_command(client, args)
    assert compare_string_ignore_case(result.readable_output, "Polling initiated for URL task 456")
    assert result.outputs_prefix == "Cape.Task.Url"
    assert isinstance(result.outputs, dict)
    outputs = result.outputs
    assert isinstance(outputs, dict)
    assert outputs.get("id") == 456


def test_cape_url_submit_command_no_url_fail(client):
    """Tests URL submission fails if URL argument is missing."""
    with pytest.raises(KeyError):
        cape_url_submit_command(client, {})


def test_cape_url_submit_command_no_task_id_fail(mocker, client):
    """Tests URL submission fails if API returns no task ID."""
    mocker.patch.object(client, "submit_url", return_value={"data": {"task_ids": None}})

    with pytest.raises(DemistoException, match="No task id returned from CAPE"):
        cape_url_submit_command(client, {"url": "http://test.example.com"})


# ========================================
# Tests: File View & Download Commands
# ========================================


@pytest.mark.parametrize(
    "id_type,id_value,client_method",
    [
        ("task_id", "123", "files_view_by_task"),
        ("md5", MOCK_MD5, "files_view_by_md5"),
        ("sha256", MOCK_SHA256, "files_view_by_sha256"),
    ],
)
def test_cape_file_view_command_by_id_type(mocker, client, id_type, id_value, client_method):
    """Tests cape_file_view_command with different ID types."""
    mocker.patch.object(
        client,
        client_method,
        return_value=util_load_json("cape_file_view_response.json"),
    )
    args = {id_type: id_value}
    result = cape_file_view_command(client, args)
    assert isinstance(result.outputs, dict)
    outputs = result.outputs
    assert isinstance(outputs, dict)
    assert outputs["id"] == "test_task_id"


@pytest.mark.parametrize(
    "id_type,id_value,client_method,expected_filename",
    [
        ("task_id", "123", "files_get_by_task", "cape_task_123_file.bin"),
        ("md5", MOCK_MD5, "files_get_by_md5", f"cape_file_{MOCK_MD5}.bin"),
        ("sha1", MOCK_SHA1, "files_get_by_sha1", f"cape_file_{MOCK_SHA1}.bin"),
        ("sha256", MOCK_SHA256, "files_get_by_sha256", f"cape_file_{MOCK_SHA256}.bin"),
    ],
)
def test_cape_sample_file_download_command_by_id_type(mocker, client, id_type, id_value, client_method, expected_filename):
    """Tests cape_sample_file_download_command with different ID types."""
    mock_content = util_load_file("cape_sample_file_download_response.bin")
    mocker.patch.object(client, client_method, return_value=mock_content)
    mocker.patch.object(CapeSandbox, "build_file_name", return_value=expected_filename)
    mocker.patch(
        "CapeSandbox.fileResult",
        return_value={"File": expected_filename, "Contents": mock_content},
    )
    args = {id_type: id_value}
    result = cape_sample_file_download_command(client, args)
    assert result["File"] == expected_filename


@pytest.mark.parametrize(
    "command_func,args",
    [
        (cape_file_view_command, {"task_id": 1, "md5": MOCK_MD5}),
        (cape_sample_file_download_command, {"task_id": 1, "sha1": MOCK_SHA1}),
    ],
)
def test_commands_multiple_ids_fail(client, command_func, args):
    """Tests commands fail if multiple ID types are provided."""
    with pytest.raises(DemistoException, match="Provide only one of"):
        command_func(client, args)


@pytest.mark.parametrize(
    "command_func",
    [
        cape_file_view_command,
        cape_sample_file_download_command,
    ],
)
def test_commands_no_id_fail(client, command_func):
    """Tests commands fail when no identifying argument is provided."""
    args = {}
    with pytest.raises(DemistoException) as excinfo:
        command_func(client, args)
    assert "provide one of:" in str(excinfo.value).lower()


# ========================================
# Tests: Task Management Commands
# ========================================


def test_cape_pcap_file_download_command(mocker, client):
    """Tests cape_pcap_file_download_command returns fileResult."""
    mock_pcap_content = util_load_file("cape_pcap_file_download_response.pcap")
    expected_filename = "cape_task_123_network_dump.pcap"
    mocker.patch.object(client, "get_task_pcap", return_value=mock_pcap_content)
    mocker.patch.object(CapeSandbox, "build_file_name", return_value=expected_filename)
    mocker.patch(
        "CapeSandbox.fileResult",
        return_value={"File": expected_filename, "Contents": mock_pcap_content},
    )
    args = {"task_id": "123"}
    result = cape_pcap_file_download_command(client, args)
    assert result["File"] == expected_filename


@pytest.mark.parametrize(
    "command_func",
    [
        cape_pcap_file_download_command,
        cape_task_delete_command,
        cape_task_report_get_command,
        cape_task_screenshot_download_command,
    ],
)
def test_commands_missing_task_id_fail(client, command_func):
    """Tests commands fail when required task_id is missing."""
    args = {}
    with pytest.raises(KeyError):
        command_func(client, args)


def test_cape_task_delete_command(mocker, client):
    """Tests cape_task_delete_command returns success message."""
    mocker.patch.object(
        client,
        "delete_task",
        return_value={"status": "success", "message": "Task deleted successfully"},
    )
    args = {"task_id": "123"}
    result = cape_task_delete_command(client, args)
    expected_output = "Task ID: 123 was deleted successfully"
    assert compare_string_ignore_case(result.readable_output, expected_output)


def test_cape_task_delete_command_no_task_id_fail(client):
    """Tests cape_task_delete_command fails when task_id is missing."""
    args = {}
    with pytest.raises(KeyError):
        cape_task_delete_command(client, args)


def test_cape_tasks_list_command_multiple_tasks(mocker, client):
    """Tests cape_tasks_list_command returns multiple task outputs."""
    mocker.patch.object(
        client,
        "list_tasks",
        return_value=util_load_json("cape_tasks_list_response.json"),
    )
    args = {"limit": 2, "page": 1}
    result = cape_tasks_list_command(client, args)
    assert result.outputs_prefix == "Cape.Task"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 2
    assert result.outputs[0].get("id") == 1


@pytest.mark.parametrize(
    "args,expected_limit,expected_offset",
    [
        ({"page": -1}, 50, 0),
        ({"page_size": 200}, 50, 0),
    ],
)
def test_cape_tasks_list_command_invalid_pagination(mocker, client, args, expected_limit, expected_offset):
    """Tests task list command handles invalid page size/page number."""
    mocker.patch.object(client, "list_tasks", return_value={"data": []})
    cape_tasks_list_command(client, args)
    client.list_tasks.assert_called_with(limit=expected_limit, offset=expected_offset)


# ========================================
# Tests: Task Report Commands
# ========================================


def test_cape_task_report_get_command_json(mocker, client):
    """Tests cape_task_report_get_command returns JSON report."""
    mocker.patch.object(
        client,
        "get_task_report",
        return_value=util_load_json("cape_task_report_get_response.json"),
    )
    args = {"task_id": "123", "format": "json", "zip": False}
    result = cape_task_report_get_command(client, args)
    assert result.outputs_prefix == "Cape.Task.Report"
    assert isinstance(result.outputs, dict)
    assert result.outputs["id"] == 123


def test_cape_task_report_get_command_zip_download(mocker, client):
    """Tests cape_task_report_get_command returns zip fileResult."""
    mock_content = b"mock zip content"
    mocker.patch.object(client, "get_task_report", return_value=mock_content)
    mocker.patch.object(CapeSandbox, "build_file_name", return_value="report.zip")
    mocker.patch(
        "CapeSandbox.fileResult",
        return_value={"File": "report.zip", "Contents": mock_content},
    )

    args = {"task_id": "123", "zip": True}
    result = cape_task_report_get_command(client, args)
    assert result["File"] == "report.zip"


def test_cape_task_report_get_command_no_info_fail(mocker, client):
    """Tests report retrieval raises error if report is empty/missing 'info' key."""
    mocker.patch.object(
        client,
        "get_task_report",
        return_value={"status": True, "message": "Report is empty"},
    )

    with pytest.raises(DemistoException, match="Report is empty"):
        cape_task_report_get_command(client, {"task_id": 123})


def test_cape_task_report_get_command_json_no_info_path(mocker, client):
    """Tests report retrieval fails when 'info' is missing."""
    mock_resp = {
        "status": True,
        "target": {"file": {"name": "test.txt"}},
        "id": 123,
    }
    mocker.patch.object(client, "get_task_report", return_value=mock_resp)
    mocker.patch("CapeSandbox.string_to_table_header", side_effect=lambda x: x.upper())

    with pytest.raises(DemistoException, match="No info object found in report for task"):
        cape_task_report_get_command(client, {"task_id": 123})


def test_cape_task_report_get_command_json_target_file_data(mocker, client):
    """Tests report retrieval includes target file data in readable output."""
    mock_resp = {
        "info": {"id": 123, "started": "1970-01-01"},
        "target": {"file": {"name": "test.exe", "sha256": MOCK_SHA256}},
    }
    mocker.patch.object(client, "get_task_report", return_value=mock_resp)
    mocker.patch("CapeSandbox.string_to_table_header", side_effect=lambda x: x.upper())

    result = cape_task_report_get_command(client, {"task_id": "123"})
    assert MOCK_SHA256 in result.readable_output
    assert "test.exe" in result.readable_output


def test_cape_task_report_get_command_not_found_fail(mocker, client):
    """Tests report retrieval fails when API returns 404."""
    mocker.patch.object(
        client,
        "get_task_report",
        side_effect=DemistoException("Task with ID 999 not found on CAPE sandbox.", res={"status": 404}),
    )

    args = {"task_id": 999, "format": "json", "zip": False}

    with pytest.raises(DemistoException) as excinfo:
        cape_task_report_get_command(client, args)

    assert "999 not found" in str(excinfo.value)


# ========================================
# Tests: Screenshot Commands
# ========================================


def test_cape_task_screenshot_download_single(mocker, client):
    """Tests downloading a single, specified screenshot number."""
    mock_content = util_load_file("mock_screenshot_content_1.png")
    mocker.patch.object(client, "get_task_screenshot", return_value=mock_content)
    mocker.patch.object(CapeSandbox, "build_file_name", return_value="screenshot_5.png")
    mocker.patch("CapeSandbox.fileResult", return_value={"File": "screenshot_5.png"})

    args = {"task_id": "123", "screenshot": 5}
    result = cape_task_screenshot_download_command(client, args)
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 1
    assert result.outputs[0]["File"] == "screenshot_5.png"


def test_cape_task_screenshot_download_all_zip_success(mocker, client):
    """
    Tests the 'download all' (no 'screenshot' arg) success path.
    - Mocks the client's 'download_all_screenshots_zip' to return bytes.
    - Verifies the correct file is created.
    """
    mocker.patch.object(client, "download_all_screenshots_zip", return_value=b"zip_content")
    mocker.patch("CapeSandbox.fileResult", return_value={"Name": "mocked.zip"})

    args = {"task_id": "123"}
    results = cape_task_screenshot_download_command(client, args)

    client.download_all_screenshots_zip.assert_called_with(task_id="123")

    assert results.outputs is not None
    assert isinstance(results.outputs, list)
    assert len(results.outputs) == 1
    assert results.outputs_prefix == "Cape.Task.Screenshot"
    assert results.outputs[0]["Name"] == "mocked.zip"
    assert "All Screenshots (ZIP)" in results.readable_output


def test_cape_task_screenshot_download_single_success(mocker, client):
    """
    Tests the 'download single' (with 'screenshot' arg) success path.
    - Mocks the client's 'get_task_screenshot' to return bytes.
    - Verifies the correct file is created.
    """
    mocker.patch.object(client, "get_task_screenshot", return_value=b"png_content")
    mocker.patch(
        "CapeSandbox.fileResult",
        return_value={"Name": "mocked.png", "ScreenshotNumber": "5"},
    )

    args = {"task_id": "123", "screenshot": "5"}
    results = cape_task_screenshot_download_command(client, args)

    client.get_task_screenshot.assert_called_with(task_id="123", number="5")

    assert results.outputs is not None
    assert isinstance(results.outputs, list)
    assert len(results.outputs) == 1
    assert results.outputs_prefix == "Cape.Task.Screenshot"
    assert results.outputs[0]["Name"] == "mocked.png"
    assert results.outputs[0]["ScreenshotNumber"] == "5"
    assert "Screenshot 5" in results.readable_output


def test_cape_task_screenshot_download_failure(mocker, client):
    """
    Tests that a client-side exception is correctly raised.
    This test works for BOTH 'all' and 'single' paths.
    """
    # Mock the 'single' path to fail
    mocker.patch.object(client, "get_task_screenshot", side_effect=DemistoException("Image Not Found"))

    args = {"task_id": "123", "screenshot": "99"}

    # The command should catch the DemistoException and re-raise it
    with pytest.raises(
        DemistoException,
        match="Failed to fetch screenshots for task 123: Image Not Found",
    ):
        cape_task_screenshot_download_command(client, args)

    # Mock the 'all' path to fail
    mocker.patch.object(
        client,
        "download_all_screenshots_zip",
        side_effect=DemistoException("ZIP Not Found"),
    )

    args_all = {"task_id": "123"}
    with pytest.raises(
        DemistoException,
        match="Failed to fetch screenshots for task 123: ZIP Not Found",
    ):
        cape_task_screenshot_download_command(client, args_all)


# ========================================
# Tests: Machine Commands
# ========================================


def test_cape_machines_list_command_single_machine_view_by_name(mocker, client):
    """Tests cape_machines_list_command returns single machine."""
    mock_resp = {"machine": {"id": 5, "name": "win7"}}
    mocker.patch.object(client, "view_machine", return_value=mock_resp)

    result = cape_machines_list_command(client, {"machine_name": "win7"})

    assert result.outputs_prefix == "Cape.Machine"
    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["id"] == 5


def test_cape_machines_list_command_multiple_machines(mocker, client):
    """Tests cape_machines_list_command returns multiple machines."""
    mocker.patch.object(
        client,
        "list_machines",
        return_value=util_load_json("cape_machines_list_response.json"),
    )
    args = {"limit": 2, "all_results": False}
    result = cape_machines_list_command(client, args)
    assert result.outputs_prefix == "Cape.Machine"
    assert result.outputs is not None
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 2
    assert result.outputs[0].get("id") == 1


# ========================================
# Tests: Status Commands
# ========================================


def test_cape_cuckoo_status_get_command_unexpected_response(mocker, client):
    """Tests cuckoo status command handles empty/non-dict response gracefully."""
    mocker.patch.object(client, "get_cuckoo_status", return_value={"message": "status ok"})

    result = cape_cuckoo_status_get_command(client, {})

    assert result.readable_output is not None
    assert "N/A" in result.readable_output


# ========================================
# Tests: Polling Functions
# ========================================


def test_initiate_polling_basic(mocker):
    """Tests initiate_polling creates correct CommandResults with ScheduledCommand."""
    result = CapeSandbox.initiate_polling(
        command="test-command",
        args={"arg1": "value1"},
        task_id=123,
        api_target="test.exe",
        outputs_prefix="Cape.Task.File",
    )

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Cape.Task.File"
    outputs = result.outputs
    assert isinstance(outputs, dict)
    assert outputs["id"] == 123
    assert outputs["target"] == "test.exe"
    assert outputs["status"] == "pending"
    assert "Polling initiated" in result.readable_output
    assert result.scheduled_command is not None
    scheduled_cmd = result.scheduled_command
    assert scheduled_cmd._command == "cape-task-poll"  # type: ignore[attr-defined]


def test_initiate_polling_custom_intervals():
    """Tests initiate_polling creates CommandResults with ScheduledCommand."""
    result = CapeSandbox.initiate_polling(
        command="test-command",
        args={"pollingInterval": 30, "pollingTimeout": 600},
        task_id=456,
        api_target="malware.dll",
        outputs_prefix="Cape.Task.File",
    )

    # Just verify the scheduled command exists and has the right command name
    assert result.scheduled_command is not None
    scheduled_cmd = result.scheduled_command
    assert scheduled_cmd._command == "cape-task-poll"  # type: ignore[attr-defined]


def test_cape_task_poll_report_non_429_error_raises(mocker, client):
    """Tests cape_task_poll_report raises non-429 errors."""
    mocker.patch.object(
        client,
        "get_task_status",
        side_effect=DemistoException("Error [500] - Internal Server Error"),
    )

    args = {"task_id": "888", "outputs_prefix": "Cape.Task.File"}

    with pytest.raises(DemistoException, match="Internal Server Error"):
        CapeSandbox.cape_task_poll_report(args, client)


# ========================================
# Tests: Main Function
# ========================================


def test_main_invalid_command_fail(mocker):
    """Tests main() raises error for invalid/unimplemented command."""
    mocker.patch.object(demisto, "command", return_value="invalid-command")
    mocker.patch.object(demisto, "params", return_value={"url": SERVER_URL, "api_token": "TOKEN"})
    mocker.patch.object(demisto, "args", return_value={})

    mock_return_error = mocker.patch("CapeSandbox.return_error")

    CapeSandbox.main()

    # Verify return_error was called with appropriate message
    mock_return_error.assert_called_once()
    error_call_args = mock_return_error.call_args[0][0]
    assert "invalid-command" in error_call_args
    assert "not implemented" in error_call_args.lower()


def test_main_test_module_success(mocker):
    """Tests main() executes test-module command successfully."""
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "params", return_value={"url": SERVER_URL, "api_token": "TOKEN"})
    mocker.patch.object(demisto, "args", return_value={})

    mock_return_results = mocker.patch("CapeSandbox.return_results")

    CapeSandbox.main()

    mock_return_results.assert_called_once_with("ok")


def test_main_cape_file_submit_success(mocker):
    """Tests main() executes cape-file-submit command successfully."""
    mocker.patch.object(demisto, "command", return_value="cape-file-submit")
    mocker.patch.object(demisto, "params", return_value={"url": SERVER_URL, "api_token": "TOKEN"})
    mocker.patch.object(demisto, "args", return_value={"entry_id": "test_id"})
    mocker.patch.object(
        CapeSandbox,
        "extract_entry_file_data",
        return_value=("/tmp/file.exe", "file.exe"),
    )

    mock_client = mocker.MagicMock()
    mock_client.submit_file.return_value = {"data": {"task_ids": [123]}}
    mocker.patch.object(CapeSandbox, "CapeSandboxClient", return_value=mock_client)

    mock_return_results = mocker.patch("CapeSandbox.return_results")
    mocker.patch.object(
        CapeSandbox,
        "initiate_polling",
        return_value=CommandResults(readable_output="Polling initiated"),
    )

    CapeSandbox.main()

    mock_return_results.assert_called_once()


def test_main_cape_task_poll_success(mocker):
    """Tests main() executes cape-task-poll command with correct argument passing."""
    mocker.patch.object(demisto, "command", return_value="cape-task-poll")
    mocker.patch.object(demisto, "params", return_value={"url": SERVER_URL, "api_token": "TOKEN"})
    mocker.patch.object(
        demisto,
        "args",
        return_value={"task_id": "123", "outputs_prefix": "Cape.Task.File"},
    )

    mock_client = mocker.MagicMock()
    mock_client.get_task_status.return_value = {"data": "running"}
    mocker.patch.object(CapeSandbox, "CapeSandboxClient", return_value=mock_client)

    mock_return_results = mocker.patch("CapeSandbox.return_results")

    CapeSandbox.main()

    # Verify return_results was called (polling result)
    mock_return_results.assert_called_once()


def test_main_command_execution_error(mocker):
    """Tests main() handles command execution errors gracefully."""
    mocker.patch.object(demisto, "command", return_value="cape-file-view")
    mocker.patch.object(demisto, "params", return_value={"url": SERVER_URL, "api_token": "TOKEN"})
    mocker.patch.object(demisto, "args", return_value={})

    mock_return_error = mocker.patch("CapeSandbox.return_error")

    CapeSandbox.main()

    # Verify error was handled
    mock_return_error.assert_called_once()
    error_message = mock_return_error.call_args[0][0]
    assert "cape-file-view" in error_message.lower()


@pytest.mark.parametrize(
    "command_name,expected_in_map",
    [
        ("test-module", True),
        ("cape-file-submit", True),
        ("cape-url-submit", True),
        ("cape-file-view", True),
        ("cape-sample-download", True),
        ("cape-tasks-list", True),
        ("cape-task-delete", True),
        ("cape-task-report-get", True),
        ("cape-pcap-file-download", True),
        ("cape-machines-list", True),
        ("cape-cuckoo-status-get", True),
        ("cape-task-poll", True),
        ("cape-task-screenshot-download", True),
        ("non-existent-command", False),
        ("", False),
    ],
)
def test_command_map_completeness(command_name, expected_in_map):
    """Tests that COMMAND_MAP contains all expected commands."""
    assert (command_name in CapeSandbox.COMMAND_MAP) == expected_in_map
