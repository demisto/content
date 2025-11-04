import json
import os
import sys
import time
import types

import pytest
from CommonServerPython import *

# Mock DemistoClassApiModule before CommonServerPython is imported
mock_demisto_class_api_module = types.ModuleType("DemistoClassApiModule")
sys.modules["DemistoClassApiModule"] = mock_demisto_class_api_module

import CapeSandbox
from CapeSandbox import (
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

SERVER_URL = "https://test_url.com"
TEST_DATA_PATH_SUFFIX = "test_data"
INTEGRATION_DIR_REL = "Packs/CapeSandbox/Integrations/CapeSandbox/"

MOCK_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
MOCK_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
MOCK_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


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


def test_parse_integration_params_missing_url_fail():
    """Tests parse_integration_params fails if 'url' is missing."""
    params = {"url": ""}
    with pytest.raises(DemistoException, match="Server URL.+is required"):
        parse_integration_params(params)


def test_parse_integration_params_username_precedence():
    """Tests parse_integration_params uses API token over username/password."""
    params = {
        "url": SERVER_URL,
        "api_token": "API_TOKEN",
        "username": "user",
        "password": "pwd",
        "insecure": True,
        "proxy": True,
        "credentials": {"identifier": "user_cred", "password": "pwd_cred"},
    }
    result = parse_integration_params(params)
    assert result["api_token"] == "API_TOKEN"
    assert result["username"] == "user_cred"
    assert not result["verify_certificate"]
    assert result["proxy"]


def test_parse_integration_params_url_strip():
    """Tests parse_integration_params strips trailing slash from URL."""
    params = {"url": f"{SERVER_URL}/", "api_token": "TOKEN"}
    result = parse_integration_params(params)
    assert result["base_url"] == SERVER_URL


def test_build_submit_form_full_and_url_mode():
    """Tests build_submit_form correctly assigns all optional args and handles URL mode."""
    args = {
        "url": "http://example.com",
        "package": "win_exe",
        "timeout": 120,
        "priority": 2,
        "memory": "True",
        "enforce_timeout": "false",
        "tags": "test_tag",
    }

    form_url = build_submit_form(args, url_mode=True)
    assert form_url["url"] == "http://example.com"
    assert form_url["package"] == "win_exe"
    assert form_url["timeout"] == 120
    assert form_url["priority"] == 2
    assert form_url["memory"] == "1"
    assert "enforce_timeout" not in form_url

    form_file = build_submit_form(args, url_mode=False)
    assert "url" not in form_file
    assert "memory" in form_file


@pytest.mark.parametrize(
    "identifier,file_type,file_format,screenshot_number,expected",
    [
        (101, "screenshot", None, 5, "cape_task_101_screenshot_5.png"),
        (102, "report", "csv", None, "cape_task_102_report.csv"),
        (MOCK_MD5, "file", None, None, f"cape_task_{MOCK_MD5}_file.json"),
        (103, "network_dump", None, None, "cape_task_103_network_dump.pcap"),
        ("12345", "unknown_type", "txt", None, "cape_task_12345.txt"),
        ("404", None, None, None, "cape_task_404.dat"),
    ],
)
def test_build_file_name_all_types(identifier, file_type, file_format, screenshot_number, expected):
    """Tests build_file_name constructs filenames for all supported types."""
    result = build_file_name(
        identifier,
        file_type=file_type,
        file_format=file_format,
        screenshot_number=screenshot_number,
    )
    assert result == expected


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
        client._check_for_api_error(error_response, "test-suffix")


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
        full_url=mocker.ANY,
        params=None,
        data=None,
        json_data=None,
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
        "get_entry_path",
        return_value=("test_data/test_file.txt", "test_file.txt"),
    )
    mocker.patch.object(
        client,
        "submit_file",
        return_value=util_load_json("cape_file_submit_response.json"),
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
    assert result.outputs.get("id") == 123


def test_cape_file_submit_command_no_task_id_fail(mocker, client):
    """Tests submission fails if API returns no task ID."""
    mocker.patch.object(CapeSandbox, "get_entry_path", return_value=("path/to/file", "file.exe"))
    mocker.patch.object(client, "submit_file", return_value={"data": {"task_ids": []}})

    with pytest.raises(DemistoException, match="No task id returned from CAPE"):
        cape_file_submit_command(client, {"entry_id": "e_id"})


def test_cape_file_submit_command_pcap_logic(mocker, client):
    """Tests submission correctly identifies and sets the pcap flag."""
    mocker.patch.object(CapeSandbox, "get_entry_path", return_value=("path/to/file.pcap", "file.pcap"))
    mocker.patch.object(client, "submit_file", return_value={"data": {"task_ids": [100]}})
    mocker.patch.object(CapeSandbox, "initiate_polling", return_value=CommandResults())

    cape_file_submit_command(client, {"entry_id": "e_id"})

    client.submit_file.assert_called_with(form=mocker.ANY, file_path=mocker.ANY, is_pcap=True)


def test_cape_file_submit_file_not_found_fail(mocker, client):
    """Tests file submission fails when file is not found."""
    mocker.patch.object(
        CapeSandbox,
        "get_entry_path",
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
        return_value=util_load_json("cape_url_submit_response.json"),
    )
    mocker.patch.object(
        CapeSandbox,
        "initiate_polling",
        return_value=CommandResults(
            readable_output="Polling initiated for URL task 456",
            outputs={"id": 456, "target": "http://example.com", "status": "pending"},
            outputs_prefix="Cape.Task.Url",
        ),
    )

    args = {"url": "http://example.com"}
    result = cape_url_submit_command(client, args)
    assert compare_string_ignore_case(result.readable_output, "Polling initiated for URL task 456")
    assert result.outputs_prefix == "Cape.Task.Url"
    assert result.outputs.get("id") == 456


def test_cape_url_submit_command_no_url_fail(client):
    """Tests URL submission fails if URL argument is missing."""
    with pytest.raises(KeyError):
        cape_url_submit_command(client, {})


def test_cape_url_submit_command_no_task_id_fail(mocker, client):
    """Tests URL submission fails if API returns no task ID."""
    mocker.patch.object(client, "submit_url", return_value={"data": {"task_ids": None}})

    with pytest.raises(DemistoException, match="No task id returned from CAPE"):
        cape_url_submit_command(client, {"url": "http://test.com"})


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
    assert result.outputs["id"] == "test_task_id"


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
        return_value=util_load_json("cape_task_delete_response.json"),
    )
    args = {"task_id": "123"}
    result = cape_task_delete_command(client, args)
    expected_output = "Task id=123 was deleted successfully"
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
        "info": {"id": 123, "started": "2023-01-01"},
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


def test_cape_task_screenshot_download_command_multiple(mocker, client):
    """Tests cape_task_screenshot_download_command returns multiple screenshots."""
    mocker.patch.object(
        client,
        "list_task_screenshots",
        return_value=util_load_json("cape_task_screenshots_list_response.json"),
    )

    content_list = [
        util_load_file("mock_screenshot_content_1.png"),
        util_load_file("mock_screenshot_content_2.png"),
    ]
    filename_list = ["cape_task_123_screenshot_1.png", "cape_task_123_screenshot_2.png"]
    mocker.patch.object(client, "get_task_screenshot", side_effect=content_list)
    mocker.patch.object(CapeSandbox, "build_file_name", side_effect=filename_list)
    mocker.patch(
        "CapeSandbox.fileResult",
        side_effect=[
            {"File": filename_list[0], "TaskID": "123", "Contents": content_list[0]},
            {"File": filename_list[1], "TaskID": "123", "Contents": content_list[1]},
        ],
    )

    args = {"task_id": "123"}
    result = cape_task_screenshot_download_command(client, args)
    assert result.outputs_prefix == "Cape.Task.Screenshot"
    assert len(result.outputs) == 2


def test_cape_task_screenshot_download_single(mocker, client):
    """Tests downloading a single, specified screenshot number."""
    mock_content = util_load_file("mock_screenshot_content_1.png")
    mocker.patch.object(client, "get_task_screenshot", return_value=mock_content)
    mocker.patch.object(CapeSandbox, "build_file_name", return_value="screenshot_5.png")
    mocker.patch("CapeSandbox.fileResult", return_value={"File": "screenshot_5.png"})

    args = {"task_id": "123", "screenshot": 5}
    result = cape_task_screenshot_download_command(client, args)
    assert len(result.outputs) == 1
    assert result.outputs[0]["File"] == "screenshot_5.png"


def test_cape_task_screenshot_download_no_candidates(mocker, client):
    """Tests failure when no screenshots are found."""
    mocker.patch.object(client, "list_task_screenshots", return_value={})
    mocker.patch.object(client, "get_task_screenshot", side_effect=DemistoException("Not Found"))

    args = {"task_id": "123"}
    with pytest.raises(DemistoException, match="No screenshots found for task 123"):
        cape_task_screenshot_download_command(client, args)


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
