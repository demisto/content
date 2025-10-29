import json
import os
import sys
import types

import pytest

from CommonServerPython import *

# Mock DemistoClassApiModule before CommonServerPython is imported
mock_demisto_class_api_module = types.ModuleType("DemistoClassApiModule")
sys.modules["DemistoClassApiModule"] = mock_demisto_class_api_module

# NOTE: Import all necessary functions from the main integration file
import CapeSandbox
from CapeSandbox import (
    CapeSandboxClient,
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
)

# --- Helpers and Constants ---

SERVER_URL = "https://test_url.com"

# Define path constants
TEST_DATA_PATH_SUFFIX = "test_data"
# FIX: Define the missing variable globally for CI fallback in helper functions
INTEGRATION_DIR_REL = "Packs/CapeSandbox/Integrations/CapeSandbox/"

# Constants for hash formats
MOCK_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
MOCK_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
MOCK_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# --- Data Loading Helpers (UNIFIED) ---


def get_full_path_unified(file_name):
    """
    Calculates the full path for a file assuming ALL mocks are directly under the 'test_data' folder.
    """
    # 1. Attempt to find the file relative to the current test file (e.g., /CapeSandbox/test_data/file.json)
    path = os.path.join(os.path.dirname(__file__), TEST_DATA_PATH_SUFFIX, file_name)

    # 2. Fallback: Check relative to the CI/Content root (e.g., /src/Packs/.../test_data/file.json)
    if not os.path.exists(path):
        fallback_path = os.path.join(os.getcwd(), INTEGRATION_DIR_REL, TEST_DATA_PATH_SUFFIX, file_name)
        if os.path.exists(fallback_path):
            path = fallback_path

    if not os.path.exists(path):
        raise FileNotFoundError(f"Mock file not found: {file_name} in {TEST_DATA_PATH_SUFFIX}.")

    return path


def util_load_json(file_name):
    """Loads a JSON file from the unified test_data directory."""
    # Since your files are in test_data, we call the unified path logic directly.
    path = get_full_path_unified(file_name)
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_file(file_name):
    """Loads a binary file from the unified test_data directory."""
    # Since your files are in test_data, we call the unified path logic directly.
    path = get_full_path_unified(file_name)
    with open(path, "rb") as f:
        return f.read()


# --- End of Data Loading Helpers ---


def compare_string_ignore_case(actual, expected):
    """Compares two strings ignoring case for text comparison (e.g., in readable_output)."""
    if actual is None or expected is None:
        return actual == expected
    return str(actual).lower() == str(expected).lower()


# --- Fixtures ---


@pytest.fixture()
def client():
    """Returns a CapeSandboxClient instance for testing with mock authentication."""
    return CapeSandboxClient(
        base_url=SERVER_URL,
        verify=True,
        proxy=True,
        api_token="MOCK_API_TOKEN_FOR_TESTING",
        username=None,
        password=None,
    )


# --- Test Functions (Pass Scenarios) ---


def test_test_module(mocker, client):
    """
    Given: Client object
    When: Calling test_module command
    Then: Should return 'ok'
    """
    mocker.patch.object(CapeSandbox, "test_module", return_value="ok")
    result = CapeSandbox.test_module(client)
    assert result == "ok"


def test_cape_file_submit_command(mocker, client):
    """
    Given: Command arguments for file submission
    When: Calling cape_file_submit_command
    Then: Should return a CommandResults object with the correct outputs
    """
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
    assert result.outputs.get("id") == 123  # type: ignore


def test_cape_url_submit_command(mocker, client):
    """
    Given: Command arguments for URL submission
    When: Calling cape_url_submit_command
    Then: Should return a CommandResults object with the correct outputs
    """
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
    assert result.outputs.get("id") == 456  # type: ignore


# --- cape-file-view tests (All ID types) ---


def test_cape_file_view_command_by_task_id(mocker, client):
    """
    Given: task_id for file view.
    When: Calling cape_file_view_command.
    Then: Should return CommandResults.
    """
    mocker.patch.object(
        client,
        "files_view_by_task",
        return_value=util_load_json("cape_file_view_response.json"),
    )
    args = {"task_id": "123"}
    result = cape_file_view_command(client, args)
    assert result.outputs["id"] == "test_task_id"  # type: ignore


def test_cape_file_view_command_by_md5(mocker, client):
    """
    Given: md5 hash for file view.
    When: Calling cape_file_view_command.
    Then: Should return CommandResults.
    """
    mocker.patch.object(
        client,
        "files_view_by_md5",
        return_value=util_load_json("cape_file_view_response.json"),
    )
    args = {"md5": MOCK_MD5}
    result = cape_file_view_command(client, args)
    assert result.outputs["id"] == "test_task_id"  # type: ignore


def test_cape_file_view_command_by_sha256(mocker, client):
    """
    Given: sha256 hash for file view.
    When: Calling cape_file_view_command.
    Then: Should return CommandResults.
    """
    mocker.patch.object(
        client,
        "files_view_by_sha256",
        return_value=util_load_json("cape_file_view_response.json"),
    )
    args = {"sha256": MOCK_SHA256}
    result = cape_file_view_command(client, args)
    assert result.outputs["id"] == "test_task_id"  # type: ignore


# --- cape-sample-file-download tests (All ID types) ---


def test_cape_sample_file_download_command_by_task_id(mocker, client):
    """
    Given: task_id for sample file download.
    When: Calling cape_sample_file_download_command.
    Then: Should return a fileResult dictionary.
    """
    mock_content = util_load_file("cape_sample_file_download_response.bin")
    expected_filename = "cape_task_123_file.bin"
    mocker.patch.object(client, "files_get_by_task", return_value=mock_content)
    mocker.patch.object(CapeSandbox, "build_file_name", return_value=expected_filename)
    mocker.patch(
        "CapeSandbox.fileResult",
        return_value={"File": expected_filename, "Contents": mock_content},
    )
    args = {"task_id": "123"}
    result = cape_sample_file_download_command(client, args)
    assert result["File"] == expected_filename


def test_cape_sample_file_download_command_by_md5(mocker, client):
    """
    Given: md5 hash for sample file download.
    When: Calling cape_sample_file_download_command.
    Then: Should return a fileResult dictionary.
    """
    mock_content = util_load_file("cape_sample_file_download_response.bin")
    expected_filename = f"cape_file_{MOCK_MD5}.bin"
    mocker.patch.object(client, "files_get_by_md5", return_value=mock_content)
    mocker.patch.object(CapeSandbox, "build_file_name", return_value=expected_filename)
    mocker.patch(
        "CapeSandbox.fileResult",
        return_value={"File": expected_filename, "Contents": mock_content},
    )
    args = {"md5": MOCK_MD5}
    result = cape_sample_file_download_command(client, args)
    assert result["File"] == expected_filename


def test_cape_sample_file_download_command_by_sha1(mocker, client):
    """
    Given: sha1 hash for sample file download.
    When: Calling cape_sample_file_download_command.
    Then: Should return a fileResult dictionary.
    """
    mock_content = util_load_file("cape_sample_file_download_response.bin")
    expected_filename = f"cape_file_{MOCK_SHA1}.bin"
    mocker.patch.object(client, "files_get_by_sha1", return_value=mock_content)
    mocker.patch.object(CapeSandbox, "build_file_name", return_value=expected_filename)
    mocker.patch(
        "CapeSandbox.fileResult",
        return_value={"File": expected_filename, "Contents": mock_content},
    )
    args = {"sha1": MOCK_SHA1}
    result = cape_sample_file_download_command(client, args)
    assert result["File"] == expected_filename


def test_cape_sample_file_download_command_by_sha256(mocker, client):
    """
    Given: sha256 hash for sample file download.
    When: Calling cape_sample_file_download_command.
    Then: Should return a fileResult dictionary.
    """
    mock_content = util_load_file("cape_sample_file_download_response.bin")
    expected_filename = f"cape_file_{MOCK_SHA256}.bin"
    mocker.patch.object(client, "files_get_by_sha256", return_value=mock_content)
    mocker.patch.object(CapeSandbox, "build_file_name", return_value=expected_filename)
    mocker.patch(
        "CapeSandbox.fileResult",
        return_value={"File": expected_filename, "Contents": mock_content},
    )
    args = {"sha256": MOCK_SHA256}
    result = cape_sample_file_download_command(client, args)
    assert result["File"] == expected_filename


# --- Other Pass Scenarios ---


def test_cape_pcap_file_download_command(mocker, client):
    """
    Given: Command arguments with task_id for PCAP file download.
    When: Calling cape_pcap_file_download_command.
    Then: Should return a fileResult dictionary.
    """
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


def test_cape_task_delete_command(mocker, client):
    """
    Given: Command arguments with task_id for task deletion.
    When: Calling cape_task_delete_command.
    Then: Should return a CommandResults object with a success message.
    """
    mocker.patch.object(
        client,
        "delete_task",
        return_value=util_load_json("cape_task_delete_response.json"),
    )
    args = {"task_id": "123"}
    result = cape_task_delete_command(client, args)
    expected_output = "Task id=123 was deleted successfully"
    assert compare_string_ignore_case(result.readable_output, expected_output)


def test_cape_tasks_list_command_multiple_tasks(mocker, client):
    """
    Given: Command arguments for listing multiple tasks.
    When: Calling cape_tasks_list_command.
    Then: Should return a CommandResults object with multiple task outputs.
    """
    mocker.patch.object(
        client,
        "list_tasks",
        return_value=util_load_json("cape_tasks_list_response.json"),
    )
    args = {"limit": 2, "page": 1}
    result = cape_tasks_list_command(client, args)
    assert result.outputs_prefix == "Cape.Task"
    assert len(result.outputs) == 2  # type: ignore
    assert result.outputs[0].get("id") == 1  # type: ignore


def test_cape_task_report_get_command_json(mocker, client):
    """
    Given: Command arguments with task_id for JSON report.
    When: Calling cape_task_report_get_command.
    Then: Should return a CommandResults object with the correct outputs.
    """
    mocker.patch.object(
        client,
        "get_task_report",
        return_value=util_load_json("cape_task_report_get_response.json"),
    )
    args = {"task_id": "123", "format": "json", "zip": False}
    result = cape_task_report_get_command(client, args)
    assert result.outputs_prefix == "Cape.Task.Report"
    assert result.outputs["id"] == 123


def test_cape_task_screenshot_download_command_multiple(mocker, client):
    """
    Given: Command arguments with task_id for multiple screenshots.
    When: Calling cape_task_screenshot_download_command.
    Then: Should return a CommandResults object with multiple fileResult objects.
    """
    mocker.patch.object(
        client,
        "list_task_screenshots",
        return_value=util_load_json("cape_task_screenshots_list_response.json"),
    )

    # FIX: Load binary content from external files
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
    assert len(result.outputs) == 2  # type: ignore


def test_cape_machines_list_command_multiple_machines(mocker, client):
    """
    Given: Command arguments for listing multiple machines.
    When: Calling cape_machines_list_command.
    Then: Should return a CommandResults object with multiple machine outputs.
    """
    mocker.patch.object(
        client,
        "list_machines",
        return_value=util_load_json("cape_machines_list_response.json"),
    )
    args = {"limit": 2, "all_results": False}
    result = cape_machines_list_command(client, args)
    assert result.outputs_prefix == "Cape.Machine"
    assert len(result.outputs) == 2  # type: ignore
    assert result.outputs[0].get("id") == 1  # type: ignore


def test_cape_cuckoo_status_get_command(mocker, client):
    """
    Given: No command arguments.
    When: Calling cape_cuckoo_status_get_command.
    Then: Should return a CommandResults object (human-readable only).
    """
    mocker.patch.object(
        client,
        "get_cuckoo_status",
        return_value=util_load_json("cape_cuckoo_status_get_response.json"),
    )
    args = {}
    result = cape_cuckoo_status_get_command(client, args)
    assert result.readable_output
    assert result.outputs is None


# --------------------------------------------------------------------------------
# --- Failure and Edge Scenarios (Missing/Invalid Inputs) ---
# --------------------------------------------------------------------------------


def test_client_init_no_auth_fail():
    """
    Given: No API token, username, or password parameters.
    When: Attempting to initialize the CapeSandboxClient.
    Then: Should raise a DemistoException.
    """
    with pytest.raises(DemistoException) as excinfo:
        CapeSandboxClient(
            base_url=SERVER_URL,
            verify=True,
            proxy=True,
            api_token=None,
            username=None,
            password=None,
        )

    assert "either api token or username + password must be provided" in str(excinfo.value).lower()


def test_cape_file_submit_file_not_found_fail(mocker, client):
    """
    Given: Arguments for file submission where get_entry_path fails.
    When: Calling cape_file_submit_command.
    Then: Should raise DemistoException.
    """
    mocker.patch.object(
        CapeSandbox,
        "get_entry_path",
        side_effect=DemistoException("Could not find file with entry ID 'invalid_id'."),
    )
    args = {"entry_id": "invalid_id"}

    with pytest.raises(DemistoException) as excinfo:
        cape_file_submit_command(client, args)

    assert "could not find file" in str(excinfo.value).lower()


# --- Missing ID Failure Tests ---


def test_cape_file_view_command_no_id_fail(client):
    """
    Given: No identifying argument (task_id, md5, sha256).
    When: Calling cape_file_view_command.
    Then: Should raise DemistoException.
    """
    args = {}
    with pytest.raises(DemistoException) as excinfo:
        cape_file_view_command(client, args)
    assert "provide one of:" in str(excinfo.value).lower()


def test_cape_sample_file_download_command_no_id_fail(client):
    """
    Given: No identifying argument (task_id, md5, sha1, sha256).
    When: Calling cape_sample_file_download_command.
    Then: Should raise DemistoException.
    """
    args = {}
    with pytest.raises(DemistoException) as excinfo:
        cape_sample_file_download_command(client, args)
    assert "provide one of:" in str(excinfo.value).lower()


def test_cape_task_delete_command_no_task_id_fail(client):
    """
    Given: Command arguments missing a required task_id.
    When: Calling cape_task_delete_command.
    Then: Should raise DemistoException.
    """
    args = {}
    with pytest.raises(DemistoException) as excinfo:
        cape_task_delete_command(client, args)

    assert "missing" in str(excinfo.value).lower()
    assert "task id" in str(excinfo.value).lower()


# --- API Failure Tests ---


def test_test_module_failure(mocker, client):
    """
    Given: Client object setup to fail connectivity.
    When: Calling test_module command.
    Then: Should raise DemistoException.
    """
    mocker.patch.object(CapeSandbox, "test_module", side_effect=Exception("Authentication failed."))

    with pytest.raises(Exception):
        CapeSandbox.test_module(client)


def test_cape_task_report_get_command_not_found_fail(mocker, client):
    """
    Given: Command arguments for report, but the API returns a 'Not Found' error (404).
    When: Calling cape_task_report_get_command.
    Then: Should raise DemistoException.
    """
    mocker.patch.object(
        client,
        "get_task_report",
        side_effect=DemistoException("Task with ID 999 not found on CAPE sandbox.", res={"status": 404}),
    )

    args = {"task_id": 999, "format": "json", "zip": False}

    with pytest.raises(DemistoException) as excinfo:
        cape_task_report_get_command(client, args)

    assert "999 not found" in str(excinfo.value)
