import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytest


@pytest.fixture(autouse=True)
def mock_demisto(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://example.com",
            "apikey": {"password": "test-api-key"},
        },
    )


TRAVERSAL_FILENAMES = [
    ("/var/lib/demisto/malicious", "malicious"),
    ("/etc/passwd", "passwd"),
    ("../../../etc/shadow", "shadow"),
    ("....//....//etc/hosts", "hosts"),
    ("subdir/nested/file.txt", "file.txt"),
    ("normal_file.txt", "normal_file.txt"),
]


@pytest.mark.parametrize("malicious_name, expected_basename", TRAVERSAL_FILENAMES)
def test_document_upload_file_sanitizes_filename(malicious_name: str, expected_basename: str, mocker):
    """
    Given: A file entry whose getFilePath()["name"] contains directory components.
    When: document_upload_file() is called.
    Then: The file_name used for shutil.copy() and open() is the basename only.
    """
    from AnythingLLM import Client

    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={
            "path": "/tmp/server_file_path",
            "name": malicious_name,
        },
    )

    mock_copy = mocker.patch("AnythingLLM.shutil.copy")
    mocker.patch("AnythingLLM.os.path.isfile", return_value=True)
    mock_remove = mocker.patch("AnythingLLM.os.remove")

    client = Client(base_url="https://example.com/api", verify=False, headers={"Content-Type": "application/json"})
    mocker.patch.object(client, "document_list", return_value={"localFiles": {"items": []}})
    mocker.patch.object(client, "_http_request", return_value={"success": True})

    mock_open = mocker.patch("builtins.open", mocker.mock_open(read_data=b"file content"))

    client.document_upload_file("entry123")

    mock_copy.assert_called_once_with("/tmp/server_file_path", expected_basename)
    mock_open.assert_called_once_with(expected_basename, "rb")
    mock_remove.assert_called_once_with(expected_basename)


def test_document_upload_file_cleanup_skipped_when_no_file(mocker):
    """
    Given: A file entry where the copied file does not exist at cleanup time.
    When: document_upload_file() completes.
    Then: os.remove is not called (guarded by os.path.isfile check).
    """
    from AnythingLLM import Client

    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={
            "path": "/tmp/server_file_path",
            "name": "test_file.txt",
        },
    )

    mocker.patch("AnythingLLM.shutil.copy")
    mocker.patch("AnythingLLM.os.path.isfile", return_value=False)
    mock_remove = mocker.patch("AnythingLLM.os.remove")

    client = Client(base_url="https://example.com/api", verify=False, headers={"Content-Type": "application/json"})
    mocker.patch.object(client, "document_list", return_value={"localFiles": {"items": []}})
    mocker.patch.object(client, "_http_request", return_value={"success": True})
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"file content"))

    client.document_upload_file("entry123")

    mock_remove.assert_not_called()


def test_document_upload_file_absolute_path_write_prevented(mocker):
    """
    Given: A filename with an absolute path.
    When: document_upload_file() is called.
    Then: shutil.copy target is the basename only, not the full absolute path.
    """
    from AnythingLLM import Client

    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={
            "path": "/tmp/server_file_path",
            "name": "/var/lib/demisto/evil",
        },
    )

    mock_copy = mocker.patch("AnythingLLM.shutil.copy")
    mocker.patch("AnythingLLM.os.path.isfile", return_value=True)
    mocker.patch("AnythingLLM.os.remove")

    client = Client(base_url="https://example.com/api", verify=False, headers={"Content-Type": "application/json"})
    mocker.patch.object(client, "document_list", return_value={"localFiles": {"items": []}})
    mocker.patch.object(client, "_http_request", return_value={"success": True})
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"file content"))

    client.document_upload_file("entry123")

    copy_dest = mock_copy.call_args[0][1]
    assert copy_dest == "evil"
    assert "/" not in copy_dest


def test_document_upload_file_relative_traversal_prevented(mocker):
    """
    Given: A filename with relative path traversal components.
    When: document_upload_file() is called.
    Then: shutil.copy target is the basename only, with no directory traversal.
    """
    from AnythingLLM import Client

    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={
            "path": "/tmp/server_file_path",
            "name": "../../../etc/shadow",
        },
    )

    mock_copy = mocker.patch("AnythingLLM.shutil.copy")
    mocker.patch("AnythingLLM.os.path.isfile", return_value=True)
    mocker.patch("AnythingLLM.os.remove")

    client = Client(base_url="https://example.com/api", verify=False, headers={"Content-Type": "application/json"})
    mocker.patch.object(client, "document_list", return_value={"localFiles": {"items": []}})
    mocker.patch.object(client, "_http_request", return_value={"success": True})
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"file content"))

    client.document_upload_file("entry123")

    copy_dest = mock_copy.call_args[0][1]
    assert copy_dest == "shadow"
    assert ".." not in copy_dest
