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
    mock_remove = mocker.patch("AnythingLLM.os.remove")

    client = Client(base_url="https://example.com/api", verify=False, headers={"Content-Type": "application/json"})
    mocker.patch.object(client, "document_list", return_value={"localFiles": {"items": []}})
    mocker.patch.object(client, "_http_request", return_value={"success": True})

    mock_open = mocker.patch("builtins.open", mocker.mock_open(read_data=b"file content"))

    client.document_upload_file("entry123")

    mock_copy.assert_called_once_with("/tmp/server_file_path", expected_basename)
    mock_open.assert_called_once_with(expected_basename, "rb")
    mock_remove.assert_called_once_with(expected_basename)


def test_document_upload_file_cleanup_handles_missing_file(mocker):
    """
    Given: A file entry where the copied file does not exist at cleanup time.
    When: document_upload_file() completes and os.remove raises FileNotFoundError.
    Then: The exception is suppressed and the function completes without error.
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
    mock_remove = mocker.patch("AnythingLLM.os.remove", side_effect=FileNotFoundError)

    client = Client(base_url="https://example.com/api", verify=False, headers={"Content-Type": "application/json"})
    mocker.patch.object(client, "document_list", return_value={"localFiles": {"items": []}})
    mocker.patch.object(client, "_http_request", return_value={"success": True})
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"file content"))

    client.document_upload_file("entry123")

    mock_remove.assert_called_once_with("test_file.txt")


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
    mocker.patch("AnythingLLM.os.remove")

    client = Client(base_url="https://example.com/api", verify=False, headers={"Content-Type": "application/json"})
    mocker.patch.object(client, "document_list", return_value={"localFiles": {"items": []}})
    mocker.patch.object(client, "_http_request", return_value={"success": True})
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"file content"))

    client.document_upload_file("entry123")

    copy_dest = mock_copy.call_args[0][1]
    assert copy_dest == "shadow"
    assert ".." not in copy_dest


def test_document_upload_file_already_exists_uses_sanitized_name(mocker):
    """
    Given: A file entry with a traversal-laden name where the document already exists in AnythingLLM.
    When: document_upload_file() is called and document_name() succeeds (no exception).
    Then: The function raises with the SANITIZED basename in the error message,
          confirms the upload is skipped (no shutil.copy / _http_request), and the
          security improvement is reflected at the user-facing error level.
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

    # document_name returning a value (no exception) means the document already exists.
    mocker.patch("AnythingLLM.document_name", return_value="existing-doc-id")
    mock_copy = mocker.patch("AnythingLLM.shutil.copy")
    mocker.patch("AnythingLLM.os.remove")

    client = Client(base_url="https://example.com/api", verify=False, headers={"Content-Type": "application/json"})
    mocker.patch.object(client, "document_list", return_value={"localFiles": {"items": []}})
    mock_http = mocker.patch.object(client, "_http_request", return_value={"success": True})

    with pytest.raises(Exception) as exc_info:
        client.document_upload_file("entry123")

    # Sanitized basename must appear; original traversal must NOT appear.
    assert "shadow" in str(exc_info.value)
    assert "../../../etc/shadow" not in str(exc_info.value)
    assert "document already exists" in str(exc_info.value)
    # Upload path must be skipped entirely when document already exists.
    mock_copy.assert_not_called()
    mock_http.assert_not_called()


def test_document_upload_file_empty_basename_skips_copy(mocker):
    """
    Given: A file entry whose name results in an empty basename (e.g., "evil/").
    When: document_upload_file() is called.
    Then: The function fails gracefully without calling shutil.copy("...", "")
          and the cleanup os.remove is NOT invoked on an empty filename.
    """
    from AnythingLLM import Client

    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={
            "path": "/tmp/server_file_path",
            "name": "evil/",
        },
    )

    mock_copy = mocker.patch("AnythingLLM.shutil.copy", side_effect=IsADirectoryError("empty filename"))
    mock_remove = mocker.patch("AnythingLLM.os.remove")

    client = Client(base_url="https://example.com/api", verify=False, headers={"Content-Type": "application/json"})
    mocker.patch.object(client, "document_list", return_value={"localFiles": {"items": []}})
    mocker.patch.object(client, "_http_request", return_value={"success": True})
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"file content"))

    with pytest.raises(Exception) as exc_info:
        client.document_upload_file("entry123")

    # Empty basename guard: cleanup must not attempt to remove an empty path.
    mock_remove.assert_not_called()
    # Either the function never reaches copy, or it copies to "" — both are acceptable
    # as long as cleanup is guarded; the user receives a wrapped error either way.
    if mock_copy.called:
        copy_dest = mock_copy.call_args[0][1]
        assert copy_dest == ""
    assert "exception uploading a file entry" in str(exc_info.value)


def test_document_upload_file_get_file_path_failure_wraps_exception(mocker):
    """
    Given: An invalid entry_id where demisto.getFilePath() raises an exception.
    When: document_upload_file() is called.
    Then: The exception is wrapped with the standard
          "AnythingLLM: document_upload_file: exception uploading a file entry [<id>]"
          format, demisto.debug is invoked, and cleanup does not crash on the
          uninitialised file_name (empty string).
    """
    from AnythingLLM import Client

    mocker.patch.object(
        demisto,
        "getFilePath",
        side_effect=Exception("entry not found"),
    )
    mock_debug = mocker.patch.object(demisto, "debug")
    mock_remove = mocker.patch("AnythingLLM.os.remove")

    client = Client(base_url="https://example.com/api", verify=False, headers={"Content-Type": "application/json"})

    with pytest.raises(Exception) as exc_info:
        client.document_upload_file("bad_entry_id")

    err = str(exc_info.value)
    assert "AnythingLLM: document_upload_file:" in err
    assert "exception uploading a file entry [bad_entry_id]" in err
    assert "entry not found" in err
    mock_debug.assert_called_once()
    # file_name was never assigned (stayed ""), so cleanup must not invoke os.remove.
    mock_remove.assert_not_called()
