import demistomock as demisto
import pytest


def _mock_file_entry(mocker, entry_id, file_path, file_name, status_code=200, response_text=""):
    """Helper: patch demisto and requests for a standard read_qr_code call."""
    mocker.patch.object(demisto, "args", return_value={"entry_id": entry_id})
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": file_path, "name": file_name},
    )
    mock_response = mocker.MagicMock()
    mock_response.status_code = status_code
    mock_response.text = response_text
    mocker.patch("requests.post", return_value=mock_response)
    return mock_response


@pytest.mark.parametrize(
    "raw_name, expected_basename",
    [
        ("/tmp/some/path/testfile.png", "testfile.png"),
        ("/tmp/evil/../../etc/passwd", "passwd"),
        ("simple.jpg", "simple.jpg"),
    ],
)
def test_read_qr_code_basename_sanitization(mocker, raw_name, expected_basename):
    """
    Given:
        - A file entry whose name may contain directory path components or traversal sequences.
    When:
        - Calling read_qr_code.
    Then:
        - Only the basename is used for the copy destination and cleanup.
        - demisto.debug logs the removal.
        - os.remove is called with the basename only.
    """
    _mock_file_entry(mocker, "entry1", "/tmp/src", raw_name, status_code=200)
    mock_copy = mocker.patch("shutil.copy")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"data"))
    mocker.patch("os.path.exists", return_value=True)
    mock_remove = mocker.patch("os.remove")
    mock_debug = mocker.patch.object(demisto, "debug")

    from QRCodeReaderGoqrMe import read_qr_code

    read_qr_code(verify=True)

    copy_dest = mock_copy.call_args[0][1]
    assert copy_dest == expected_basename
    assert "/" not in copy_dest
    mock_remove.assert_called_once_with(expected_basename)
    mock_debug.assert_any_call(f"Removing temporary file: {expected_basename}")


def test_read_qr_code_cleanup_runs_on_api_error(mocker):
    """
    Given:
        - A valid file entry but an API response with a non-200 status code.
    When:
        - Calling read_qr_code.
    Then:
        - os.remove is still called via the finally block even when the request fails.
    """
    _mock_file_entry(mocker, "entry2", "/tmp/badfile", "badfile.png", status_code=400, response_text="Bad Request")
    mocker.patch("shutil.copy")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"data"))
    mocker.patch("os.path.exists", return_value=True)
    mock_remove = mocker.patch("os.remove")
    mocker.patch("QRCodeReaderGoqrMe.return_error")

    from QRCodeReaderGoqrMe import read_qr_code

    read_qr_code(verify=True)

    mock_remove.assert_called_once_with("badfile.png")


def test_read_qr_code_copy_failure_skips_remove(mocker):
    """
    Given:
        - A file entry where shutil.copy fails (temp file is never created).
    When:
        - Calling read_qr_code.
    Then:
        - An exception is raised with the appropriate message.
        - os.remove is NOT called (file never existed).
        - demisto.debug logs the skip message.
    """
    mocker.patch.object(demisto, "args", return_value={"entry_id": "entry3"})
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "/tmp/missing", "name": "missing.png"},
    )
    mocker.patch("shutil.copy", side_effect=OSError("No such file"))
    mocker.patch("os.path.exists", return_value=False)
    mock_remove = mocker.patch("os.remove")
    mock_debug = mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")

    from QRCodeReaderGoqrMe import read_qr_code

    with pytest.raises(Exception, match="Failed to prepare file for upload."):
        read_qr_code(verify=True)

    mock_remove.assert_not_called()
    mock_debug.assert_any_call("Temporary file not found, skipping removal: missing.png")
