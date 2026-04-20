import os

import demistomock as demisto
import pytest


def test_read_qr_code_uses_basename(mocker):
    """
    Given:
        - A file entry with a name containing directory path components.
    When:
        - Calling read_qr_code.
    Then:
        - Verify that only the basename of the file name is used.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"entry_id": "entry1"},
    )
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "/tmp/testfile", "name": "/tmp/some/path/testfile.png"},
    )
    mock_copy = mocker.patch("shutil.copy")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"data"))
    mock_remove = mocker.patch("os.remove")

    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mocker.patch("requests.post", return_value=mock_response)

    from QRCodeReaderGoqrMe import read_qr_code

    read_qr_code(verify=True)

    # Verify shutil.copy was called with the basename only
    copy_call_args = mock_copy.call_args[0]
    assert copy_call_args[1] == "testfile.png"
    assert os.path.basename(copy_call_args[1]) == copy_call_args[1]

    # Verify cleanup uses os.remove (not rmtree)
    mock_remove.assert_called_once_with("testfile.png")


def test_read_qr_code_traversal_path_sanitized(mocker):
    """
    Given:
        - A file entry with a name that contains traversal-style path components.
    When:
        - Calling read_qr_code.
    Then:
        - Verify that only the final filename component is used, not the full path.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"entry_id": "entry2"},
    )
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "/tmp/testfile2", "name": "/tmp/evil/../../etc/passwd"},
    )
    mock_copy = mocker.patch("shutil.copy")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"data"))
    mocker.patch("os.remove")

    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mocker.patch("requests.post", return_value=mock_response)

    from QRCodeReaderGoqrMe import read_qr_code

    read_qr_code(verify=True)

    # Verify only the basename "passwd" is used, not the full traversal path
    copy_call_args = mock_copy.call_args[0]
    assert copy_call_args[1] == "passwd"
    assert "/" not in copy_call_args[1]


def test_read_qr_code_cleanup_on_success(mocker):
    """
    Given:
        - A valid file entry and a successful API response.
    When:
        - Calling read_qr_code.
    Then:
        - Verify that os.remove is called for cleanup after a successful request.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"entry_id": "entry3"},
    )
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "/tmp/qrfile", "name": "qrfile.jpg"},
    )
    mocker.patch("shutil.copy")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"imagedata"))
    mock_remove = mocker.patch("os.remove")

    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mocker.patch("requests.post", return_value=mock_response)

    from QRCodeReaderGoqrMe import read_qr_code

    result = read_qr_code(verify=False)

    assert result is not None
    mock_remove.assert_called_once_with("qrfile.jpg")


def test_read_qr_code_cleanup_on_error(mocker):
    """
    Given:
        - A valid file entry but an API response with a non-200 status code.
    When:
        - Calling read_qr_code.
    Then:
        - Verify that os.remove is still called even when the request fails.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"entry_id": "entry4"},
    )
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "/tmp/badfile", "name": "badfile.png"},
    )
    mocker.patch("shutil.copy")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"data"))
    mock_remove = mocker.patch("os.remove")

    mock_response = mocker.MagicMock()
    mock_response.status_code = 400
    mock_response.text = "Bad Request"
    mocker.patch("requests.post", return_value=mock_response)
    mocker.patch("QRCodeReaderGoqrMe.return_error")

    from QRCodeReaderGoqrMe import read_qr_code

    read_qr_code(verify=True)

    # Cleanup must always run via finally block
    mock_remove.assert_called_once_with("badfile.png")


def test_read_qr_code_copy_failure_raises(mocker):
    """
    Given:
        - A file entry where the copy operation fails.
    When:
        - Calling read_qr_code.
    Then:
        - Verify that an exception is raised with an appropriate message.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"entry_id": "entry5"},
    )
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "/tmp/missing", "name": "missing.png"},
    )
    mocker.patch("shutil.copy", side_effect=OSError("No such file"))

    from QRCodeReaderGoqrMe import read_qr_code

    with pytest.raises(Exception, match="Failed to prepare file for upload."):
        read_qr_code(verify=True)
