import demistomock as demisto
import pytest


def test_read_qr_code_file_name_used_directly(mocker):
    """
    Given:
        - A file entry with a name returned by getFilePath.
    When:
        - Calling read_qr_code.
    Then:
        - Verify that the file name is used directly without modification.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"entry_id": "entry1"},
    )
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "/tmp/testfile", "name": "testfile.png"},
    )
    mock_copy = mocker.patch("shutil.copy")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"data"))
    mock_rmtree = mocker.patch("shutil.rmtree")

    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mocker.patch("requests.post", return_value=mock_response)

    from QRCodeReaderGoqrMe import read_qr_code

    read_qr_code(verify=True)

    # Verify shutil.copy was called with the file name from getFilePath
    copy_call_args = mock_copy.call_args[0]
    assert copy_call_args[1] == "testfile.png"

    # Verify cleanup uses shutil.rmtree
    mock_rmtree.assert_called_once_with("testfile.png", ignore_errors=True)


def test_read_qr_code_cleanup_on_success(mocker):
    """
    Given:
        - A valid file entry and a successful API response.
    When:
        - Calling read_qr_code.
    Then:
        - Verify that cleanup is performed after a successful request.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"entry_id": "entry2"},
    )
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "/tmp/qrfile", "name": "qrfile.jpg"},
    )
    mocker.patch("shutil.copy")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"imagedata"))
    mock_rmtree = mocker.patch("shutil.rmtree")

    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mocker.patch("requests.post", return_value=mock_response)

    from QRCodeReaderGoqrMe import read_qr_code

    result = read_qr_code(verify=False)

    assert result is not None
    mock_rmtree.assert_called_once_with("qrfile.jpg", ignore_errors=True)


def test_read_qr_code_cleanup_on_error(mocker):
    """
    Given:
        - A valid file entry but an API response with a non-200 status code.
    When:
        - Calling read_qr_code.
    Then:
        - Verify that cleanup is still performed even when the request fails.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"entry_id": "entry3"},
    )
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "/tmp/badfile", "name": "badfile.png"},
    )
    mocker.patch("shutil.copy")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"data"))
    mock_rmtree = mocker.patch("shutil.rmtree")

    mock_response = mocker.MagicMock()
    mock_response.status_code = 400
    mock_response.text = "Bad Request"
    mocker.patch("requests.post", return_value=mock_response)
    mocker.patch("QRCodeReaderGoqrMe.return_error")

    from QRCodeReaderGoqrMe import read_qr_code

    read_qr_code(verify=True)

    # Cleanup must always run via finally block
    mock_rmtree.assert_called_once_with("badfile.png", ignore_errors=True)


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
        return_value={"entry_id": "entry4"},
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
