import os

import demistomock as demisto


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
        return_value={"path": "/tmp/testfile", "name": "/tmp/evil/../../../etc/passwd"},
    )
    mock_copy = mocker.patch("shutil.copy")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"data"))
    mocker.patch("os.remove")

    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mocker.patch("requests.post", return_value=mock_response)

    from QRCodeReaderGoqrMe import read_qr_code

    read_qr_code(verify=True)

    # Verify shutil.copy was called with the sanitized basename only
    copy_call_args = mock_copy.call_args[0]
    assert copy_call_args[1] == "passwd"
    assert os.path.basename(copy_call_args[1]) == copy_call_args[1]
