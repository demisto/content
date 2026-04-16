import os

import demistomock as demisto


def test_document_upload_file_uses_basename(mocker):
    """
    Given:
        - A file entry with a name containing directory path components.
    When:
        - Calling document_upload_file.
    Then:
        - Verify that only the basename of the file name is used.
    """
    mocker.patch.object(
        demisto,
        "getFilePath",
        return_value={"path": "/tmp/testfile", "name": "/tmp/evil/../../../etc/passwd"},
    )
    mock_copy = mocker.patch("shutil.copy")
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"data"))

    from AnythingLLM import Client

    client = Client(
        base_url="https://test.com",
        verify=False,
        proxy=False,
        headers={"Authorization": "Bearer test", "Content-Type": "application/json"},
    )

    # Mock document_list to return empty so the file doesn't "already exist"
    mocker.patch.object(client, "document_list", return_value=[])
    mocker.patch.object(
        client,
        "_http_request",
        return_value={"success": True, "documents": [{"location": "custom-documents/passwd"}]},
    )

    client.document_upload_file("entry1")

    # Verify shutil.copy was called with the sanitized basename only
    copy_call_args = mock_copy.call_args[0]
    assert copy_call_args[1] == "passwd"
    assert os.path.basename(copy_call_args[1]) == copy_call_args[1]
