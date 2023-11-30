"""KeeperSecretsManager Integration for Cortex XSOAR - Unit Tests file"""

from unittest.mock import patch

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig

from KeeperSecretsManager import Client, get_field_command, list_credentials_command, \
    list_records_command, find_records_command, list_files_command, find_files_command, \
    get_file_command, get_infofile_command


def get_mock_client() -> Client:
    config = MockConfig.make_config()
    client = Client(credentials=config, insecure=True)
    return client


def test_get_field_command():
    """Tests ksm-get-field command function.
    Checks the output of the command function with the expected output.
    """

    client = get_mock_client()

    resp_queue = mock.ResponseQueue(client=client.secrets_manager)
    mock_response = mock.Response()
    mock_record = mock_response.add_record(title="My Record 1")
    mock_record.field("login", "My Login 1")
    mock_record.field("password", "My Password 1")
    resp_queue.add_response(mock_response)

    prefix = SecretsManager.notation_prefix
    notation = f"{prefix}://{mock_record.uid}/field/login"
    resp = get_field_command(client, {"notation": notation})
    assert resp.outputs == "My Login 1"
    assert resp.outputs_prefix == "KeeperSecretsManager.Field"
    assert resp.outputs_key_field == ""


def test_list_credentials_command():
    """Tests ksm-list-credentials command function.
    Checks the output of the command function with the expected output.
    """

    client = get_mock_client()

    resp_queue = mock.ResponseQueue(client=client.secrets_manager)
    mock_response = mock.Response()
    mock_record = mock_response.add_record(title="My Record 1")
    mock_record.field("login", "My Login 1")
    mock_record.field("password", "My Password 1")
    mock_response.add_record(title="My Record 2", record_type="file")
    mock_response.add_record(title="My Record 3", record_type="address")
    resp_queue.add_response(mock_response)

    resp = list_credentials_command(client, {})
    assert isinstance(resp.outputs, list)
    assert len(resp.outputs) == 1
    assert isinstance(resp.outputs[0], dict)
    assert resp.outputs[0].get("uid", "") == mock_record.uid
    assert resp.outputs[0].get("name", "") == "My Record 1"
    assert resp.outputs_prefix == "KeeperSecretsManager.Creds"
    assert resp.outputs_key_field == "name"


def test_list_records_command():
    """Tests ksm-list-records command function.
    Checks the output of the command function with the expected output.
    """

    client = get_mock_client()

    resp_queue = mock.ResponseQueue(client=client.secrets_manager)
    mock_response = mock.Response()
    mock_record = mock_response.add_record(title="My Record 1", record_type="login")
    mock_record.field("login", "My Login 1")
    mock_record.field("password", "My Password 1")
    mock_response.add_record(title="My Record 2", record_type="file")
    mock_response.add_record(title="My Record 3", record_type="address")
    mock_response.add_record(title="My Record 4", record_type="contact")
    resp_queue.add_response(mock_response)

    resp = list_records_command(client, {})
    assert isinstance(resp.outputs, list)
    assert len(resp.outputs) == 4
    assert isinstance(resp.outputs[0], dict)
    assert resp.outputs[0].get("uid", "") == mock_record.uid
    assert resp.outputs[0].get("type", "") == "login"
    assert resp.outputs[0].get("title", "") == "My Record 1"
    assert resp.outputs_prefix == "KeeperSecretsManager.Records"
    assert resp.outputs_key_field == "uid"


def test_find_records_command():
    """Tests ksm-find-records command function.
    Checks the output of the command function with the expected output.
    """

    client = get_mock_client()

    resp_queue = mock.ResponseQueue(client=client.secrets_manager)
    mock_response = mock.Response()
    mock_record = mock_response.add_record(title="My Record 1", record_type="login")
    mock_response.add_record(title="My Record 2", record_type="file")
    mock_response.add_record(title="My Record 3", record_type="address")
    mock_response.add_record(title="My Record 4", record_type="contact")
    resp_queue.add_response(mock_response)

    resp = find_records_command(client, {"title": "Record", "partial_match": True})
    assert isinstance(resp.outputs, list)
    assert len(resp.outputs) == 4
    assert isinstance(resp.outputs[0], dict)
    assert resp.outputs[0].get("uid", "") == mock_record.uid
    assert resp.outputs[0].get("type", "") == "login"
    assert resp.outputs[0].get("title", "") == "My Record 1"
    assert resp.outputs_prefix == "KeeperSecretsManager.Records"
    assert resp.outputs_key_field == "uid"


def test_list_files_command():
    """Tests ksm-list-files command function.
    Checks the output of the command function with the expected output.
    """

    client = get_mock_client()

    resp_queue = mock.ResponseQueue(client=client.secrets_manager)
    mock_response = mock.Response()
    mock_record = mock_response.add_record(title="My Record 1", record_type="login")
    file1 = mock_record.add_file("file1.txt", "Samples", content="This is file 1.")
    mock_record2 = mock_response.add_record(title="My Record 2", record_type="file")
    file2 = mock_record2.add_file("file2.txt", "Documentation", content="This is file 2.")
    mock_response.add_record(title="My Record 3", record_type="address")
    mock_response.add_record(title="My Record 4", record_type="contact")
    resp_queue.add_response(mock_response)

    resp = list_files_command(client, {})
    assert isinstance(resp.outputs, list)
    assert len(resp.outputs) == 2
    assert isinstance(resp.outputs[0], dict)
    assert resp.outputs[0].get("record_uid", "") == mock_record.uid
    assert resp.outputs[0].get("file_uid", "") == file1.uid
    assert resp.outputs[1].get("file_uid", "") == file2.uid
    assert resp.outputs_prefix == "KeeperSecretsManager.Files"
    assert resp.outputs_key_field == "file_uid"


def test_find_files_command():
    """Tests ksm-find-files command function.
    Checks the output of the command function with the expected output.
    """

    client = get_mock_client()

    resp_queue = mock.ResponseQueue(client=client.secrets_manager)
    mock_response = mock.Response()
    mock_record = mock_response.add_record(title="My Record 1", record_type="login")
    file1 = mock_record.add_file("file1.txt", "Samples", content="This is file 1.")
    mock_record2 = mock_response.add_record(title="My Record 2", record_type="file")
    file2 = mock_record2.add_file("file2.txt", "Documentation", content="This is file 2.")
    mock_response.add_record(title="My Record 3", record_type="address")
    mock_response.add_record(title="My Record 4", record_type="contact")
    resp_queue.add_response(mock_response)

    resp = find_files_command(client, {"file_name": "file", "partial_match": True})
    assert isinstance(resp.outputs, list)
    assert len(resp.outputs) == 2
    assert isinstance(resp.outputs[0], dict)
    assert resp.outputs[0].get("record_uid", "") == mock_record.uid
    assert resp.outputs[0].get("file_uid", "") == file1.uid
    assert resp.outputs[1].get("file_uid", "") == file2.uid
    assert resp.outputs_prefix == "KeeperSecretsManager.Files"
    assert resp.outputs_key_field == "file_uid"


def test_get_file_command():
    """Tests ksm-get-file command function.
    Checks the output of the command function with the expected output.
    """

    client = get_mock_client()

    resp_queue = mock.ResponseQueue(client=client.secrets_manager)
    mock_response = mock.Response()
    mock_record = mock_response.add_record(title="My Record 1", record_type="login")
    mock_file = mock_record.add_file("file1.txt", "Samples", content="This is file 1.")
    resp_queue.add_response(mock_response)

    def mock_download_get(_):
        mock_res = mock.Response()
        mock_res.status_code = 200
        mock_res.reason = "OK"
        mock_res.content = mock_file.downloadable_content()
        return mock_res
    with patch("requests.get", side_effect=mock_download_get):
        resp = get_file_command(client, {"file_uid": mock_file.uid})

    assert isinstance(resp, dict)
    assert resp.get("File", "") == "file1.txt"
    assert resp.get("ContentsFormat", "") == "text"


def test_get_infofile_command():
    """Tests ksm-get-infofile command function.
    Checks the output of the command function with the expected output.
    """

    client = get_mock_client()

    resp_queue = mock.ResponseQueue(client=client.secrets_manager)
    mock_response = mock.Response()
    mock_record = mock_response.add_record(title="My Record 1", record_type="login")
    mock_file = mock_record.add_file("file1.txt", "Samples", content="This is file 1.")
    resp_queue.add_response(mock_response)

    def mock_download_get(_):
        mock_res = mock.Response()
        mock_res.status_code = 200
        mock_res.reason = "OK"
        mock_res.content = mock_file.downloadable_content()
        return mock_res
    with patch("requests.get", side_effect=mock_download_get):
        resp = get_infofile_command(client, {"file_uid": mock_file.uid})

    assert isinstance(resp, dict)
    assert resp.get("File", "") == "file1.txt"
    assert resp.get("ContentsFormat", "") == "text"
