from collections.abc import Callable
from unittest.mock import MagicMock
import pytest
from pytest_mock import MockerFixture
from requests_mock import MockerCore
from pathlib import Path
import json
from CommonServerPython import CommandResults, DemistoException
import demistomock as demisto
from MicrosoftGraphFiles import (
    remove_identity_key,
    url_validation,
    parse_key_to_context,
    delete_file_command,
    download_file_command,
    list_sharepoint_sites_command,
    list_drive_content_command,
    create_new_folder_command,
    list_drives_in_site_command,
    MsGraphClient,
    upload_new_file_command,
    list_site_permissions_command,
    create_site_permissions_command,
    update_site_permissions_command,
    delete_site_permission_command,
    get_site_id_from_site_name,
)


def util_load_json(path: str) -> dict:
    return json.loads(Path(path).read_text())


COMMANDS_RESPONSES = util_load_json("test_data/response.json")
ARGUMENTS = util_load_json("test_data/test_inputs.json")
COMMANDS_EXPECTED_RESULTS = util_load_json("test_data/expected_results.json")

EXCLUDE_LIST = ["eTag"]

RESPONSE_KEYS_DICTIONARY = {
    "@odata.context": "OdataContext",
}


class File:
    content = b"12345"


CLIENT_MOCKER = MsGraphClient(
    tenant_id="tenant_id",
    auth_id="auth_id",
    enc_key="enc_key",
    app_name="app_name",
    ok_codes=(200, 204, 201),
    base_url="https://graph.microsoft.com/v1.0/",
    verify="use_ssl",
    proxy="proxy",
    self_deployed="self_deployed",
    redirect_uri="",
    auth_code="",
)

CLIENT_MOCKER_AUTH_CODE = MsGraphClient(
    tenant_id="tenant_id",
    auth_id="auth_id",
    enc_key="enc_key",
    app_name="app_name",
    ok_codes=(200, 204, 201),
    base_url="https://graph.microsoft.com/v1.0/",
    verify="use_ssl",
    proxy="proxy",
    self_deployed="self_deployed",
    redirect_uri="redirect_uri",
    auth_code="auth_code",
)


def authorization_mock(requests_mock: MockerCore) -> None:
    """
    Authorization API request mock.

    """
    authorization_url = "https://login.microsoftonline.com/tenant_id/oauth2/v2.0/token"
    requests_mock.post(
        authorization_url,
        json={
            "access_token": "my-access-token",
            "expires_in": 3595,
            "refresh_token": "my-refresh-token",
        },
    )


def test_remove_identity_key_with_valid_application_input() -> None:
    """
    Given:
        - Dictionary with three nested objects which the creator type is "application"
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    res = remove_identity_key(ARGUMENTS["remove_identifier_data_application_type"]["CreatedBy"])
    assert len(res.keys()) > 1
    assert res["Type"]
    assert res["ID"] == "test"


def test_remove_identity_key_with_valid_user_input() -> None:
    """
    Given:
        - Dictionary with three nested objects which the creator type is "user" and system account
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    res = remove_identity_key(ARGUMENTS["remove_identifier_data_user_type"]["CreatedBy"])
    assert len(res.keys()) > 1
    assert res["Type"]
    assert res.get("ID") is None


def test_remove_identity_key_with_valid_empty_input() -> None:
    """
    Given:
        - Dictionary with three nested objects
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    assert remove_identity_key("") == ""


def test_remove_identity_key_with_invalid_object() -> None:
    """
    Given:
        - Dictionary with three nested objects
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    source = "not a dict"
    res = remove_identity_key(source)
    assert res == source


def test_url_validation_with_valid_link() -> None:
    """
    Given:
        - Link to more results for list commands
    When
        - There is too many results
    Then
        - Returns True if next link url is valid
    """
    res = url_validation(ARGUMENTS["valid_next_link_url"])
    assert res == ARGUMENTS["valid_next_link_url"]


def test_url_validation_with_empty_string() -> None:
    """
    Given:
        - Empty string as next link url
    When
        - Got a bad input from the user
    Then
        - Returns Demisto error
    """
    with pytest.raises(DemistoException):
        url_validation("")


def test_url_validation_with_invalid_url() -> None:
    """
    Given:
        - invalid string as next link url
    When
        - Got a bad input from the user
    Then
        - Returns Demisto error
    """

    with pytest.raises(DemistoException):
        url_validation(ARGUMENTS["invalid_next_link_url"])


def test_parse_key_to_context_exclude_keys_from_list() -> None:
    """
    Given:
        - Raw response from graph api
    When
        - Parsing data to context
    Then
        - Exclude from output unwanted keys
    """
    parsed_response = parse_key_to_context(COMMANDS_RESPONSES["list_drive_children"]["value"][0])
    assert parsed_response.get("eTag", True) is True
    assert parsed_response.get("ETag", True) is True


@pytest.mark.parametrize(
    "command, args, response, filename_expected",
    [
        (
            download_file_command,
            {"object_type": "drives", "object_type_id": "123", "item_id": "232"},
            File,
            "232",
        ),
        (
            download_file_command,
            {
                "object_type": "drives",
                "object_type_id": "123",
                "item_id": "232",
                "file_name": "test.xslx",
            },
            File,
            "test.xslx",
        ),
    ],
)  # noqa: E124
def test_download_file(
    mocker: MockerFixture,
    command: Callable,
    args: dict,
    response: File,
    filename_expected: str,
) -> None:
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - Ensure the `filename` is as sent in the command arguments when provided
          otherwise, the `filename` is `item_id`
    """
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=response)
    mock_file_result = mocker.patch("MicrosoftGraphFiles.fileResult")
    command(CLIENT_MOCKER, args)
    mock_file_result.assert_called_with(filename_expected, response.content)


@pytest.mark.parametrize(
    "command, args, response, expected_result",
    [
        (
            delete_file_command,
            {"object_type": "drives", "object_type_id": "123", "item_id": "232"},
            COMMANDS_RESPONSES["download_file"],
            COMMANDS_EXPECTED_RESULTS["download_file"],
        )
    ],
)
def test_delete_file(mocker: MockerFixture, command: Callable, args: dict, response: str, expected_result: str) -> None:
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - return FileResult object
    """
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=response)
    _, result = command(CLIENT_MOCKER, args)
    assert expected_result == result


@pytest.mark.parametrize(
    "command, args, response, expected_result",
    [
        (
            list_sharepoint_sites_command,
            {},
            COMMANDS_RESPONSES["list_tenant_sites"],
            COMMANDS_EXPECTED_RESULTS["list_tenant_sites"],
        )
    ],
)
def test_list_tenant_sites(mocker: MockerFixture, command: Callable, args: dict, response: dict, expected_result: dict) -> None:
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - return FileResult object
    """
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=response)
    result = command(CLIENT_MOCKER, args)
    assert expected_result == result[1]


@pytest.mark.parametrize(
    "command, args, response, expected_result",
    [
        (
            list_drive_content_command,
            {"object_type": "sites", "object_type_id": "12434", "item_id": "123"},
            COMMANDS_RESPONSES["list_drive_children"],
            COMMANDS_EXPECTED_RESULTS["list_drive_children"],
        )
    ],
)
def test_list_drive_content(mocker: MockerFixture, command: Callable, args: dict, response: dict, expected_result: dict) -> None:
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - return FileResult object
    """
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=response)
    result = command(CLIENT_MOCKER, args)
    assert expected_result == result[1]


@pytest.mark.parametrize(
    "command, args, response, expected_result",
    [
        (
            create_new_folder_command,
            {
                "object_type": "groups",
                "object_type_id": "1234",
                "parent_id": "1234",
                "folder_name": "name",
            },
            COMMANDS_RESPONSES["create_new_folder"],
            COMMANDS_EXPECTED_RESULTS["create_new_folder"],
        )
    ],
)
def test_create_name_folder(mocker: MockerFixture, command: Callable, args: dict, response: dict, expected_result: dict) -> None:
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - return FileResult object
    """
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=response)
    result = command(CLIENT_MOCKER, args)
    assert expected_result == result[1]


@pytest.mark.parametrize(
    "command, args, response, expected_result",
    [
        (
            list_drives_in_site_command,
            {"site_id": "site_id"},
            COMMANDS_RESPONSES["list_drives_in_a_site"],
            COMMANDS_EXPECTED_RESULTS["list_drives_in_a_site"],
        )
    ],
)
def test_list_drives_in_site(mocker: MockerFixture, command: Callable, args: dict, response: dict, expected_result: dict) -> None:
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - return FileResult object
    """
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=response)
    result = command(CLIENT_MOCKER, args)
    assert expected_result == result[1]


def expected_upload_headers() -> list:
    return [
        {"Content-Length": "327680", "Content-Range": "bytes 0-327679/7450762", "Content-Type": "application/octet-stream"},
        {"Content-Length": "327680", "Content-Range": "bytes 327680-655359/7450762", "Content-Type": "application/octet-stream"},
        {"Content-Length": "327680", "Content-Range": "bytes 655360-983039/7450762", "Content-Type": "application/octet-stream"},
        {"Content-Length": "327680", "Content-Range": "bytes 983040-1310719/7450762", "Content-Type": "application/octet-stream"},
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 1310720-1638399/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 1638400-1966079/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 1966080-2293759/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 2293760-2621439/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 2621440-2949119/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 2949120-3276799/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 3276800-3604479/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 3604480-3932159/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 3932160-4259839/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 4259840-4587519/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 4587520-4915199/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 4915200-5242879/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 5242880-5570559/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 5570560-5898239/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 5898240-6225919/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 6225920-6553599/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 6553600-6881279/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "327680",
            "Content-Range": "bytes 6881280-7208959/7450762",
            "Content-Type": "application/octet-stream",
        },
        {
            "Content-Length": "241802",
            "Content-Range": "bytes 7208960-7450761/7450762",
            "Content-Type": "application/octet-stream",
        },
    ]


def validate_upload_attachments_flow(create_upload_mock: MagicMock, upload_query_mock: MagicMock) -> bool:
    """
    Validates that the upload flow is working as expected, each piece of headers is sent as expected.
    """
    if not create_upload_mock.called:
        return False

    if create_upload_mock.call_count != 1:
        return False

    expected_headers = iter(expected_upload_headers())
    for i in range(upload_query_mock.call_count):
        current_headers = next(expected_headers)
        mock_res = upload_query_mock.mock_calls[i].kwargs["headers"]
        if mock_res != current_headers:
            return False
    return True


def self_deployed_client() -> MsGraphClient:
    return CLIENT_MOCKER


json_response = {
    "@odata.context": "dummy_url",
    "@content.downloadUrl": "dummy_url",
    "createdBy": {"application": {"id": "some_id", "displayName": "MS Graph Files"}, "user": {"displayName": "SharePoint App"}},
    "createdDateTime": "some_date",
    "eTag": '"some_eTag"',
    "id": "some_id",
    "lastModifiedBy": {
        "application": {"id": "some_id", "displayName": "MS Graph Files"},
        "user": {"displayName": "SharePoint App"},
    },
    "lastModifiedDateTime": "some_date",
    "name": "yaya.jpg",
    "parentReference": {"driveType": "documentLibrary", "driveId": "some_id", "id": "some_id", "path": "some_path"},
    "webUrl": "https://some_url",
    "cTag": '"c:{000-000},0"',
    "file": {"hashes": {"quickXorHash": "00000"}, "irmEffectivelyEnabled": False, "irmEnabled": False, "mimeType": "image/jpeg"},
    "fileSystemInfo": {"createdDateTime": "some_date", "lastModifiedDateTime": "some_date"},
    "image": {},
    "shared": {"effectiveRoles": ["write"], "scope": "users"},
    "size": 5906704,
}


class MockedResponse:
    def __init__(self, status_code, json):
        self.status_code = status_code
        self.json_response = json

    def json(self):
        return self.json_response


def upload_response_side_effect(**kwargs):
    headers = kwargs.get("headers")
    if headers and int(headers["Content-Length"]) < MsGraphClient.MAX_ATTACHMENT_UPLOAD:
        return MockedResponse(status_code=201, json=json_response)
    return MockedResponse(status_code=202, json="")


UPLOAD_LARGE_FILE_COMMAND_ARGS = [
    (
        self_deployed_client(),
        {
            "object_type": "drives",
            "object_type_id": "some_object_type_id",
            "parent_id": "some_parent_id",
            "entry_id": "3",
            "file_name": "some_file_name",
        },
    )
]

return_value_upload_without_upload_session = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#sites(some_site)/drive/items/$entity",
    "@microsoft.graph.downloadUrl": "some_url",
    "createdDateTime": "2022-12-15T12:56:27Z",
    "eTag": '"{11111111-1111-1111-1111-111111111111},11"',
    "id": "some_id",
    "lastModifiedDateTime": "2022-12-28T11:38:55Z",
    "name": "some_pdf.pdf",
    "webUrl": "https://some_url/some_pdf.pdf",
    "cTag": '"c:{11111111-1111-1111-1111-111111111111},11"',
    "size": 3028,
    "createdBy": {"application": {"id": "some_id", "displayName": "MS Graph Files"}, "user": {"displayName": "SharePoint App"}},
    "lastModifiedBy": {
        "application": {"id": "some_id", "displayName": "MS Graph Files"},
        "user": {"displayName": "SharePoint App"},
    },
    "parentReference": {
        "driveType": "documentLibrary",
        "driveId": "some_drive_id",
        "id": "some_id",
        "path": "/drive/root:/test-folder",
    },
    "file": {"mimeType": "image/jpeg", "hashes": {"quickXorHash": "quickXorHash"}},
    "fileSystemInfo": {"createdDateTime": "2022-12-15T12:56:27Z", "lastModifiedDateTime": "2022-12-28T11:38:55Z"},
    "image": {},
    "shared": {"scope": "users"},
}

return_context = {
    "MsGraphFiles.UploadedFiles(val.ID === obj.ID)": {
        "OdataContext": "https://graph.microsoft.com/v1.0/$metadata#sites(some_site)/drive/items/$entity",
        "DownloadUrl": "some_url",
        "CreatedDateTime": "2022-12-15T12:56:27Z",
        "LastModifiedDateTime": "2022-12-28T11:38:55Z",
        "Name": "some_pdf.pdf",
        "WebUrl": "https://some_url/some_pdf.pdf",
        "Size": 3028,
        "CreatedBy": {
            "Application": {"DisplayName": "MS Graph Files", "ID": "some_id"},
            "User": {"DisplayName": "SharePoint App"},
        },
        "LastModifiedBy": {
            "Application": {"DisplayName": "MS Graph Files", "ID": "some_id"},
            "User": {"DisplayName": "SharePoint App"},
        },
        "ParentReference": {
            "DriveType": "documentLibrary",
            "DriveId": "some_drive_id",
            "Path": "/drive/root:/test-folder",
            "ID": "some_id",
        },
        "File": {"MimeType": "image/jpeg", "Hashes": {"QuickXorHash": "quickXorHash"}},
        "FileSystemInfo": {
            "CreatedDateTime": "2022-12-15T12:56:27Z",
            "LastModifiedDateTime": "2022-12-28T11:38:55Z",
        },
        "Image": {},
        "Shared": {"Scope": "users"},
        "ID": "some_id",
    }
}


@pytest.mark.parametrize("client, args", UPLOAD_LARGE_FILE_COMMAND_ARGS)
def test_upload_command_with_upload_session(mocker: MockerFixture, client: MsGraphClient, args: dict) -> None:
    """
    Given:
        - An image to upload with a size bigger than 3.
    When:
        - running upload new file command.
    Then:
        - return an result with upload session.
    """
    import requests

    mocker.patch.object(demisto, "getFilePath", return_value={"path": "test_data/shark.jpg", "name": "shark.jpg"})
    create_upload_mock = mocker.patch.object(
        MsGraphClient, "create_an_upload_session", return_value=({"response": "", "uploadUrl": "test.com"}, "test.com")
    )
    upload_query_mock = mocker.patch.object(requests, "put", side_effect=upload_response_side_effect)
    upload_file_without_upload_session_mock = mocker.patch.object(MsGraphClient, "upload_new_file", return_value="")
    upload_new_file_command(client, args)
    assert upload_file_without_upload_session_mock.call_count == 0
    assert validate_upload_attachments_flow(create_upload_mock, upload_query_mock)


@pytest.mark.parametrize("client, args", UPLOAD_LARGE_FILE_COMMAND_ARGS)
def test_upload_command_without_upload_session(mocker: MockerFixture, client: MsGraphClient, args: dict) -> None:
    """
    Given:
        - An image to upload (file size lower than 3).
    When:
        - running upload new file command.
    Then:
        - return an result without upload session.
    """
    mocker.patch.object(demisto, "getFilePath", return_value={"path": "test_data/some_pdf.pdf", "name": "some_pdf.pdf"})
    mocker_https = mocker.patch.object(client.ms_client, "http_request", return_value=return_value_upload_without_upload_session)
    create_upload_mock = mocker.patch.object(
        MsGraphClient, "create_an_upload_session", return_value=({"response": "", "uploadUrl": "test.com"}, "test.com")
    )
    upload_file_with_upload_session_mock = mocker.patch.object(
        MsGraphClient,
        "upload_file_with_upload_session_flow",
        return_value=({"response": "", "uploadUrl": "test.com"}, "test.com"),
    )

    human_readable, context, result = upload_new_file_command(client, args)
    assert mocker_https.call_count == 1
    assert create_upload_mock.call_count == 0
    assert upload_file_with_upload_session_mock.call_count == 0
    assert (
        human_readable == "### MsGraphFiles - File information:\n|CreatedDateTime|ID|Name|Size|WebUrl|\n|---|---|---|---|---|"
        "\n| 2022-12-15T12:56:27Z | some_id | some_pdf.pdf | 3028 | https://some_url/some_pdf.pdf |\n"
    )
    assert result == return_value_upload_without_upload_session
    assert context == return_context


@pytest.mark.parametrize(argnames="client_id", argvalues=["test_client_id", None])
def test_test_module_command_with_managed_identities(mocker: MockerFixture, requests_mock: MockerCore, client_id: str | None):
    """
    Given:
        - Managed Identities client id for authentication.
    When:
        - Calling test_module.
    Then:
        - Ensure the output are as expected.
    """
    from MicrosoftGraphFiles import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import re

    mock_token = {"access_token": "test_token", "expires_in": "86400"}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f"^{Resources.graph}.*"), json={})

    params = {
        "managed_identities_client_id": {"password": client_id},
        "authentication_type": "Azure Managed Identities",
        "host": Resources.graph,
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "results", return_value=params)
    mocker.patch("MicrosoftApiModule.get_integration_context", return_value={})

    main()

    assert "ok" in demisto.results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs["resource"] == [Resources.graph]
    assert client_id and qs["client_id"] == [client_id] or "client_id" not in qs


@pytest.mark.parametrize(
    "func_to_test, args",
    [
        pytest.param(list_site_permissions_command, {}, id="test list_site_permissions_command"),
        pytest.param(
            create_site_permissions_command,
            {"app_id": "test", "role": "test", "display_name": "test"},
            id="test create_site_permissions_command",
        ),
        pytest.param(
            update_site_permissions_command,
            {
                "app_id": "test",
                "role": "test",
                "display_name": "test",
                "permission_id": "test",
            },
            id="test update_site_permissions_command",
        ),
        pytest.param(
            delete_site_permission_command,
            {"permission_id": "test"},
            id="test delete_site_permission_command",
        ),
    ],
)
def test_get_site_id_raise_error_site_name_or_site_id_required(
    func_to_test: Callable[[MsGraphClient, dict], CommandResults], args: dict
) -> None:
    """
    Given:
        - Function to test and arguments to pass to the function
    When:
        - Calling the function without providing site_id or site_name parameter
    Then:
        - Ensure DemistoException is raised with expected error message
    """
    with pytest.raises(DemistoException, match="Please provide 'site_id' or 'site_name' parameter."):
        func_to_test(CLIENT_MOCKER, args)


@pytest.mark.parametrize(
    "func_to_test, args",
    [
        pytest.param(
            list_site_permissions_command,
            {"site_name": "test"},
            id="test list_site_permissions_command with site_name",
        ),
        pytest.param(
            create_site_permissions_command,
            {
                "site_name": "test",
                "app_id": "test",
                "role": "test",
                "display_name": "test",
            },
            id="test create_site_permissions_command with site_name",
        ),
        pytest.param(
            update_site_permissions_command,
            {
                "site_name": "test",
                "app_id": "test",
                "role": "test",
                "display_name": "test",
                "permission_id": "test",
            },
            id="test update_site_permissions_command with site_name",
        ),
        pytest.param(
            delete_site_permission_command,
            {"site_name": "test", "permission_id": "test"},
            id="test delete_site_permissions_command with site_name",
        ),
    ],
)
def test_get_site_id_raise_error_invalid_site_name(
    requests_mock: MockerCore,
    func_to_test: Callable[[MsGraphClient, dict], CommandResults],
    args: dict,
) -> None:
    """
    Given:
        - A function to test that requires a valid site name or ID
        - Arguments to pass to the function that have an invalid site name

    When:
        - The function is called with the invalid site name

    Then:
        - Ensure a DemistoException is raised
        - With error message that the site was not found and to provide valid site name/ID
    """
    authorization_mock(requests_mock)
    requests_mock.get("https://graph.microsoft.com/v1.0/sites", json={"value": []}, status_code=200)
    with pytest.raises(
        DemistoException,
        match="Site 'test' not found. Please provide a valid site name.",
    ):
        func_to_test(CLIENT_MOCKER, args)


def test_get_site_id_from_site_name_404(requests_mock: MockerCore) -> None:
    """
    Given:
        - Mocked 404 response from the API when searching for the site

    When:
        - The get_site_id_from_site_name function is called with the site name

    Then:
        - Ensure a DemistoException is raised
        - With error message that includes:
            - The site name that was passed in
            - Mention that the site was not found
            - Instructions to provide a valid site name/ID
        - And the error details matching the 404 response
    """
    site_name = "test_site"
    authorization_mock(requests_mock)
    requests_mock.get(f"https://graph.microsoft.com/v1.0/sites?search={site_name}", status_code=404, text="Item not found")

    with pytest.raises(DemistoException) as e:
        get_site_id_from_site_name(CLIENT_MOCKER, site_name)

    assert str(e.value) == (
        "Error getting site ID for test_site. Ensure integration instance has permission for this site and site name is valid."
        " Error details: Error in API call [404] - None\nItem not found"
    )


def test_list_site_permissions(requests_mock: MockerCore) -> None:
    """
    Given:
        - A requests mock object
        - Mock responses set up for the list site permissions API call

    When:
        - The list_site_permissions_command function is called with the mock client
        - And arguments for a site ID

    Then:
        - Ensure the readable output contains the expected permission data
        - And matches the mock response
    """
    authorization_mock(requests_mock)
    requests_mock.get(
        "https://graph.microsoft.com/v1.0/sites/test/permissions",
        json=util_load_json("test_data/mock_list_permissions.json"),
    )

    result = list_site_permissions_command(CLIENT_MOCKER, {"site_id": "test"})
    assert result.readable_output == (
        "### Site Permission\n"
        "|Application ID|Application Name|ID|Roles|\n"
        "|---|---|---|---|\n"
        "| new-app-id | Example1 App | 1 | read |\n"
        "| new-app-id | Example2 App | 2 | write |\n"
    )


def test_list_site_permissions_with_permission_id(requests_mock: MockerCore) -> None:
    """
    Given:
        - A requests mock object
        - Arguments with a site ID and permission ID

    When:
        - The list_site_permissions_command is called with the arguments

    Then:
        - Ensure the readable output contains the expected permission data
        - Ensure the api call is with permission id "/permissions/id"
    """
    args = {"site_id": "test", "permission_id": "id"}
    authorization_mock(requests_mock)
    requests_mock.get(
        "https://graph.microsoft.com/v1.0/sites/test/permissions/id",
        json=util_load_json("test_data/mock_list_permissions.json")["value"][0],
    )

    result = list_site_permissions_command(CLIENT_MOCKER, args)
    assert result.readable_output == (
        "### Site Permission\n"
        "|Application ID|Application Name|ID|Roles|\n"
        "|---|---|---|---|\n"
        "| new-app-id | Example1 App | 1 | read |\n"
    )


def test_create_permissions_success(requests_mock: MockerCore) -> None:
    """
    Given:
        - Arguments with site ID, app ID, role and display name

    When:
        - The create_site_permissions_command is called with the arguments

    Then:
        - Ensure the readable output contains the expected permission data
    """
    args = {
        "site_id": "test",
        "app_id": "app-id",
        "role": "role",
        "display_name": "name",
    }
    authorization_mock(requests_mock)
    requests_mock.post(
        "https://graph.microsoft.com/v1.0/sites/test/permissions",
        json=util_load_json("test_data/mock_list_permissions.json")["value"][0],
    )
    result = create_site_permissions_command(CLIENT_MOCKER, args)
    assert result.readable_output == (
        "### Site Permission\n"
        "|Application ID|Application Name|ID|Roles|\n"
        "|---|---|---|---|\n"
        "| new-app-id | Example1 App | 1 | read |\n"
    )


def test_update_permissions_command(requests_mock: MockerCore) -> None:
    """
    Given:
        - Arguments with permission ID, new role, and site ID

    When:
        - The update_site_permissions_command is called with the arguments

    Then:
        - Ensure the readable output contains the expected updated permission data
        - Ensure the API call is made to update the permission with the given ID
    """
    args = {"permission_id": "id", "role": "role1", "site_id": "site"}
    authorization_mock(requests_mock)
    requests_mock.patch(
        "https://graph.microsoft.com/v1.0/sites/site/permissions/id",
        json=util_load_json("test_data/mock_list_permissions.json")["value"][0],
    )
    result = update_site_permissions_command(CLIENT_MOCKER, args)

    assert result.readable_output == "Permission id of site site was updated successfully with new role ['read']."


def test_delete_site_permission_command(requests_mock: MockerCore) -> None:
    """
    Given:
        - Arguments with permission ID and site ID

    When:
        - The delete_site_permission_command is called with the arguments

    Then:
        - Ensure the API call is made to delete the permission with the given ID
        - Ensure the readable output indicates the permission was deleted
    """
    args = {"permission_id": "id", "site_id": "site"}
    authorization_mock(requests_mock)
    requests_mock.delete("https://graph.microsoft.com/v1.0/sites/site/permissions/id", status_code=204)
    result = delete_site_permission_command(CLIENT_MOCKER, args)

    assert result.readable_output == "Site permission was deleted."


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function msgraph-user-generate-login-url
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from MicrosoftGraphFiles import main, Scopes

    redirect_uri = "redirect_uri"
    tenant_id = "tenant_id"
    client_id = "client_id"
    mocked_params = {
        "redirect_uri": redirect_uri,
        "auth_type": "Authorization Code",
        "self_deployed": "True",
        "credentials_tenant_id": {"password": tenant_id},
        "credentials_auth_id": {"password": client_id},
        "credentials_enc_key": {"password": "client_secret"},
    }
    mocker.patch.object(demisto, "params", return_value=mocked_params)
    mocker.patch.object(demisto, "command", return_value="msgraph-files-generate-login-url")
    return_results = mocker.patch("MicrosoftGraphFiles.return_results")

    main()
    expected_url = (
        f"[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?"
        f"response_type=code&scope=offline_access%20{Scopes.graph}"
        f"&client_id={client_id}&redirect_uri={redirect_uri})"
    )
    res = return_results.call_args[0][0].readable_output
    assert expected_url in res


@pytest.mark.parametrize(
    "grant_type, self_deployed, demisto_command, expected_result, should_raise, client",
    [
        ("", False, "test-module", "ok", False, CLIENT_MOCKER),
        ("authorization_code", True, "test-module", "ok", True, CLIENT_MOCKER_AUTH_CODE),
        ("client_credentials", True, "test-module", "ok", False, CLIENT_MOCKER),
        ("client_credentials", True, "msgraph-files-auth-test", "```✅ Success!```", False, CLIENT_MOCKER),
        ("authorization_code", True, "msgraph-files-auth-test", "```✅ Success!```", False, CLIENT_MOCKER_AUTH_CODE),
    ],
)
def test_test_function(mocker, grant_type, self_deployed, demisto_command, expected_result, should_raise, client):
    """
    Given:
        - Authentication method, self_deployed information, and demisto command.
    When:
        - Calling test_function.
    Then:
        - Ensure the output is as expected.
    """

    from MicrosoftGraphFiles import test_function

    client = client
    client.ms_client.self_deployed = self_deployed

    client.ms_client.grant_type = grant_type
    demisto_params = {
        "self_deployed": self_deployed,
        "auth_code": client.ms_client.auth_code,
        "redirect_uri": client.ms_client.redirect_uri,
    }
    mocker.patch("MicrosoftGraphFiles.demisto.params", return_value=demisto_params)
    mocker.patch("MicrosoftGraphFiles.demisto.command", return_value=demisto_command)
    mocker.patch.object(client.ms_client, "http_request")

    if should_raise:
        with pytest.raises(DemistoException) as exc:
            test_function(client)
            assert "self-deployed - Authorization Code Flow" in str(exc)
    else:
        result = test_function(client)
        assert result == expected_result
        client.ms_client.http_request.assert_called_once_with(url_suffix="sites", timeout=7, method="GET")
