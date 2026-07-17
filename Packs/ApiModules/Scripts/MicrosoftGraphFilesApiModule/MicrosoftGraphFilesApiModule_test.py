import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock

import demistomock as demisto
import pytest
from CommonServerPython import CommandResults, DemistoException
from MicrosoftGraphFilesApiModule import (
    MsGraphClient,
    _decode_sharepoint_login_name,
    _summarize_permission_grantees,
    assign_sensitivity_label_command,
    copy_driveitem_command,
    create_new_folder_command,
    create_site_permissions_command,
    delete_driveitem_permission_command,
    delete_file_command,
    delete_site_permission_command,
    download_file_command,
    get_sensitivity_label_command,
    get_site_id_from_site_name,
    list_drive_content_command,
    list_drives_in_site_command,
    list_driveitem_permissions_command,
    list_sharepoint_sites_command,
    list_site_permissions_command,
    parse_key_to_context,
    remove_identity_key,
    update_driveitem_command,
    update_site_permissions_command,
    upload_new_file_command,
    url_validation,
)
from pytest_mock import MockerFixture
from requests_mock import MockerCore


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
    ok_codes=(200, 201, 202, 204),
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
    ok_codes=(200, 201, 202, 204),
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
    mock_file_result = mocker.patch("MicrosoftGraphFilesApiModule.fileResult")
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
    def __init__(self, status_code, json, headers=None):
        self.status_code = status_code
        self.json_response = json
        self.headers = headers or {}

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
    import re

    from MicrosoftGraphFilesApiModule import (
        MANAGED_IDENTITIES_TOKEN_URL,
        Resources,
        run_microsoft_graph_files_integration as main,
    )

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
    assert (client_id and qs["client_id"] == [client_id]) or "client_id" not in qs


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
    from MicrosoftGraphFilesApiModule import Scopes, run_microsoft_graph_files_integration as main

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
    return_results = mocker.patch("MicrosoftGraphFilesApiModule.return_results")

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

    from MicrosoftGraphFilesApiModule import test_function

    client = client
    client.ms_client.self_deployed = self_deployed

    client.ms_client.grant_type = grant_type
    demisto_params = {
        "self_deployed": self_deployed,
        "auth_code": client.ms_client.auth_code,
        "redirect_uri": client.ms_client.redirect_uri,
    }
    mocker.patch("MicrosoftGraphFilesApiModule.demisto.params", return_value=demisto_params)
    mocker.patch("MicrosoftGraphFilesApiModule.demisto.command", return_value=demisto_command)
    mocker.patch.object(client.ms_client, "http_request")

    if should_raise:
        with pytest.raises(DemistoException) as exc:
            test_function(client)
            assert "self-deployed - Authorization Code Flow" in str(exc)
    else:
        result = test_function(client)
        assert result == expected_result
        client.ms_client.http_request.assert_called_once_with(url_suffix="sites", timeout=7, method="GET")


# ---------------------------------------------------------------------------
# msgraph-driveitem-update (N1)
# ---------------------------------------------------------------------------

DRIVEITEM_RESPONSE = {
    "@odata.context": "test-context",
    "id": "item-1",
    "name": "renamed.txt",
    "size": 42,
    "webUrl": "https://example/web",
    "createdDateTime": "2024-01-01T00:00:00Z",
    "lastModifiedDateTime": "2024-01-02T00:00:00Z",
    "parentReference": {
        "driveId": "drive-1",
        "driveType": "documentLibrary",
        "id": "parent-1",
        "path": "/drive/root:",
    },
    "file": {"mimeType": "text/plain"},
}


def test_update_driveitem_rename_only(requests_mock: MockerCore) -> None:
    """
    Given:
        - object_type=users with only new_name supplied
    When:
        - update_driveitem_command is invoked
    Then:
        - Only the name key is sent in the PATCH body
        - MsGraphFiles.UpdatedItem context is populated from the response
    """
    authorization_mock(requests_mock)
    mock = requests_mock.patch(
        "https://graph.microsoft.com/v1.0/users/uid/drive/items/item-1",
        json=DRIVEITEM_RESPONSE,
    )
    result = update_driveitem_command(
        CLIENT_MOCKER,
        {
            "object_type": "users",
            "object_type_id": "uid",
            "item_id": "item-1",
            "new_name": "renamed.txt",
        },
    )
    assert mock.last_request.json() == {"name": "renamed.txt"}
    assert result.outputs_prefix == "MsGraphFiles.UpdatedItem"
    assert result.outputs["ID"] == "item-1"
    assert result.outputs["Name"] == "renamed.txt"


def test_update_driveitem_cross_drive_move(requests_mock: MockerCore) -> None:
    """
    Given:
        - object_type=drives, new_parent_id, new_parent_drive_id and conflict_behavior
    When:
        - update_driveitem_command is invoked
    Then:
        - parentReference body carries both id and driveId
        - @microsoft.graph.conflictBehavior is in the body
        - URI uses the drives/{id}/items/{id} shape (no /drive/ segment)
    """
    authorization_mock(requests_mock)
    mock = requests_mock.patch(
        "https://graph.microsoft.com/v1.0/drives/drive-source/items/item-1",
        json=DRIVEITEM_RESPONSE,
    )
    update_driveitem_command(
        CLIENT_MOCKER,
        {
            "object_type": "drives",
            "object_type_id": "drive-source",
            "item_id": "item-1",
            "new_parent_id": "parent-2",
            "new_parent_drive_id": "drive-dest",
            "conflict_behavior": "rename",
        },
    )
    sent = mock.last_request.json()
    assert sent["parentReference"] == {"id": "parent-2", "driveId": "drive-dest"}
    assert sent["@microsoft.graph.conflictBehavior"] == "rename"
    assert "name" not in sent
    assert "description" not in sent


def test_update_driveitem_no_fields_raises(requests_mock: MockerCore) -> None:
    """
    Given:
        - No optional update fields are supplied
    When:
        - update_driveitem_command is invoked
    Then:
        - DemistoException is raised before any HTTP call
    """
    authorization_mock(requests_mock)
    with pytest.raises(DemistoException, match="at least one update field"):
        update_driveitem_command(
            CLIENT_MOCKER,
            {"object_type": "users", "object_type_id": "uid", "item_id": "item-1"},
        )


# ---------------------------------------------------------------------------
# msgraph-driveitem-copy (N2)
# ---------------------------------------------------------------------------


def test_copy_driveitem_202_returns_monitor_url(requests_mock: MockerCore) -> None:
    """
    Given:
        - object_type=users with destination_parent_id and new_name
    When:
        - copy_driveitem_command is invoked and Microsoft Graph responds 202 + Location header
    Then:
        - The body contains parentReference.id and name
        - The MonitorUrl output is populated from the Location header
        - Echo fields ItemId / ObjectType / ObjectTypeId are populated
    """
    authorization_mock(requests_mock)
    monitor_url = "https://graph.microsoft.com/v1.0/operations/monitor-xyz"
    mock = requests_mock.post(
        "https://graph.microsoft.com/v1.0/users/uid/drive/items/item-1/copy",
        status_code=202,
        headers={"Location": monitor_url},
        text="",
    )
    result = copy_driveitem_command(
        CLIENT_MOCKER,
        {
            "object_type": "users",
            "object_type_id": "uid",
            "item_id": "item-1",
            "destination_parent_id": "parent-2",
            "new_name": "copied.txt",
        },
    )
    sent_body = mock.last_request.json()
    assert sent_body == {"parentReference": {"id": "parent-2"}, "name": "copied.txt"}
    assert result.outputs == {
        "MonitorUrl": monitor_url,
        "ItemId": "item-1",
        "ObjectType": "users",
        "ObjectTypeId": "uid",
    }
    assert result.outputs_prefix == "MsGraphFiles.CopyOperation"


def test_copy_driveitem_cross_drive_with_conflict_behavior(requests_mock: MockerCore) -> None:
    """
    Given:
        - object_type=drives with both destination_parent_id and destination_drive_id, plus conflict_behavior
    When:
        - copy_driveitem_command is invoked
    Then:
        - parentReference body carries both id and driveId
        - conflict_behavior is sent as a query parameter (not in body)
        - URI uses drives/{id}/items/{id}/copy (no /drive/ segment)
    """
    authorization_mock(requests_mock)
    mock = requests_mock.post(
        "https://graph.microsoft.com/v1.0/drives/drive-src/items/item-1/copy",
        status_code=202,
        headers={"Location": "https://example/monitor"},
        text="",
    )
    copy_driveitem_command(
        CLIENT_MOCKER,
        {
            "object_type": "drives",
            "object_type_id": "drive-src",
            "item_id": "item-1",
            "destination_parent_id": "parent-2",
            "destination_drive_id": "drive-dest",
            "conflict_behavior": "rename",
        },
    )
    sent_body = mock.last_request.json()
    assert sent_body == {"parentReference": {"id": "parent-2", "driveId": "drive-dest"}}
    assert mock.last_request.qs.get("@microsoft.graph.conflictbehavior") == ["rename"]


def test_copy_driveitem_empty_body_when_no_optional_args(requests_mock: MockerCore) -> None:
    """
    Given:
        - Only required args (object_type, object_type_id, item_id)
    When:
        - copy_driveitem_command is invoked
    Then:
        - An empty JSON body is sent (Graph copies to root with the original name)
        - No conflict_behavior query parameter is sent
    """
    authorization_mock(requests_mock)
    mock = requests_mock.post(
        "https://graph.microsoft.com/v1.0/users/uid/drive/items/item-1/copy",
        status_code=202,
        headers={"Location": "https://example/monitor"},
        text="",
    )
    copy_driveitem_command(
        CLIENT_MOCKER,
        {"object_type": "users", "object_type_id": "uid", "item_id": "item-1"},
    )
    assert mock.last_request.json() == {}
    assert "@microsoft.graph.conflictbehavior" not in mock.last_request.qs


# ---------------------------------------------------------------------------
# msgraph-driveitem-permissions-list (N3)
# ---------------------------------------------------------------------------

DRIVEITEM_PERMISSIONS_RESPONSE = {
    "@odata.context": "test-context",
    "@odata.nextLink": "https://graph.microsoft.com/v1.0/page2?$skiptoken=abc",
    "value": [
        {
            "id": "perm-1",
            "roles": ["read"],
            "link": {"scope": "anonymous", "type": "view", "webUrl": "https://example.com/share/link"},
        },
        {
            "id": "perm-2",
            "roles": ["write"],
            "grantedToV2": {
                "user": {"displayName": "External User", "email": "ext@external.com", "id": "u-ext"},
            },
        },
        {
            "id": "perm-3",
            "roles": ["read"],
            "grantedToV2": {"user": {"displayName": "Owner", "email": "owner@tenant.com", "id": "u-own"}},
            "inheritedFrom": {"driveId": "drive-1", "id": "parent-1", "path": "/drive/root:"},
        },
    ],
}


def test_list_driveitem_permissions_happy_path(requests_mock: MockerCore) -> None:
    """
    Given:
        - A driveItem with three permissions of mixed types
    When:
        - list_driveitem_permissions_command is invoked
    Then:
        - All three permissions are returned under MsGraphFiles.ItemPermission.Value
        - NextToken carries @odata.nextLink
        - Echo fields ItemId / ObjectType / ObjectTypeId are populated
    """
    authorization_mock(requests_mock)
    requests_mock.get(
        "https://graph.microsoft.com/v1.0/sites/site-1/drive/items/item-1/permissions",
        json=DRIVEITEM_PERMISSIONS_RESPONSE,
    )
    result = list_driveitem_permissions_command(
        CLIENT_MOCKER,
        {"object_type": "sites", "object_type_id": "site-1", "item_id": "item-1"},
    )
    assert result.outputs_prefix == "MsGraphFiles.ItemPermission"
    assert result.outputs["ItemId"] == "item-1"
    assert result.outputs["ObjectType"] == "sites"
    assert result.outputs["ObjectTypeId"] == "site-1"
    assert result.outputs["NextToken"] == DRIVEITEM_PERMISSIONS_RESPONSE["@odata.nextLink"]
    assert len(result.outputs["Value"]) == 3
    ids = [p["ID"] for p in result.outputs["Value"]]
    assert ids == ["perm-1", "perm-2", "perm-3"]


def test_list_driveitem_permissions_with_limit(requests_mock: MockerCore) -> None:
    """
    Given:
        - object_type=drives with limit=10
    When:
        - list_driveitem_permissions_command is invoked
    Then:
        - $top=10 is sent as a query parameter
        - URI uses drives/{id}/items/{id}/permissions (no /drive/ segment)
    """
    authorization_mock(requests_mock)
    mock = requests_mock.get(
        "https://graph.microsoft.com/v1.0/drives/drive-1/items/item-1/permissions",
        json={"@odata.context": "ctx", "value": []},
    )
    list_driveitem_permissions_command(
        CLIENT_MOCKER,
        {"object_type": "drives", "object_type_id": "drive-1", "item_id": "item-1", "limit": "10"},
    )
    assert mock.last_request.qs.get("$top") == ["10"]


def test_list_driveitem_permissions_uses_next_page_url(requests_mock: MockerCore) -> None:
    """
    Given:
        - next_page_url pointing to a follow-up @odata.nextLink
    When:
        - list_driveitem_permissions_command is invoked
    Then:
        - The full URL is used directly (not appended to base)
    """
    authorization_mock(requests_mock)
    next_url = "https://graph.microsoft.com/v1.0/users/uid/drive/items/i1/permissions?$skiptoken=xyz"
    mock = requests_mock.get(next_url, json={"@odata.context": "ctx", "value": []})
    list_driveitem_permissions_command(
        CLIENT_MOCKER,
        {
            "object_type": "users",
            "object_type_id": "uid",
            "item_id": "i1",
            "next_page_url": next_url,
        },
    )
    assert mock.called


# ---------------------------------------------------------------------------
# msgraph-driveitem-permission-delete (N4)
# ---------------------------------------------------------------------------


def test_delete_driveitem_permission_204(requests_mock: MockerCore) -> None:
    """
    Given:
        - All four required args
    When:
        - delete_driveitem_permission_command is invoked and Microsoft Graph responds 204
    Then:
        - The expected DELETE URL is called
        - Echo outputs ItemId / PermissionId are populated
    """
    authorization_mock(requests_mock)
    mock = requests_mock.delete(
        "https://graph.microsoft.com/v1.0/sites/site-1/drive/items/item-1/permissions/perm-1",
        status_code=204,
        text="",
    )
    result = delete_driveitem_permission_command(
        CLIENT_MOCKER,
        {
            "object_type": "sites",
            "object_type_id": "site-1",
            "item_id": "item-1",
            "permission_id": "perm-1",
        },
    )
    assert mock.called
    assert result.outputs == {
        "ItemId": "item-1",
        "PermissionId": "perm-1",
        "ObjectType": "sites",
        "ObjectTypeId": "site-1",
    }
    assert result.outputs_prefix == "MsGraphFiles.RemovedItemPermission"


def test_delete_driveitem_permission_drives_uri(requests_mock: MockerCore) -> None:
    """
    Given:
        - object_type=drives
    When:
        - delete_driveitem_permission_command is invoked
    Then:
        - The URI uses drives/{id}/items/{id}/permissions/{permId} (no /drive/ segment)
    """
    authorization_mock(requests_mock)
    mock = requests_mock.delete(
        "https://graph.microsoft.com/v1.0/drives/drive-1/items/item-1/permissions/perm-1",
        status_code=204,
        text="",
    )
    delete_driveitem_permission_command(
        CLIENT_MOCKER,
        {
            "object_type": "drives",
            "object_type_id": "drive-1",
            "item_id": "item-1",
            "permission_id": "perm-1",
        },
    )
    assert mock.called


def test_delete_driveitem_permission_404_surfaced(requests_mock: MockerCore) -> None:
    """
    Given:
        - A permission_id that does not exist (Microsoft Graph returns 404)
    When:
        - delete_driveitem_permission_command is invoked
    Then:
        - The error is surfaced (no silent suppression). Playbook is expected to use
          XSOAR's per-task "Continue on error" for bulk-delete loops.
    """
    authorization_mock(requests_mock)
    requests_mock.delete(
        "https://graph.microsoft.com/v1.0/users/uid/drive/items/item-1/permissions/bogus",
        status_code=404,
        json={"error": {"code": "itemNotFound", "message": "The resource could not be found."}},
    )
    with pytest.raises(Exception):  # noqa: B017 - the underlying client raises DemistoException
        delete_driveitem_permission_command(
            CLIENT_MOCKER,
            {
                "object_type": "users",
                "object_type_id": "uid",
                "item_id": "item-1",
                "permission_id": "bogus",
            },
        )


def test_decode_sharepoint_login_name_guest_user() -> None:
    """
    Given:
        - A SharePoint claims-encoded loginName for an external guest user
    When:
        - _decode_sharepoint_login_name is called
    Then:
        - The original external email is recovered (underscore replaced back with '@')
    """
    encoded = "i:0#.f|membership|ymishra_paloaltonetworks.com#ext#@aperturesync.onmicrosoft.com"
    assert _decode_sharepoint_login_name(encoded) == "ymishra@paloaltonetworks.com"


def test_decode_sharepoint_login_name_internal_user() -> None:
    """
    Given:
        - A SharePoint claims-encoded loginName for an internal tenant user (no #ext# marker)
    When:
        - _decode_sharepoint_login_name is called
    Then:
        - The UPN portion after the last "|" is returned unchanged
    """
    encoded = "i:0#.f|membership|user@tenant.onmicrosoft.com"
    assert _decode_sharepoint_login_name(encoded) == "user@tenant.onmicrosoft.com"


def test_decode_sharepoint_login_name_passthrough() -> None:
    """
    Given:
        - A non-claims-encoded string or empty input
    When:
        - _decode_sharepoint_login_name is called
    Then:
        - The input is returned as-is
    """
    assert _decode_sharepoint_login_name("plain@example.com") == "plain@example.com"
    assert _decode_sharepoint_login_name("") == ""


def test_summarize_permission_grantees_external_user_via_siteuser() -> None:
    """
    Given:
        - A permission entry where the external guest user shows up under
          GrantedToV2.SiteUser with both Email and a claims-encoded LoginName
    When:
        - _summarize_permission_grantees is called
    Then:
        - The external user's email is returned (proving SiteUser.Email is now surfaced)
    """
    perm = {
        "ID": "perm-ext",
        "Roles": ["write"],
        "GrantedTo": {"User": {"DisplayName": "ymishra", "Email": "ymishra@paloaltonetworks.com"}},
        "GrantedToV2": {
            "SiteUser": {
                "DisplayName": "ymishra",
                "Email": "ymishra@paloaltonetworks.com",
                "LoginName": "i:0#.f|membership|ymishra_paloaltonetworks.com#ext#@aperturesync.onmicrosoft.com",
            },
        },
    }
    assert _summarize_permission_grantees(perm) == "ymishra@paloaltonetworks.com"


def test_summarize_permission_grantees_siteuser_loginname_only() -> None:
    """
    Given:
        - A permission entry whose only identifier is a claims-encoded SiteUser.LoginName
          (no Email field populated)
    When:
        - _summarize_permission_grantees is called
    Then:
        - The decoded guest email is surfaced
    """
    perm = {
        "ID": "perm-ext",
        "Roles": ["write"],
        "GrantedToV2": {
            "SiteUser": {
                "LoginName": "i:0#.f|membership|ymishra_paloaltonetworks.com#ext#@aperturesync.onmicrosoft.com",
            },
        },
    }
    assert _summarize_permission_grantees(perm) == "ymishra@paloaltonetworks.com"


def test_summarize_permission_grantees_multiple_identities() -> None:
    """
    Given:
        - A permission entry with grantedToIdentitiesV2 carrying multiple users
    When:
        - _summarize_permission_grantees is called
    Then:
        - All distinct emails are joined with ", " preserving discovery order
    """
    perm = {
        "ID": "perm-link",
        "Roles": ["read"],
        "GrantedToIdentitiesV2": [
            {"User": {"Email": "alice@example.com"}},
            {"User": {"Email": "bob@example.com"}},
            {"User": {"Email": "alice@example.com"}},  # duplicate — should be deduped
        ],
    }
    assert _summarize_permission_grantees(perm) == "alice@example.com, bob@example.com"


def test_summarize_permission_grantees_empty() -> None:
    """
    Given:
        - A permission entry with no grantedTo* fields (e.g. anonymous link only)
    When:
        - _summarize_permission_grantees is called
    Then:
        - An empty string is returned
    """
    perm = {"ID": "perm-link", "Roles": ["read"], "Link": {"Scope": "anonymous", "Type": "view"}}
    assert _summarize_permission_grantees(perm) == ""


# Sensitivity-label commands
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "object_type, expected_uri_part",
    [
        ("drives", "drives/drive-1/items/item-1"),
        ("users", "users/user-1/drive/items/item-1"),
        ("sites", "sites/site-1/drive/items/item-1"),
        ("groups", "groups/group-1/drive/items/item-1"),
    ],
)
def test_get_sensitivity_label_uri_branching(mocker: MockerFixture, object_type: str, expected_uri_part: str) -> None:
    """
    Given:
        - A request to get a sensitivity label for each supported object_type.
    When:
        - Running the get_sensitivity_label_command.
    Then:
        - The Graph URL is constructed using the correct drive-prefix branching:
          'drives/{id}/items/...' for drives and '{type}/{id}/drive/items/...' for users/sites/groups.
        - The request uses GET (not the action endpoint) and includes the
          `$select=sensitivityLabel` query parameter.
    """
    http_mock = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        return_value={"sensitivityLabel": None},
    )
    object_type_id_map = {
        "drives": "drive-1",
        "users": "user-1",
        "sites": "site-1",
        "groups": "group-1",
    }
    args = {
        "object_type": object_type,
        "object_type_id": object_type_id_map[object_type],
        "item_id": "item-1",
    }
    get_sensitivity_label_command(CLIENT_MOCKER, args)

    call_kwargs = http_mock.call_args.kwargs
    assert call_kwargs["method"] == "GET"
    assert call_kwargs["url_suffix"] == expected_uri_part
    assert "/extractSensitivityLabels" not in call_kwargs["url_suffix"]
    assert call_kwargs["params"] == {"$select": "sensitivityLabel"}


def test_get_sensitivity_label_invalid_object_type() -> None:
    """
    Given:
        - An invalid object_type value that is not one of drives, groups, sites, users.
    When:
        - Running the get_sensitivity_label_command.
    Then:
        - A DemistoException is raised with a message indicating the invalid object_type.
    """
    args = {"object_type": "invalid", "object_type_id": "id-1", "item_id": "item-1"}
    with pytest.raises(DemistoException, match="Invalid object_type 'invalid'"):
        get_sensitivity_label_command(CLIENT_MOCKER, args)


# Real Graph v1.0 response for GET driveItem?$select=sensitivityLabel, captured
# from live testing against a file with a classification-only label.
GET_LABEL_REAL_RESPONSE = {
    "@odata.etag": '"{45E2324B-C375-4B70-92E7-177F0C2B52BF},14"',
    "sensitivityLabel": {
        "displayName": "This label is created to test the MRB Activity",
        "id": "08973045-2fd6-4014-9177-9f2a3e55c29e",
        "protectionEnabled": False,
    },
}


def test_get_sensitivity_label_command_happy_path(mocker: MockerFixture) -> None:
    """
    Given:
        - A real Graph v1.0 response containing a classification-only sensitivity
          label (protectionEnabled=false) returned by
          `GET driveItem?$select=sensitivityLabel`.
    When:
        - Running the get_sensitivity_label_command.
    Then:
        - The outputs contain itemId plus all label fields returned by
          Microsoft Graph, matching the values in the response.
    """
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=GET_LABEL_REAL_RESPONSE)
    args = {"object_type": "drives", "object_type_id": "d1", "item_id": "i1"}
    result = get_sensitivity_label_command(CLIENT_MOCKER, args)

    assert result.outputs_prefix == "MsGraphFiles.SensitivityLabel"
    assert result.outputs == {
        "itemId": "i1",
        "displayName": "This label is created to test the MRB Activity",
        "id": "08973045-2fd6-4014-9177-9f2a3e55c29e",
        "protectionEnabled": False,
    }


@pytest.mark.parametrize(
    "graph_response",
    [
        {"sensitivityLabel": None},
        {},
    ],
)
def test_get_sensitivity_label_command_empty_label(mocker: MockerFixture, graph_response: dict) -> None:
    """
    Given:
        - A Graph response where the drive item has no sensitivity label assigned.
          This is represented either as `sensitivityLabel: null` or by omitting the
          field entirely from the response.
    When:
        - Running the get_sensitivity_label_command.
    Then:
        - The command does NOT raise an error.
        - The outputs contain only itemId (no label fields since the label is empty).
        - The readable output contains a descriptive "no label assigned" message.
    """
    mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        return_value=graph_response,
    )
    args = {"object_type": "drives", "object_type_id": "d1", "item_id": "i1"}
    result = get_sensitivity_label_command(CLIENT_MOCKER, args)

    assert result.outputs == {
        "itemId": "i1",
    }
    assert "No sensitivity label is assigned" in result.readable_output


def test_get_sensitivity_label_command_protected_label(mocker: MockerFixture) -> None:
    """
    Given:
        - A Graph response containing a sensitivity label whose
          `protectionEnabled` flag is true (encrypted/protected label).
    When:
        - Running the get_sensitivity_label_command.
    Then:
        - The boolean is preserved in the outputs as True.
    """
    response = {
        "sensitivityLabel": {
            "id": "11111111-2222-3333-4444-555555555555",
            "displayName": "Confidential",
            "protectionEnabled": True,
        },
    }
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=response)
    args = {"object_type": "drives", "object_type_id": "d1", "item_id": "i1"}
    result = get_sensitivity_label_command(CLIENT_MOCKER, args)

    assert result.outputs == {
        "itemId": "i1",
        "id": "11111111-2222-3333-4444-555555555555",
        "displayName": "Confidential",
        "protectionEnabled": True,
    }
    assert result.outputs["protectionEnabled"] is True


@pytest.mark.parametrize(
    "object_type, expected_uri_part",
    [
        ("drives", "drives/drive-1/items/item-1/assignSensitivityLabel"),
        ("users", "users/user-1/drive/items/item-1/assignSensitivityLabel"),
        ("sites", "sites/site-1/drive/items/item-1/assignSensitivityLabel"),
        ("groups", "groups/group-1/drive/items/item-1/assignSensitivityLabel"),
    ],
)
def test_assign_sensitivity_label_uri_branching(mocker: MockerFixture, object_type: str, expected_uri_part: str) -> None:
    """
    Given:
        - A request to assign a sensitivity label for each supported object_type. Microsoft
          Graph treats assignSensitivityLabel as a long-running operation, returning 202
          Accepted with a Location header that points to an operations URL.
    When:
        - Running the assign_sensitivity_label_command without supplying assignment_method
          or justification_text.
    Then:
        - The Graph URL uses the correct drive-prefix branching for each object_type.
        - The request body contains only sensitivityLabelId (no assignmentMethod and no
          justificationText are sent when the caller did not supply them).
    """
    object_type_id_map = {
        "drives": "drive-1",
        "users": "user-1",
        "sites": "site-1",
        "groups": "group-1",
    }
    location_header = f"https://graph.microsoft.com/v1.0/drives/{object_type_id_map[object_type]}/operations/op-1"
    http_mock = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        return_value=MockedResponse(status_code=202, json={}, headers={"Location": location_header}),
    )
    args = {
        "object_type": object_type,
        "object_type_id": object_type_id_map[object_type],
        "item_id": "item-1",
        "sensitivity_label_id": "label-guid-1",
    }
    assign_sensitivity_label_command(CLIENT_MOCKER, args)

    call_kwargs = http_mock.call_args.kwargs
    assert call_kwargs["method"] == "POST"
    assert call_kwargs["url_suffix"] == expected_uri_part
    assert call_kwargs["resp_type"] == "response"
    assert call_kwargs["json_data"] == {
        "sensitivityLabelId": "label-guid-1",
    }


def test_assign_sensitivity_label_command_happy_path(mocker: MockerFixture) -> None:
    """
    Given:
        - A successful 202 Accepted response from Microsoft Graph for the
          assignSensitivityLabel call, including a Location response header (matching the
          format from the official docs) pointing to the long-running operation status URL.
    When:
        - Running the assign_sensitivity_label_command with a non-default assignment_method
          and an explicit justification_text.
    Then:
        - The outputs include `itemId`, `sensitivityLabelId`, and `location` only —
          no `result` and no `httpStatusCode`.
        - The request body uses the user-supplied assignment_method and justificationText.
    """
    location_header = "https://contoso.sharepoint.com/_api/v2.0/monitor/MyMonitorJobId"
    http_mock = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        return_value=MockedResponse(status_code=202, json={}, headers={"Location": location_header}),
    )
    args = {
        "object_type": "drives",
        "object_type_id": "d1",
        "item_id": "i1",
        "sensitivity_label_id": "label-guid-1",
        "assignment_method": "privileged",
        "justification_text": "Manual review",
    }
    result = assign_sensitivity_label_command(CLIENT_MOCKER, args)

    assert result.outputs_prefix == "MsGraphFiles.AssignedSensitivityLabel"
    assert result.outputs == {
        "itemId": "i1",
        "sensitivityLabelId": "label-guid-1",
        "location": location_header,
    }
    assert "result" not in result.outputs
    assert "httpStatusCode" not in result.outputs

    sent_body = http_mock.call_args.kwargs["json_data"]
    assert sent_body == {
        "sensitivityLabelId": "label-guid-1",
        "assignmentMethod": "privileged",
        "justificationText": "Manual review",
    }


def test_assign_sensitivity_label_command_removes_label_when_empty_string(mocker: MockerFixture) -> None:
    """
    Given:
        - An assign command invocation with `sensitivity_label_id` explicitly set to "".
          Per Microsoft Graph, an empty string instructs Graph to remove the existing label.
    When:
        - Running the assign_sensitivity_label_command.
    Then:
        - The JSON body sent to Microsoft Graph contains `"sensitivityLabelId": ""`.
        - The outputs reflect the empty `sensitivityLabelId`.
    """
    http_mock = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        return_value=MockedResponse(status_code=202, json={}, headers={"Location": ""}),
    )
    args = {
        "object_type": "drives",
        "object_type_id": "d1",
        "item_id": "i1",
        "sensitivity_label_id": "",
    }
    result = assign_sensitivity_label_command(CLIENT_MOCKER, args)

    sent_body = http_mock.call_args.kwargs["json_data"]
    assert sent_body["sensitivityLabelId"] == ""
    assert "assignmentMethod" not in sent_body
    assert "justificationText" not in sent_body
    assert result.outputs["sensitivityLabelId"] == ""


def test_assign_sensitivity_label_command_omits_justification_when_empty(mocker: MockerFixture) -> None:
    """
    Given:
        - An assign command invocation that does not supply `justification_text`
          (or supplies it as an empty string).
    When:
        - Running the assign_sensitivity_label_command.
    Then:
        - The JSON body sent to Microsoft Graph does NOT contain a `justificationText`
          key at all (rather than sending `"justificationText": ""`).
    """
    http_mock = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        return_value=MockedResponse(status_code=202, json={}, headers={"Location": "https://contoso.example/monitor/x"}),
    )
    args = {
        "object_type": "drives",
        "object_type_id": "d1",
        "item_id": "i1",
        "sensitivity_label_id": "label-guid-1",
        "justification_text": "",
    }
    assign_sensitivity_label_command(CLIENT_MOCKER, args)

    sent_body = http_mock.call_args.kwargs["json_data"]
    assert "justificationText" not in sent_body
    assert sent_body == {"sensitivityLabelId": "label-guid-1"}


def test_assign_sensitivity_label_command_omits_assignment_method_when_empty(mocker: MockerFixture) -> None:
    """
    Given:
        - An assign command invocation that does not supply `assignment_method`
          (or supplies it as an empty string).
    When:
        - Running the assign_sensitivity_label_command.
    Then:
        - The JSON body sent to Microsoft Graph does NOT contain an `assignmentMethod`
          key at all (rather than sending `"assignmentMethod": ""` or silently
          substituting a default value).
    """
    http_mock = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        return_value=MockedResponse(status_code=202, json={}, headers={"Location": "https://contoso.example/monitor/x"}),
    )
    args = {
        "object_type": "drives",
        "object_type_id": "d1",
        "item_id": "i1",
        "sensitivity_label_id": "label-guid-1",
        "assignment_method": "",
    }
    assign_sensitivity_label_command(CLIENT_MOCKER, args)

    sent_body = http_mock.call_args.kwargs["json_data"]
    assert "assignmentMethod" not in sent_body
    assert sent_body == {"sensitivityLabelId": "label-guid-1"}


@pytest.mark.parametrize("status_code", [400, 403, 404, 503])
def test_assign_sensitivity_label_propagates_http_errors(mocker: MockerFixture, status_code: int) -> None:
    """
    Given:
        - Microsoft Graph returns a 4xx or 5xx error for the assignSensitivityLabel call.
    When:
        - Running the assign_sensitivity_label_command.
    Then:
        - The DemistoException raised by the underlying HTTP client is allowed to propagate
          (caught by the outer main() try/except in the integration entry point) so the
          calling layer can inspect the raw Graph error message.
    """
    error_message = f"Error in API call [{status_code}] - error from Graph"
    mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        side_effect=DemistoException(error_message),
    )
    args = {
        "object_type": "drives",
        "object_type_id": "d1",
        "item_id": "i1",
        "sensitivity_label_id": "label-guid-1",
    }
    with pytest.raises(DemistoException) as exc_info:
        assign_sensitivity_label_command(CLIENT_MOCKER, args)
    assert error_message in str(exc_info.value)
