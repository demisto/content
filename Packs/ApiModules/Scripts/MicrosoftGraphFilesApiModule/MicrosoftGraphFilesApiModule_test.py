import base64
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
    _summarize_identity_set,
    _summarize_permission_grantees,
    assign_sensitivity_label_command,
    copy_driveitem_command,
    create_new_folder_command,
    create_site_permissions_command,
    delete_driveitem_permission_command,
    delete_file_command,
    delete_site_permission_command,
    download_file_command,
    encode_sharing_url,
    get_driveitem_analytics_command,
    get_driveitem_metadata_command,
    get_sensitivity_label_command,
    get_site_id_from_site_name,
    list_drive_content_command,
    list_drives_in_site_command,
    list_driveitem_activities_command,
    list_driveitem_permissions_command,
    list_sharepoint_sites_command,
    list_site_permissions_command,
    parse_key_to_context,
    remove_identity_key,
    resolve_item_addressing,
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


def test_summarize_permission_grantees_camel_case_keys_from_a_list() -> None:
    """
    Given:
        - A permission whose grantedToIdentitiesV2 entries still carry Microsoft's original
          camelCase keys, which is what actually reaches this function at runtime:
          parse_key_to_context title-cases dict keys but does NOT recurse into lists.
    When:
        - _summarize_permission_grantees is called
    Then:
        - The grantees are still found. Matching only title-cased keys silently dropped every
          identity that came from a list, so the Granted To column rendered empty for exactly
          the permissions that matter most - files shared with specific people.
    """
    perm = {
        "ID": "perm-link",
        "GrantedToIdentitiesV2": [
            {"user": {"email": "alice@example.com"}},
            {"user": {"displayName": "Bob"}},
        ],
    }

    assert _summarize_permission_grantees(perm) == "alice@example.com, Bob"


def test_summarize_permission_grantees_mixed_casing() -> None:
    """
    Given:
        - A permission mixing a title-cased single identity set with a camelCase list entry,
          which is the realistic shape after parse_key_to_context.
    When:
        - _summarize_permission_grantees is called
    Then:
        - Both are labelled, in discovery order.
    """
    perm = {
        "GrantedToV2": {"SiteUser": {"LoginName": "i:0#.f|membership|single@example.com"}},
        "GrantedToIdentitiesV2": [{"user": {"email": "fromlist@example.com"}}],
    }

    assert _summarize_permission_grantees(perm) == "single@example.com, fromlist@example.com"


def test_summarize_identity_set_handles_both_casings() -> None:
    """
    Given:
        - An itemActivity actor in Microsoft's original camelCase, and the same in title case.
    When:
        - _summarize_identity_set is called
    Then:
        - Both are labelled. The same helper is fed parsed and unparsed payloads depending on
          the call site, so it cannot assume either casing.
    """
    assert _summarize_identity_set({"user": {"email": "actor@example.com"}}) == "actor@example.com"
    assert _summarize_identity_set({"User": {"Email": "actor@example.com"}}) == "actor@example.com"


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


@pytest.mark.parametrize(
    "share_url, expected",
    [
        # The example from the Microsoft "Encoding sharing URLs" documentation.
        (
            "https://onedrive.live.com/redir?resid=1231244193912!12&authKey=1201919!12921!1",
            "u!aHR0cHM6Ly9vbmVkcml2ZS5saXZlLmNvbS9yZWRpcj9yZXNpZD0xMjMxMjQ0MTkzOTEyITEyJmF1dGhLZXk9MTIwMTkxOSExMjkyMSEx",
        ),
        # A typical SharePoint sharing URL, whose base64 needs '=' padding stripped.
        # The expected value is the base64url of the fake URL above it - derived data, not a
        # credential. Keep a path whose encoding actually pads, or this case proves nothing.
        (
            "https://contoso.sharepoint.com/:w:/r/personal/fake_user/Documents/report.docx",
            "u!aHR0cHM6Ly9jb250b3NvLnNoYXJlcG9pbnQuY29tLzp3Oi9yL3BlcnNvbmFsL2Zha2VfdXNlci9Eb2N1bWVudHMvcmVwb3J0LmRvY3g",
        ),
        # Chosen because its raw base64 contains BOTH '+' and '/', which is what actually
        # exercises the base64url translation. Most sharing URLs never produce those
        # characters, so a realistic-looking URL would leave the translation untested.
        ("https://c.sharepoint.com/x/>>>???.docx", "u!aHR0cHM6Ly9jLnNoYXJlcG9pbnQuY29tL3gvPj4-Pz8_LmRvY3g"),
    ],
)
def test_encode_sharing_url(share_url: str, expected: str):
    """
    Given: A sharing URL.
    When: Encoding it for the GET /shares/{token} route.
    Then: The token is base64url encoded, unpadded, and prefixed with 'u!'.
    """
    encoded = encode_sharing_url(share_url)

    assert encoded == expected
    assert encoded.startswith("u!")
    # base64url alphabet only - '+', '/' and '=' must not survive the translation.
    assert "+" not in encoded
    assert "/" not in encoded
    assert "=" not in encoded


def test_encode_sharing_url_translates_base64url_characters():
    """
    Given: A URL whose raw base64 encoding contains both '+' and '/'.
    When: Encoding it for the GET /shares/{token} route.
    Then: '+' becomes '-' and '/' becomes '_', per the documented base64url translation.
    """
    share_url = "https://c.sharepoint.com/x/>>>???.docx"
    raw_base64 = base64.b64encode(share_url.encode("utf-8")).decode("utf-8")
    # Guard the premise of this test: if these are ever absent the assertions below are vacuous.
    assert "+" in raw_base64
    assert "/" in raw_base64

    encoded = encode_sharing_url(share_url)

    assert "-" in encoded
    assert "_" in encoded
    # The token must decode back to the original URL.
    body = encoded[2:].replace("_", "/").replace("-", "+")
    assert base64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8") == share_url


@pytest.mark.parametrize(
    "object_type, item_id, suffix, expected",
    [
        ("drives", "drive-1", "", "drives/drive-1/items/item-1"),
        ("sites", "site-1", "", "sites/site-1/drive/items/item-1"),
        ("groups", "group-1", "permissions", "groups/group-1/drive/items/item-1/permissions"),
        ("users", "user-1", "analytics/allTime", "users/user-1/drive/items/item-1/analytics/allTime"),
    ],
)
def test_driveitem_uri_by_id(object_type: str, item_id: str, suffix: str, expected: str):
    """
    Given: An object type, its ID and an optional sub-resource suffix.
    When: Building a driveItem URI addressed by item ID.
    Then: 'drives' is addressed directly and every other type goes through '/drive'.
    """
    assert MsGraphClient._driveitem_uri(object_type, item_id, "item-1", suffix) == expected


@pytest.mark.parametrize(
    "object_type, object_type_id, item_path, suffix, expected",
    [
        ("drives", "drive-1", "Documents/report.docx", "", "drives/drive-1/root:/Documents/report.docx"),
        ("sites", "site-1", "Documents/report.docx", "", "sites/site-1/drive/root:/Documents/report.docx"),
        (
            "sites",
            "site-1",
            "Documents/report.docx",
            "extractSensitivityLabels",
            "sites/site-1/drive/root:/Documents/report.docx:/extractSensitivityLabels",
        ),
        # Leading and trailing slashes are stripped so the URL never doubles up separators.
        ("sites", "site-1", "/Documents/report.docx/", "", "sites/site-1/drive/root:/Documents/report.docx"),
        # Spaces and other reserved characters are percent-encoded, separators are preserved.
        ("sites", "site-1", "My Folder/a b.docx", "", "sites/site-1/drive/root:/My%20Folder/a%20b.docx"),
    ],
)
def test_driveitem_path_uri(object_type: str, object_type_id: str, item_path: str, suffix: str, expected: str):
    """
    Given: An item path relative to the drive root.
    When: Building a path-addressed driveItem URI.
    Then: The path is percent-encoded and closed with ':' only when a suffix follows.
    """
    assert MsGraphClient._driveitem_path_uri(object_type, object_type_id, item_path, suffix) == expected


def test_resolve_item_addressing_by_item_id():
    """
    Given: Only item_id, alongside the object type arguments.
    When: Resolving the addressing mode.
    Then: The item_id mode is returned with its companion arguments.
    """
    result = resolve_item_addressing({"object_type": "sites", "object_type_id": "site-1", "item_id": "item-1"})

    assert result == {"mode": "item_id", "value": "item-1", "object_type": "sites", "object_type_id": "site-1"}


def test_resolve_item_addressing_by_item_path():
    """
    Given: Only item_path, on a command that supports path addressing.
    When: Resolving the addressing mode.
    Then: The item_path mode is returned.
    """
    result = resolve_item_addressing({"object_type": "sites", "object_type_id": "site-1", "item_path": "a/b.docx"})

    assert result["mode"] == "item_path"
    assert result["value"] == "a/b.docx"


def test_resolve_item_addressing_by_share_url():
    """
    Given: Only share_url, on a command that supports it.
    When: Resolving the addressing mode.
    Then: The share_url mode is returned with empty object type fields, keeping the shape
          uniform across modes, because a sharing URL addresses the item on its own.
    """
    result = resolve_item_addressing({"share_url": "https://e.sharepoint.com/x"}, allow_share_url=True)

    assert result == {
        "mode": "share_url",
        "value": "https://e.sharepoint.com/x",
        "object_type": "",
        "object_type_id": "",
    }


@pytest.mark.parametrize(
    "args, kwargs, expected_error",
    [
        # Nothing supplied - the message lists what the command accepts.
        ({}, {}, "Provide one of the following arguments: item_id, item_path."),
        ({}, {"allow_path": False}, "Provide one of the following arguments: item_id."),
        ({}, {"allow_share_url": True}, "Provide one of the following arguments: item_id, item_path, share_url."),
        # More than one supplied - the message names the offending arguments.
        (
            {"item_id": "item-1", "item_path": "a/b.docx"},
            {},
            "Provide only one of the following arguments, but got item_id, item_path.",
        ),
        (
            {"item_id": "item-1", "share_url": "https://e.sharepoint.com/x"},
            {"allow_share_url": True},
            "Provide only one of the following arguments, but got item_id, share_url.",
        ),
        # Supplied but unsupported by this endpoint.
        ({"item_path": "a/b.docx"}, {"allow_path": False}, "The item_path argument is not supported by this command."),
        ({"share_url": "https://e.sharepoint.com/x"}, {}, "The share_url argument is not supported by this command."),
        # Addressing by id/path requires the parent resource ID.
        ({"object_type": "sites", "item_id": "item-1"}, {}, "The object_type_id argument is required"),
        # Addressing by id/path also requires a valid object_type. The argument has no default,
        # so an omitted value would otherwise reach the URI builders and produce a malformed URL.
        ({"object_type_id": "site-1", "item_id": "item-1"}, {}, "The object_type argument is required"),
        ({"object_type": "", "object_type_id": "site-1", "item_path": "a/b.docx"}, {}, "The object_type argument is required"),
        (
            {"object_type": "bogus", "object_type_id": "site-1", "item_id": "item-1"},
            {},
            "must be one of: drives, groups, sites, users. Got 'bogus'.",
        ),
    ],
)
def test_resolve_item_addressing_invalid(args: dict, kwargs: dict, expected_error: str):
    """
    Given: An invalid combination of addressing arguments.
    When: Resolving the addressing mode.
    Then: A DemistoException naming the relevant arguments is raised.
    """
    with pytest.raises(DemistoException) as exc_info:
        resolve_item_addressing(args, **kwargs)

    assert expected_error in str(exc_info.value)


@pytest.mark.parametrize("object_type", ["drives", "groups", "sites", "users"])
def test_resolve_item_addressing_accepts_every_valid_object_type(object_type: str):
    """
    Given: Each of the object types Microsoft Graph supports for addressing a driveItem.
    When: Resolving the addressing mode by item ID.
    Then: The value is accepted and passed through unchanged.
    """
    result = resolve_item_addressing({"object_type": object_type, "object_type_id": "id-1", "item_id": "item-1"})

    assert result["object_type"] == object_type


def test_resolve_item_addressing_share_url_does_not_require_object_type():
    """
    Given: Only share_url, which is self-addressing.
    When: Resolving the addressing mode.
    Then: No object_type is demanded, because the sharing token identifies the item on its own.
    """
    result = resolve_item_addressing({"share_url": "https://e.sharepoint.com/x"}, allow_share_url=True)

    assert result["mode"] == "share_url"
    assert result["object_type"] == ""
    assert result["object_type_id"] == ""


def test_resolve_item_addressing_returns_the_same_keys_for_every_mode():
    """
    Given: Each of the three addressing modes.
    When: Resolving the addressing mode.
    Then: The returned dictionaries carry an identical key set, so callers can index directly
          instead of guarding every lookup with .get().
    """
    by_id = resolve_item_addressing({"object_type": "sites", "object_type_id": "site-1", "item_id": "item-1"})
    by_path = resolve_item_addressing({"object_type": "sites", "object_type_id": "site-1", "item_path": "a/b.docx"})
    by_url = resolve_item_addressing({"share_url": "https://e.sharepoint.com/x"}, allow_share_url=True)

    assert by_id.keys() == by_path.keys() == by_url.keys()


def test_resolve_item_addressing_ignores_empty_strings():
    """
    Given: Arguments where the unused addressing modes are empty strings, as XSOAR supplies them.
    When: Resolving the addressing mode.
    Then: The empty values are ignored rather than counted as supplied.
    """
    result = resolve_item_addressing(
        {"object_type": "sites", "object_type_id": "site-1", "item_id": "item-1", "item_path": "", "share_url": ""},
        allow_share_url=True,
    )

    assert result["mode"] == "item_id"


DRIVEITEM_METADATA_RESPONSE = {
    "id": "a9670e1f-67b8-43e1-85f6-b395c4119acf",
    "name": "test.docx",
    "size": 12345,
    "webUrl": "https://contoso.sharepoint.com/personal/fake_user/Documents/test.docx",
    "createdDateTime": "2025-11-24T14:19:11Z",
    "lastModifiedDateTime": "2025-11-24T14:19:40Z",
    "createdBy": {"user": {"email": "fake.user@example.com", "id": "826411a3", "displayName": "Fake User"}},
    "lastModifiedBy": {"user": {"email": "fake.user@example.com", "id": "826411a3", "displayName": "Fake User"}},
    "parentReference": {"id": "0622f447", "siteId": "7878e691-3e74-4a11-899d-c69622de1254", "driveId": "drive-abc"},
    "sharepointIds": {"listItemUniqueId": "a9670e1f-67b8-43e1-85f6-b395c4119acf", "siteId": "7878e691"},
}


# The sharepointIds lookup is a separate request, so the metadata tests that do not care about it
# turn it off to keep the call sequence to a single request.
def test_get_driveitem_metadata_command_by_item_id(mocker: MockerFixture):
    """
    Given: An item_id together with the object type arguments.
    When: Running msgraph-driveitem-metadata-get.
    Then: The items/{id} route is called and the metadata is returned under MsGraphFiles.Files.
    """
    http_request = mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=DRIVEITEM_METADATA_RESPONSE)

    result = get_driveitem_metadata_command(
        CLIENT_MOCKER,
        {"object_type": "sites", "object_type_id": "site-1", "item_id": "item-1", "include_sharepoint_ids": "false"},
    )

    assert http_request.call_args.kwargs["url_suffix"] == "sites/site-1/drive/items/item-1"
    assert result.outputs_prefix == "MsGraphFiles.Files"
    assert result.outputs["ID"] == "a9670e1f-67b8-43e1-85f6-b395c4119acf"
    assert result.outputs["ItemID"] == "a9670e1f-67b8-43e1-85f6-b395c4119acf"
    # SiteID and DriveId are lifted out of parentReference so callers do not have to dig for them.
    assert result.outputs["SiteID"] == "7878e691-3e74-4a11-899d-c69622de1254"
    # DriveId states which drive ItemID belongs to - without it the ID cannot be used in a
    # follow-up command, which matters most for share_url lookups that land in a personal drive.
    assert result.outputs["DriveId"] == "drive-abc"
    assert "test.docx" in result.readable_output
    assert "drive-abc" in result.readable_output


def test_get_driveitem_metadata_command_by_item_path(mocker: MockerFixture):
    """
    Given: An item_path instead of an item_id.
    When: Running msgraph-driveitem-metadata-get.
    Then: The path-addressed root:/ route is called.
    """
    http_request = mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=DRIVEITEM_METADATA_RESPONSE)

    get_driveitem_metadata_command(
        CLIENT_MOCKER,
        {
            "object_type": "sites",
            "object_type_id": "site-1",
            "item_path": "Documents/test.docx",
            "include_sharepoint_ids": "false",
        },
    )

    assert http_request.call_args.kwargs["url_suffix"] == "sites/site-1/drive/root:/Documents/test.docx"


def test_get_driveitem_metadata_command_by_share_url(mocker: MockerFixture):
    """
    Given: A share_url and no object type arguments.
    When: Running msgraph-driveitem-metadata-get.
    Then: The /shares/{token}/driveItem route is called with the encoded token.
    """
    http_request = mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=DRIVEITEM_METADATA_RESPONSE)
    share_url = "https://contoso.sharepoint.com/:w:/r/personal/fake_user/Documents/test.docx"

    get_driveitem_metadata_command(CLIENT_MOCKER, {"share_url": share_url, "include_sharepoint_ids": "false"})

    assert http_request.call_args.kwargs["url_suffix"] == f"shares/{encode_sharing_url(share_url)}/driveItem"


def test_get_driveitem_metadata_command_merges_sharepoint_ids(mocker: MockerFixture):
    """
    Given: include_sharepoint_ids is on, and the item's parentReference carries a driveId.
    When: Running msgraph-driveitem-metadata-get.
    Then: A second request asks for sharepointIds on its own, addressed by drive, and the result
          is merged into the same output. Microsoft Graph does not return sharepointIds as part
          of the driveItem, not even when it is named in $select, so a dedicated request is the
          only way to get it.
    """
    metadata_without_ids = {k: v for k, v in DRIVEITEM_METADATA_RESPONSE.items() if k != "sharepointIds"}
    sharepoint_ids = {
        "listId": "b1f2c3d4-1111-2222-3333-444455556666",
        "listItemUniqueId": "a9670e1f-67b8-43e1-85f6-b395c4119acf",
        "siteId": "7878e691",
    }
    http_request = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        side_effect=[metadata_without_ids, {"sharepointIds": sharepoint_ids}],
    )

    result = get_driveitem_metadata_command(
        CLIENT_MOCKER, {"object_type": "sites", "object_type_id": "site-1", "item_id": "item-1", "include_sharepoint_ids": "true"}
    )

    assert http_request.call_count == 2
    # The second call is addressed by drive, using the IDs taken from the first response, so it
    # also works for the path and share_url modes where the caller never supplied a site ID.
    # sites/{id}/drive would resolve only the site's default document library.
    second_call = http_request.call_args_list[1].kwargs
    assert second_call["url_suffix"] == "drives/drive-abc/items/a9670e1f-67b8-43e1-85f6-b395c4119acf"
    assert second_call["params"] == {"$select": "sharepointIds"}
    assert result.outputs["SharepointIds"]["ListId"] == "b1f2c3d4-1111-2222-3333-444455556666"
    assert result.outputs["SharepointIds"]["ListItemUniqueId"] == "a9670e1f-67b8-43e1-85f6-b395c4119acf"
    assert "a9670e1f-67b8-43e1-85f6-b395c4119acf" in result.readable_output


def test_get_driveitem_metadata_command_sharepoint_ids_falls_back_to_site_route(mocker: MockerFixture):
    """
    Given: A response whose parentReference carries a siteId but no driveId.
    When: Running msgraph-driveitem-metadata-get with include_sharepoint_ids=true.
    Then: The lookup falls back to the site route rather than building a 'drives//items/...'
          URL or skipping the lookup altogether.
    """
    metadata = {k: v for k, v in DRIVEITEM_METADATA_RESPONSE.items() if k != "sharepointIds"}
    metadata["parentReference"] = {"id": "0622f447", "siteId": "7878e691-3e74-4a11-899d-c69622de1254"}
    http_request = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        side_effect=[metadata, {"sharepointIds": {"listId": "list-1", "listItemUniqueId": "item-unique-1"}}],
    )

    result = get_driveitem_metadata_command(
        CLIENT_MOCKER, {"object_type": "sites", "object_type_id": "site-1", "item_id": "item-1", "include_sharepoint_ids": "true"}
    )

    assert http_request.call_count == 2
    assert (
        http_request.call_args_list[1].kwargs["url_suffix"]
        == "sites/7878e691-3e74-4a11-899d-c69622de1254/drive/items/a9670e1f-67b8-43e1-85f6-b395c4119acf"
    )
    assert result.outputs["SharepointIds"]["ListId"] == "list-1"


def test_get_driveitem_metadata_command_sharepoint_ids_by_share_url(mocker: MockerFixture):
    """
    Given: An item addressed by share_url, which resolves to a personal OneDrive rather than to
           the site's default document library.
    When: Running msgraph-driveitem-metadata-get with include_sharepoint_ids=true.
    Then: The lookup is addressed by drive. Addressing it through sites/{id}/drive - the previous
          behaviour - reached the wrong library and returned no identifiers.
    """
    metadata_without_ids = {k: v for k, v in DRIVEITEM_METADATA_RESPONSE.items() if k != "sharepointIds"}
    http_request = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        side_effect=[metadata_without_ids, {"sharepointIds": {"listId": "list-1", "listItemUniqueId": "item-unique-1"}}],
    )

    get_driveitem_metadata_command(
        CLIENT_MOCKER,
        {
            "share_url": "https://contoso.sharepoint.com/:w:/r/personal/fake_user/Documents/test.docx",
            "include_sharepoint_ids": "true",
        },
    )

    assert http_request.call_args_list[1].kwargs["url_suffix"] == "drives/drive-abc/items/a9670e1f-67b8-43e1-85f6-b395c4119acf"


def test_get_driveitem_metadata_command_skips_sharepoint_ids_when_disabled(mocker: MockerFixture):
    """
    Given: include_sharepoint_ids=false.
    When: Running msgraph-driveitem-metadata-get.
    Then: Only the metadata request is made - the extra round trip is avoided.
    """
    http_request = mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=DRIVEITEM_METADATA_RESPONSE)

    get_driveitem_metadata_command(
        CLIENT_MOCKER,
        {"object_type": "sites", "object_type_id": "site-1", "item_id": "item-1", "include_sharepoint_ids": "false"},
    )

    assert http_request.call_count == 1
    # sharepointIds must not be requested through $select - Graph ignores it there.
    assert "sharepointIds" not in http_request.call_args.kwargs["params"]["$select"]
    assert "id,name,size,webUrl" in http_request.call_args.kwargs["params"]["$select"]


def test_get_driveitem_metadata_command_requires_exactly_one_addressing_argument():
    """
    Given: Both item_id and share_url.
    When: Running msgraph-driveitem-metadata-get.
    Then: A DemistoException naming the conflicting arguments is raised before any HTTP call.
    """
    with pytest.raises(DemistoException) as exc_info:
        get_driveitem_metadata_command(CLIENT_MOCKER, {"item_id": "item-1", "share_url": "https://e.sharepoint.com/x"})

    assert "Provide only one of the following arguments, but got item_id, share_url." in str(exc_info.value)


# Shaped from a real v1.0 response captured against a live tenant. The action facets are nested
# under 'action' and the timestamp lives at 'times.recordedDateTime' - NOT at a top-level
# 'activityDateTime', which is what the beta endpoint and parts of the documentation describe.
DRIVEITEM_ACTIVITIES_RESPONSE = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#activities",
    "value": [
        {
            "id": "wDv99w9U3khuO0MPAAAAAA==",
            "action": {"share": {}},
            "times": {"recordedDateTime": "2026-01-15T08:27:49Z"},
            "actor": {"user": {"displayName": "Fake User", "email": "fake.user@example.com"}},
        },
        {
            "id": "8DvNr6FL3kgZ9D8PAAAAAA==",
            # Multiple facets at once, one of which carries a payload worth surfacing.
            "action": {"edit": {}, "version": {"newVersion": "2.0"}},
            "times": {"recordedDateTime": "2026-01-04T14:58:14Z"},
            "actor": {"user": {"displayName": "Someone Else"}},
        },
    ],
}


# Activities and analytics both address the item through its SharePoint list representation, so
# every non-paged call is preceded by a sharepointIds lookup.
SHAREPOINT_IDS_RESPONSE = {
    "sharepointIds": {
        "listId": "list-1",
        "listItemUniqueId": "list-item-1",
        "siteId": "site-1",
    }
}


def test_list_driveitem_activities_command_uses_list_item_route(mocker: MockerFixture):
    """
    Given: A site_id and an item_id.
    When: Running msgraph-driveitem-activities-list.
    Then: The item's SharePoint identifiers are resolved first, and the activities are then read
          from the list-item route keyed by listItemUniqueId rather than by the driveItem ID.
    """
    http_request = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        side_effect=[SHAREPOINT_IDS_RESPONSE, DRIVEITEM_ACTIVITIES_RESPONSE],
    )

    result = list_driveitem_activities_command(CLIENT_MOCKER, {"site_id": "site-1", "item_id": "item-1"})

    assert http_request.call_count == 2
    assert http_request.call_args_list[0].kwargs["url_suffix"] == "sites/site-1/drive/items/item-1"
    assert http_request.call_args_list[0].kwargs["params"] == {"$select": "sharepointIds"}
    # The activities route keys off listItemUniqueId, not the driveItem ID.
    assert http_request.call_args_list[1].kwargs["url_suffix"] == "sites/site-1/lists/list-1/items/list-item-1/activities"
    assert result.outputs_prefix == "MsGraphFiles.ItemActivity"
    assert result.outputs["SiteID"] == "site-1"
    assert result.outputs["ItemId"] == "item-1"
    assert len(result.outputs["Value"]) == 2
    assert result.outputs["Value"][0]["ID"] == "wDv99w9U3khuO0MPAAAAAA=="
    # The v1.0 schema carries the timestamp at times.recordedDateTime.
    assert result.outputs["Value"][0]["Times"]["RecordedDateTime"] == "2026-01-15T08:27:49Z"
    assert "Fake User" in result.readable_output or "fake.user@example.com" in result.readable_output
    # The table must show the real facet name and the timestamp - a regression here previously
    # rendered the literal word "Action" and dropped the date column entirely.
    # Facet names arrive title-cased because parse_key_to_context normalizes every key.
    assert "Share" in result.readable_output
    assert "2026-01-15T08:27:49Z" in result.readable_output
    assert "Recorded Date Time" in result.readable_output
    # The version facet carries a payload worth surfacing alongside the facet name.
    assert "Edit, Version (2.0)" in result.readable_output


def test_list_driveitem_activities_command_raises_when_item_is_not_a_list_item(mocker: MockerFixture):
    """
    Given: An item that exposes no SharePoint identifiers, for example one held outside a
           document library.
    When: Running msgraph-driveitem-activities-list.
    Then: A DemistoException explains why the item cannot be addressed, instead of a confusing
          404 from a URL built with empty identifiers.
    """
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value={"sharepointIds": {}})

    with pytest.raises(DemistoException) as exc:
        list_driveitem_activities_command(CLIENT_MOCKER, {"site_id": "site-1", "item_id": "item-1"})

    assert "Could not resolve the SharePoint list identifiers for item 'item-1'" in str(exc.value)


def test_list_driveitem_activities_command_limit_is_client_side(mocker: MockerFixture):
    """
    Given: A limit argument.
    When: Running msgraph-driveitem-activities-list.
    Then: The results are truncated locally and no $top is sent, because the activities
          endpoint supports no OData query parameters.
    """
    http_request = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        side_effect=[SHAREPOINT_IDS_RESPONSE, DRIVEITEM_ACTIVITIES_RESPONSE],
    )

    result = list_driveitem_activities_command(CLIENT_MOCKER, {"site_id": "site-1", "item_id": "item-1", "limit": "1"})

    assert len(result.outputs["Value"]) == 1
    # No query parameters on the activities call itself - only the sharepointIds lookup uses any.
    assert "params" not in http_request.call_args_list[1].kwargs


def test_list_driveitem_activities_command_no_activities(mocker: MockerFixture):
    """
    Given: An item with no recorded activity.
    When: Running msgraph-driveitem-activities-list.
    Then: A friendly message is returned rather than an empty table. An empty result is also
          what an unlicensed tenant returns, so this path must stay readable.
    """
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", side_effect=[SHAREPOINT_IDS_RESPONSE, {"value": []}])

    result = list_driveitem_activities_command(CLIENT_MOCKER, {"site_id": "site-1", "item_id": "item-1"})

    assert "No activities were found for item item-1." in result.readable_output


def test_list_driveitem_activities_command_next_page_url(mocker: MockerFixture):
    """
    Given: A next_page_url from a previous response.
    When: Running msgraph-driveitem-activities-list.
    Then: The full URL is followed directly, with no sharepointIds lookup - the identifiers are
          already baked into the paging URL.
    """
    http_request = mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value=DRIVEITEM_ACTIVITIES_RESPONSE)
    next_url = "https://graph.microsoft.com/v1.0/sites/site-1/lists/list-1/items/list-item-1/activities?$skiptoken=abc"

    list_driveitem_activities_command(CLIENT_MOCKER, {"site_id": "site-1", "item_id": "item-1", "next_page_url": next_url})

    assert http_request.call_count == 1
    assert http_request.call_args.kwargs["full_url"] == next_url


""" msgraph-driveitem-analytics-get """


DRIVEITEM_ANALYTICS_RESPONSE = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#itemAnalytics",
    "allTime": {
        "startDateTime": "2024-01-01T00:00:00Z",
        "endDateTime": "2026-01-15T00:00:00Z",
        "access": {"actionCount": 24, "actorCount": 5},
        "edit": {"actionCount": 3, "actorCount": 2},
    },
}


def test_get_driveitem_analytics_command_uses_list_item_route(mocker: MockerFixture):
    """
    Given: A site_id and an item_id.
    When: Running msgraph-driveitem-analytics-get.
    Then: The SharePoint identifiers are resolved first and the analytics are read from the
          list-item route, the same addressing the activities command uses.
    """
    http_request = mocker.patch.object(
        CLIENT_MOCKER.ms_client,
        "http_request",
        side_effect=[SHAREPOINT_IDS_RESPONSE, DRIVEITEM_ANALYTICS_RESPONSE],
    )

    result = get_driveitem_analytics_command(CLIENT_MOCKER, {"site_id": "site-1", "item_id": "item-1"})

    assert http_request.call_count == 2
    assert http_request.call_args_list[0].kwargs["url_suffix"] == "sites/site-1/drive/items/item-1"
    assert http_request.call_args_list[1].kwargs["url_suffix"] == "sites/site-1/lists/list-1/items/list-item-1/analytics/allTime"
    assert result.outputs_prefix == "MsGraphFiles.ItemAnalytics"
    assert result.outputs["TimeRange"] == "allTime"
    assert result.outputs["SiteID"] == "site-1"
    # The stats are lifted out of the time-range wrapper into a single Stats object.
    assert result.outputs["Stats"]["Access"]["ActionCount"] == 24
    assert "24" in result.readable_output


def test_get_driveitem_analytics_command_surfaces_undocumented_facets(mocker: MockerFixture):
    """
    Given: An analytics payload containing a facet beyond the four the table used to hard-code.
    When: Running msgraph-driveitem-analytics-get.
    Then: The extra facet reaches the table. The previous implementation iterated a fixed
          ("Access", "Create", "Edit", "Delete") tuple and silently dropped anything else.
    """
    response = {
        "allTime": {
            "startDateTime": "2024-01-01T00:00:00Z",
            "endDateTime": "2026-01-15T00:00:00Z",
            "access": {"actionCount": 24, "actorCount": 5},
            "move": {"actionCount": 7, "actorCount": 1},
        }
    }
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", side_effect=[SHAREPOINT_IDS_RESPONSE, response])

    result = get_driveitem_analytics_command(CLIENT_MOCKER, {"site_id": "site-1", "item_id": "item-1"})

    assert "Move" in result.readable_output
    assert "Access" in result.readable_output
    # The window scalars describe the period, not an action, so they must not become rows.
    assert "StartDateTime" not in result.readable_output
    assert "Start Date Time" not in result.readable_output


def test_get_driveitem_analytics_command_no_rows_when_only_window_scalars(mocker: MockerFixture):
    """
    Given: A payload carrying only the start/end window and no action facet.
    When: Running msgraph-driveitem-analytics-get.
    Then: The "no analytics data" message is produced rather than a table of empty rows.
    """
    response = {"allTime": {"startDateTime": "2024-01-01T00:00:00Z", "endDateTime": "2026-01-15T00:00:00Z"}}
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", side_effect=[SHAREPOINT_IDS_RESPONSE, response])

    result = get_driveitem_analytics_command(CLIENT_MOCKER, {"site_id": "site-1", "item_id": "item-1"})

    assert "No analytics data was returned for item item-1" in result.readable_output


def test_get_driveitem_analytics_command_raises_when_item_is_not_a_list_item(mocker: MockerFixture):
    """
    Given: An item that exposes no SharePoint identifiers.
    When: Running msgraph-driveitem-analytics-get.
    Then: The same explanatory error as the activities command is raised, rather than a 404 from
          a URL built with empty identifiers.
    """
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", return_value={"sharepointIds": {}})

    with pytest.raises(DemistoException) as exc:
        get_driveitem_analytics_command(CLIENT_MOCKER, {"site_id": "site-1", "item_id": "item-1"})

    assert "Could not resolve the SharePoint list identifiers for item 'item-1'" in str(exc.value)


def test_get_driveitem_analytics_command_last_seven_days(mocker: MockerFixture):
    """
    Given: time_range=lastSevenDays, whose payload is returned bare rather than nested.
    When: Running msgraph-driveitem-analytics-get.
    Then: The time range reaches the URL and the bare stats shape is normalized the same way.
    """
    bare_response = {"access": {"actionCount": 4, "actorCount": 1}}
    http_request = mocker.patch.object(
        CLIENT_MOCKER.ms_client, "http_request", side_effect=[SHAREPOINT_IDS_RESPONSE, bare_response]
    )

    result = get_driveitem_analytics_command(
        CLIENT_MOCKER, {"site_id": "site-1", "item_id": "item-1", "time_range": "lastSevenDays"}
    )

    assert (
        http_request.call_args_list[1].kwargs["url_suffix"]
        == "sites/site-1/lists/list-1/items/list-item-1/analytics/lastSevenDays"
    )
    assert result.outputs["TimeRange"] == "lastSevenDays"
    assert result.outputs["Stats"]["Access"]["ActionCount"] == 4


def test_get_driveitem_analytics_command_no_data(mocker: MockerFixture):
    """
    Given: An empty analytics payload, which is also what a tenant without the required plan returns.
    When: Running msgraph-driveitem-analytics-get.
    Then: A message that names the licensing possibility is returned instead of an empty table.
    """
    mocker.patch.object(CLIENT_MOCKER.ms_client, "http_request", side_effect=[SHAREPOINT_IDS_RESPONSE, {}])

    result = get_driveitem_analytics_command(CLIENT_MOCKER, {"site_id": "site-1", "item_id": "item-1"})

    assert "No analytics data was returned for item item-1" in result.readable_output
    assert "tenant plan" in result.readable_output
