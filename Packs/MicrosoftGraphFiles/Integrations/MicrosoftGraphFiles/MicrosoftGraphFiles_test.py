import pytest
import json
import CommonServerPython
import demistomock as demisto
from MicrosoftGraphFiles import remove_identity_key, url_validation, parse_key_to_context, delete_file_command, \
    download_file_command, list_sharepoint_sites_command, list_drive_content_command, create_new_folder_command, \
    list_drives_in_site_command, MsGraphClient, upload_new_file_command

with open("test_data/response.json", "rb") as test_data:
    commands_responses = json.load(test_data)

with open("test_data/test_inputs.json", "rb") as test_data:
    arguments = json.load(test_data)

with open("test_data/expected_results.json", "rb") as test_data:
    commands_expected_results = json.load(test_data)

EXCLUDE_LIST = ["eTag"]

RESPONSE_KEYS_DICTIONARY = {
    "@odata.context": "OdataContext",
}


class File:
    content = b"12345"


client_mocker = MsGraphClient(
    tenant_id="tenant_id", auth_id="auth_id", enc_key='enc_key', app_name='app_name',
    base_url='url', verify='use_ssl', proxy='proxy', self_deployed='self_deployed', ok_codes=(1, 2, 3))


def test_remove_identity_key_with_valid_application_input():
    """
    Given:
        - Dictionary with three nested objects which the creator type is "application"
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    res = remove_identity_key(
        arguments["remove_identifier_data_application_type"]["CreatedBy"]
    )
    assert len(res.keys()) > 1
    assert res.get("Type")
    assert res["ID"] == "test"


def test_remove_identity_key_with_valid_user_input():
    """
    Given:
        - Dictionary with three nested objects which the creator type is "user" and system account
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    res = remove_identity_key(
        arguments["remove_identifier_data_user_type"]["CreatedBy"]
    )
    assert len(res.keys()) > 1
    assert res.get("Type")
    assert res.get("ID") is None


def test_remove_identity_key_with_valid_empty_input():
    """
    Given:
        - Dictionary with three nested objects
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    res = remove_identity_key("")
    assert res == ""


def test_remove_identity_key_with_invalid_object():
    """
    Given:
        - Dictionary with three nested objects
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    source = 'not a dict'
    res = remove_identity_key(source)
    assert res == source


def test_url_validation_with_valid_link():
    """
    Given:
        - Link to more results for list commands
    When
        - There is too many results
    Then
        - Returns True if next link url is valid
    """
    res = url_validation(arguments["valid_next_link_url"])
    assert res == arguments["valid_next_link_url"]


def test_url_validation_with_empty_string():
    """
    Given:
        - Empty string as next link url
    When
        - Got a bad input from the user
    Then
        - Returns Demisto error
    """
    next_link_url = ""
    with pytest.raises(CommonServerPython.DemistoException):
        url_validation(next_link_url)


def test_url_validation_with_invalid_url():
    """
    Given:
        - invalid string as next link url
    When
        - Got a bad input from the user
    Then
        - Returns Demisto error
    """

    with pytest.raises(CommonServerPython.DemistoException):
        url_validation(arguments["invalid_next_link_url"])


def test_parse_key_to_context_exclude_keys_from_list():
    """
    Given:
        - Raw response from graph api
    When
        - Parsing data to context
    Then
        - Exclude from output unwanted keys
    """
    parsed_response = parse_key_to_context(
        commands_responses["list_drive_children"]["value"][0]
    )
    assert parsed_response.get("eTag", True) is True
    assert parsed_response.get("ETag", True) is True


@pytest.mark.parametrize(
    "command, args, response, expected_result",
    [
        (
            download_file_command,
            {"object_type": "drives", "object_type_id": "123", "item_id": "232"}, File,
            commands_expected_results["download_file"]
        ),
    ],
)  # noqa: E124
def test_download_file(command, args, response, expected_result, mocker):
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - return FileResult object
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=response)
    result = command(client_mocker, args)
    assert "Contents" in list(result.keys())


@pytest.mark.parametrize(
    "command, args, response, expected_result",
    [
        (
            delete_file_command,
            {"object_type": "drives", "object_type_id": "123", "item_id": "232"},
            commands_responses["download_file"],
            commands_expected_results["download_file"],
        )
    ],
)  # noqa: E124
def test_delete_file(command, args, response, expected_result, mocker):
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - return FileResult object
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=response)
    human_readable, result = command(client_mocker, args)
    assert expected_result == result


@pytest.mark.parametrize(
    "command, args, response, expected_result",
    [
        (
            list_sharepoint_sites_command,
            {},
            commands_responses["list_tenant_sites"],
            commands_expected_results["list_tenant_sites"],
        )
    ],
)  # noqa: E124
def test_list_tenant_sites(command, args, response, expected_result, mocker):
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - return FileResult object
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=response)
    result = command(client_mocker, args)
    assert expected_result == result[1]


@pytest.mark.parametrize(
    "command, args, response, expected_result",
    [
        (
            list_drive_content_command,
            {"object_type": "sites", "object_type_id": "12434", "item_id": "123"},
            commands_responses["list_drive_children"],
            commands_expected_results["list_drive_children"],
        )
    ],
)  # noqa: E124
def test_list_drive_content(command, args, response, expected_result, mocker):
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - return FileResult object
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=response)
    result = command(client_mocker, args)
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
            commands_responses["create_new_folder"],
            commands_expected_results["create_new_folder"],
        )
    ],
)  # noqa: E124
def test_create_name_folder(command, args, response, expected_result, mocker):
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - return FileResult object
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=response)
    result = command(client_mocker, args)
    assert expected_result == result[1]


@pytest.mark.parametrize(
    "command, args, response, expected_result",
    [
        (
            list_drives_in_site_command,
            {"site_id": "site_id"},
            commands_responses["list_drives_in_a_site"],
            commands_expected_results["list_drives_in_a_site"],
        )
    ],
)  # noqa: E124
def test_list_drives_in_site(command, args, response, expected_result, mocker):
    """
    Given:
        - Location to where to upload file to Graph Api
    When
        - Using download file command in Demisto
    Then
        - return FileResult object
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=response)
    result = command(client_mocker, args)
    assert expected_result == result[1]


def expected_upload_headers():
    return [
        {'Content-Length': '327680', 'Content-Range': 'bytes 0-327679/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 327680-655359/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 655360-983039/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 983040-1310719/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 1310720-1638399/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 1638400-1966079/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 1966080-2293759/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 2293760-2621439/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 2621440-2949119/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 2949120-3276799/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 3276800-3604479/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 3604480-3932159/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 3932160-4259839/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 4259840-4587519/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 4587520-4915199/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 4915200-5242879/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 5242880-5570559/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 5570560-5898239/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 5898240-6225919/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 6225920-6553599/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 6553600-6881279/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '327680', 'Content-Range': 'bytes 6881280-7208959/7450762',
         'Content-Type': 'application/octet-stream'},
        {'Content-Length': '241802', 'Content-Range': 'bytes 7208960-7450761/7450762',
         'Content-Type': 'application/octet-stream'},
    ]


def validate_upload_attachments_flow(create_upload_mock, upload_query_mock):
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
        mock_res = upload_query_mock.mock_calls[i].kwargs['headers']
        if mock_res != current_headers:
            return False
    return True


def self_deployed_client():
    return MsGraphClient(tenant_id="tenant_id", auth_id="auth_id", enc_key='enc_key', app_name='app_name',
                         base_url='url', verify='use_ssl', proxy='proxy', self_deployed='self_deployed', ok_codes=(1, 2, 3))


json_response = {'@odata.context': 'dummy_url',
                 '@content.downloadUrl': 'dummy_url',
                 'createdBy': {'application': {'id': 'some_id',
                               'displayName': 'MS Graph Files'},
                               'user': {'displayName': 'SharePoint App'}},
                 'createdDateTime': 'some_date',
                 'eTag': '"some_eTag"',
                 'id': 'some_id',
                 'lastModifiedBy': {'application': {'id': 'some_id',
                                    'displayName': 'MS Graph Files'},
                                    'user': {'displayName': 'SharePoint App'}},
                 'lastModifiedDateTime': 'some_date',
                 'name': 'yaya.jpg',
                 'parentReference': {'driveType': 'documentLibrary',
                                     'driveId': 'some_id',
                                     'id': 'some_id',
                                     'path': 'some_path'},
                 'webUrl': 'https://some_url',
                 'cTag': '"c:{000-000},0"',
                 'file': {'hashes': {'quickXorHash': '00000'},
                          'irmEffectivelyEnabled': False, 'irmEnabled': False,
                          'mimeType': 'image/jpeg'},
                 'fileSystemInfo': {'createdDateTime': 'some_date',
                                    'lastModifiedDateTime': 'some_date'},
                 'image': {}, 'shared': {'effectiveRoles': ['write'],
                                         'scope': 'users'}, 'size': 5906704}


class MockedResponse:

    def __init__(self, status_code, json):
        self.status_code = status_code
        self.json_response = json

    def json(self):
        return self.json_response


def upload_response_side_effect(**kwargs):
    headers = kwargs.get('headers')
    if headers and int(headers['Content-Length']) < MsGraphClient.MAX_ATTACHMENT_UPLOAD:
        return MockedResponse(status_code=201, json=json_response)
    return MockedResponse(status_code=202, json='')


UPLOAD_LARGE_FILE_COMMAND_ARGS = [
    (
        self_deployed_client(),
        {
            'object_type': 'drives',
            'object_type_id': 'some_object_type_id',
            'parent_id': 'some_parent_id',
            'entry_id': '3',
            'file_name': 'some_file_name',
        },
    )]

return_value_upload_without_upload_session = {'@odata.context': "https://graph.microsoft.com/v1.0/$metadata#sites"
                                                                "(some_site)/drive/items/$entity",
                                              '@microsoft.graph.downloadUrl': 'some_url',
                                              'createdDateTime': '2022-12-15T12:56:27Z',
                                              'eTag': '"{11111111-1111-1111-1111-111111111111},11"',
                                              'id': 'some_id',
                                              'lastModifiedDateTime': '2022-12-28T11:38:55Z',
                                              'name': 'some_pdf.pdf',
                                              'webUrl': 'https://some_url/some_pdf.pdf',
                                              'cTag': '"c:{11111111-1111-1111-1111-111111111111},11"', 'size': 3028,
                                              'createdBy': {'application': {'id': 'some_id',
                                                                            'displayName': 'MS Graph Files'},
                                                            'user': {'displayName': 'SharePoint App'}},
                                              'lastModifiedBy': {'application': {'id': 'some_id',
                                                                                 'displayName': 'MS Graph Files'},
                                                                 'user': {'displayName': 'SharePoint App'}},
                                              'parentReference': {'driveType': 'documentLibrary',
                                                                  'driveId': 'some_drive_id',
                                                                  'id': 'some_id',
                                                                  'path': '/drive/root:/test-folder'},
                                              'file': {'mimeType': 'image/jpeg',
                                                       'hashes': {'quickXorHash': 'quickXorHash'}},
                                              'fileSystemInfo': {'createdDateTime': '2022-12-15T12:56:27Z',
                                                                 'lastModifiedDateTime': '2022-12-28T11:38:55Z'},
                                              'image': {},
                                              'shared': {'scope': 'users'}}

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


@pytest.mark.parametrize('client, args', UPLOAD_LARGE_FILE_COMMAND_ARGS)
def test_upload_command_with_upload_session(mocker, client, args):
    """
        Given:
            - An image to upload with a size bigger than 3.
        When:
            - running upload new file command.
        Then:
            - return an result with upload session.
     """
    import requests
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_data/shark.jpg',
                                                              'name': 'shark.jpg'})
    create_upload_mock = mocker.patch.object(MsGraphClient, 'create_an_upload_session',
                                             return_value=({"response": "", "uploadUrl": "test.com"}, "test.com"))
    upload_query_mock = mocker.patch.object(requests, 'put', side_effect=upload_response_side_effect)
    upload_file_without_upload_session_mock = mocker.patch.object(MsGraphClient, 'upload_new_file',
                                                                  return_value="")
    upload_new_file_command(client, args)
    assert upload_file_without_upload_session_mock.call_count == 0
    assert validate_upload_attachments_flow(create_upload_mock, upload_query_mock)


@pytest.mark.parametrize('client, args', UPLOAD_LARGE_FILE_COMMAND_ARGS)
def test_upload_command_without_upload_session(mocker, client, args):
    """
        Given:
            - An image to upload (file size lower than 3).
        When:
            - running upload new file command.
        Then:
            - return an result without upload session.
     """
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_data/some_pdf.pdf',
                                                              'name': 'some_pdf.pdf'})
    mocker_https = mocker.patch.object(client.ms_client, "http_request", return_value=return_value_upload_without_upload_session)
    create_upload_mock = mocker.patch.object(MsGraphClient, 'create_an_upload_session',
                                             return_value=({"response": "", "uploadUrl": "test.com"}, "test.com"))
    upload_file_with_upload_session_mock = mocker.patch.object(MsGraphClient, 'upload_file_with_upload_session_flow',
                                                               return_value=({"response": "",
                                                                              "uploadUrl": "test.com"}, "test.com"))

    human_readable, context, result = upload_new_file_command(client, args)
    assert mocker_https.call_count == 1
    assert create_upload_mock.call_count == 0
    assert upload_file_with_upload_session_mock.call_count == 0
    assert human_readable == '### MsGraphFiles - File information:\n|CreatedDateTime|ID|Name|Size|WebUrl|\n|---|---|---|---|---|'\
                             '\n| 2022-12-15T12:56:27Z | some_id | some_pdf.pdf | 3028 | https://some_url/some_pdf.pdf |\n'
    assert result == return_value_upload_without_upload_session
    assert context == return_context


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
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

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f'^{Resources.graph}.*'), json={})

    params = {
        'managed_identities_client_id': {'password': client_id},
        'authentication_type': 'Azure Managed Identities',
        'host': Resources.graph
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in demisto.results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs
