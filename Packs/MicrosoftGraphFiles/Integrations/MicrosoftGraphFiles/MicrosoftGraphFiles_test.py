import pytest
import json
import CommonServerPython
from MicrosoftGraphFiles import remove_identity_key, url_validation, parse_key_to_context, delete_file_command, \
    download_file_command, list_sharepoint_sites_command, list_drive_content_command, create_new_folder_command, \
    list_drives_in_site_command, MsGraphClient

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


class File(object):
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
    assert len(res.keys()) > 1 and res.get("Type")
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
    assert len(res.keys()) > 1 and res.get("Type")
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
    object = "not a dict"
    res = remove_identity_key(object)
    assert res == object


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
    try:
        url_validation(next_link_url)
    except CommonServerPython.DemistoException:
        assert True
    else:
        assert False


def test_url_validation_with_invalid_url():
    """
    Given:
        - invalid string as next link url
    When
        - Got a bad input from the user
    Then
        - Returns Demisto error
    """

    try:
        url_validation(arguments["invalid_next_link_url"])
    except CommonServerPython.DemistoException:
        assert True
    else:
        assert False


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
