import pytest
from freezegun import freeze_time
import time
import json
import CommonServerPython
from MicrosoftGraphFiles import epoch_seconds, get_encrypted, remove_identity_key, url_validation, parse_key_to_context, test_module, delete_file_command,\
    download_file_command, list_tenant_sites_command, list_drive_children_command, create_new_folder_command, replace_an_existing_file_command, list_drives_in_site_command,\
    upload_new_file_command



with open('test_data/response.json', 'rb') as test_data:
    commands_responses = json.load(test_data)

with open('test_data/inputs1.json', 'rb') as test_data:
    arguments = json.load(test_data)

EXCLUDE_LIST = ['eTag']

RESPONSE_KEYS_DICTIONARY = {
    "@odata.context": "OdataContext",
}

@pytest.mark.commands
@freeze_time(time.ctime(1576009202))
def test_epoch_seconds():
    """
    Given:

    When
        - Save creation time for access token in context
    Then
        - The function returns current date in seconds
    """
    assert epoch_seconds() == 1576016402


def test_get_encrypted():
    """
    Given:

    When
        - Save creation time for access token in context
    Then
        - The function returns current date in seconds
    """
    res = get_encrypted('34534545', 'hgrfhgfgf9qxsgaff4UmdxIYqsLRjCExiHsJgfgj+vf=')
    assert (isinstance(res, str) and res)


def test_remove_identity_key_with_valid_application_input():
    """
    Given:
        - Dictionary with three nested objects which the creator type is "application"
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    res = remove_identity_key(arguments['remove_identifier_data_application_type']['CreatedBy'])
    assert len(res.keys()) > 1 and res.get('Type')
    assert res['ID'] == 'test'


def test_remove_identity_key_with_valid_user_input():
    """
    Given:
        - Dictionary with three nested objects which the creator type is "user" and system account
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    res = remove_identity_key(arguments['remove_identifier_data_user_type']['CreatedBy'])
    assert len(res.keys()) > 1 and res.get('Type')
    assert res.get('ID') is None


def test_remove_identity_key_with_valid_empty_input():
    """
    Given:
        - Dictionary with three nested objects
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    res = remove_identity_key('')
    assert res == ''


def test_remove_identity_key_with_invalid_object():
    """
    Given:
        - Dictionary with three nested objects
    When
        - When Parsing outputs to context
    Then
        - Dictionary to remove to first key and add it as an item in the dictionary
    """
    object = 'not a dict'
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
    res = url_validation(arguments['valid_next_link_url'])
    assert res == arguments['valid_next_link_url']


def test_url_validation_with_empty_string():
    """
    Given:
        - Empty string as next link url
    When
        - Got a bad input from the user
    Then
        - Returns Demisto error
    """
    next_link_url = ''
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
        url_validation(arguments['invalid_next_link_url'])
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
    parsed_response = parse_key_to_context(commands_responses['list_drive_children_response']['value'][0])
    assert parsed_response.get('eTag', True) is True
    assert parsed_response.get('ETag', True) is True


# @pytest.mark.parametrize('command, args, response, expected_result', [
#     (test_module, {}, RESPONSE_LIST_GROUPS, EXPECTED_LIST_GROUPS),
#     (delete_file_command, {'group_id': '123'}, RESPONSE_GET_GROUP, EXPECTED_GET_GROUP),
#     (download_file_command, {'group_id': '123', 'mail_nickname': 'nick', 'security_enabled': True},
#     (list_tenant_sites_command, {'group_id': '123', 'mail_nickname': 'nick', 'security_enabled': True},
#     (list_drive_children_command, {'group_id': '123', 'mail_nickname': 'nick', 'security_enabled': True},
#     (create_new_folder_command, {'group_id': '123', 'mail_nickname': 'nick', 'security_enabled': True},
#     (replace_an_existing_file_command, {'group_id': '123', 'mail_nickname': 'nick', 'security_enabled': True},
#     (list_drives_in_site_command, {'group_id': '123', 'mail_nickname': 'nick', 'security_enabled': True},
#     (upload_new_file_command, {'group_id': '123', 'mail_nickname': 'nick', 'security_enabled': True},
#      RESPONSE_CREATE_GROUP, EXPECTED_CREATE_GROUP),
# ])  # noqa: E124
# def test_commands(command, args, response, expected_result, mocker):
#     client = Client('https://graph.microsoft.com/v1.0', 'tenant-id', 'auth_and_token_url', 'auth_id',
#                     'token_retrieval_url', 'enc_key', 'use_ssl', 'proxies')
#   mocker.patch.object(client, 'http_request', return_value=response)
#     result = command(client, args)
#     assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
