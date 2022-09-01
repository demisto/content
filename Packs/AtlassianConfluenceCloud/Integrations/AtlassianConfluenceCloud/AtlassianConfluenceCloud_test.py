import io

import pytest
from CommonServerPython import *
from AtlassianConfluenceCloud import Client, URL_SUFFIX, MESSAGES
from test_data import input_data

BASE_URL = "https://dummy.atlassian.com"

client = Client(BASE_URL, True, False, headers={"Accept": "application/json"}, auth=("user", "user123"))


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module_when_valid_response_is_returned(requests_mock):
    """
    To test test_module command when success response come.
    Given
        - A valid response
    When
        - The status code returned is 200
    Then
        - Ensure test module should return success
    """
    from AtlassianConfluenceCloud import test_module

    requests_mock.get(BASE_URL + URL_SUFFIX["CONTENT_SEARCH"], status_code=200)
    assert test_module(client) == 'ok'


@pytest.mark.parametrize("status_code, error_msg", input_data.exception_handler_params)
def test_exception_handler(status_code, error_msg, requests_mock):
    """
    To test exception handler in various http error code.
    Given
        - a dictionary containing http code
    When
        - they are the error codes
    Then
        - raise DemistoException
    """
    requests_mock.get(BASE_URL, status_code=status_code)

    with pytest.raises(DemistoException) as ve:
        Client.http_request(client, method='GET')

    assert str(ve.value) == error_msg


@pytest.mark.parametrize("status_code, error_msg", input_data.exception_handler_forbidden_response)
def test_exception_handler_when_403_error_occurred(status_code, error_msg, requests_mock, capfd):
    """
    To test exception handler when 403 error code occurred.
    Given
        - a dictionary containing http error code 403
    Then
        - raise DemistoException
    """
    api_error_msg = util_load_json("test_data/error_msg_for_403_error_code.json")
    requests_mock.get(BASE_URL, json=api_error_msg, status_code=status_code)
    with capfd.disabled():
        with pytest.raises(DemistoException) as de:
            Client.http_request(client, method='GET')

        assert str(de.value) == error_msg


def test_validate_url():
    """
    To test validate_url helper function when empty url is given.
    Given
        - whitespaces provided in Site Name
    Then
        - Returns the response message of invalid input
    """
    from AtlassianConfluenceCloud import validate_url

    with pytest.raises(ValueError) as ve:
        validate_url("")

    assert str(ve.value) == "Site Name can not be empty."


def test_confluence_cloud_group_list_command_when_valid_response_is_returned(requests_mock):
    """
    To test confluence_cloud_group_list command when valid response return.
    Given:
        - command arguments for list group command
    When:
        - Calling `confluence-cloud-group-list` command
    Then:
        -  Returns the response data
    """
    from AtlassianConfluenceCloud import confluence_cloud_group_list_command

    expected_response = util_load_json(os.path.join("test_data", "group/group_list_command_response.json"))
    requests_mock.get(BASE_URL + URL_SUFFIX["GROUP"], json=expected_response)
    expected_context_output = util_load_json(os.path.join("test_data", "group/group_list_command_context.json"))

    with open(os.path.join("test_data", "group/group_list_command.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "limit": "2",
        "access_type": "site-admin"
    }
    response = confluence_cloud_group_list_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Group'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


@pytest.mark.parametrize("args, err_msg", input_data.list_group_invalid_args)
def test_confluence_cloud_group_list_command_when_invalid_args_are_provided(args, err_msg):
    """
    To test confluence_cloud_group_list command when invalid arguments are provided.
    Given:
        - invalid command arguments for list group command
    When
        - Calling `confluence-cloud-group-list`
    Then:
        - Returns the response message of invalid input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_group_list_command
    with pytest.raises(ValueError) as de:
        confluence_cloud_group_list_command(client, args)
    assert str(de.value) == err_msg


def test_confluence_cloud_group_list_command_when_empty_response_is_returned(requests_mock):
    """
    Test case scenario for successful execution of confluence_cloud_group_list command with an empty response.
    Given:
        - command arguments for list group command
    When:
        - Calling `confluence-cloud-group-list` command
    Then:
        - Returns no records for the given input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_group_list_command
    requests_mock.get(BASE_URL + URL_SUFFIX["GROUP"], json={"results": []}, status_code=200)
    command_results = confluence_cloud_group_list_command(client, {"limit": "0"})
    assert command_results.readable_output == "No group(s) were found for the given argument(s)."


def test_confluence_cloud_content_delete_command_when_valid_response_is_returned(requests_mock):
    """
    To test confluence_cloud_content_delete command when valid response return.
    Given:
        - command arguments for delete content command
    When:
        - Calling `confluence-cloud-content-delete` command
    Then:
        - Returns the response data
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_delete_command

    requests_mock.delete(BASE_URL + URL_SUFFIX["CONTENT"] + "/123", status_code=204)

    args = {
        "content_id": "123"
    }
    response = confluence_cloud_content_delete_command(client, args)

    assert response.readable_output == MESSAGES["HR_DELETE_CONTENT"].format("123")


@pytest.mark.parametrize("args, error_msg", input_data.delete_content_invalid_args)
def test_confluence_cloud_content_delete_command_when_invalid_argument_given(args, error_msg):
    """
    To test confluence_cloud_content_delete command when invalid argument is provided.
    Given:
        - invalid command arguments for delete content command
    When
        - Calling `confluence-cloud-content-delete`
    Then:
        - Returns the response message of invalid input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_delete_command

    with pytest.raises(ValueError) as de:
        confluence_cloud_content_delete_command(client, args)
    assert str(de.value) == error_msg


def test_confluence_cloud_content_delete_command_when_api_returns_error(requests_mock, capfd):
    """
    To test confluence_cloud_content_delete_command when 400 error code occurred.
    Given:
        - invalid command arguments for delete content command
    When:
        - Calling `confluence-cloud-content-delete` command
    Then:
        - Raise DemistoException
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_delete_command

    api_error_msg = util_load_json("test_data/content_delete/content_delete_command_bad_request_error.json")
    requests_mock.delete(BASE_URL + URL_SUFFIX["CONTENT"] + "/123", json=api_error_msg, status_code=400)

    args = {
        "content_id": "123",
        "status": "draft"
    }
    with capfd.disabled():
        with pytest.raises(DemistoException) as de:
            confluence_cloud_content_delete_command(client, args)

        assert str(de.value) == f"{api_error_msg.get('data').get('errors')[0].get('message').get('translation')} \n"


def test_confluence_cloud_content_create_command_when_valid_response_is_returned(requests_mock):
    """
    To test confluence_cloud_content_create command when valid response return.
    Given:
        - command arguments for create content command
    When:
        - Calling `confluence-cloud-content-create` command
    Then:
        - Returns the response data
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_create_command

    expected_response = util_load_json(os.path.join("test_data", "content_create/content_create_command_response.json"))
    requests_mock.post(BASE_URL + URL_SUFFIX["CONTENT"], json=expected_response)
    expected_context_output = util_load_json(os.path.join("test_data", "content_create"
                                                                       "/content_create_command_context.json"))

    with open(os.path.join("test_data", "content_create/content_create_command.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "title": "XSOAR_Page",
        "type": "page",
        "space_key": "XSOAR"
    }
    response = confluence_cloud_content_create_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Content'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


@pytest.mark.parametrize("args, err_msg", input_data.content_create_invalid_args)
def test_confluence_cloud_content_create_command_when_invalid_args_are_provided(args, err_msg):
    """
    To test confluence_cloud_content_create command when invalid arguments are provided.
    Given:
        - invalid command arguments for create content command
    When
        - Calling `confluence-cloud-content-create` command
    Then:
        - Returns the response message of invalid input arguments
    """
    from AtlassianConfluenceCloud import validate_create_content_args
    with pytest.raises(ValueError) as de:
        validate_create_content_args(args, is_update=False)
    assert str(de.value) == err_msg


def test_confluence_cloud_content_create_command_when_object_not_present(requests_mock):
    """
    To test confluence_cloud_content_create command when valid response return.
    Given:
        - command arguments for list group command
    When:
        - Calling `confluence-cloud-group-list` command
    Then:
        -  Returns the response with some missing values
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_create_command

    expected_response = util_load_json(
        os.path.join("test_data", "content_create/content_create_object_not_present.json"))
    requests_mock.post(BASE_URL + URL_SUFFIX["CONTENT"], json=expected_response[0])
    expected_context_output = util_load_json(os.path.join("test_data", "content_create"
                                                                       "/content_create_object_not_present.json"))

    with open(os.path.join("test_data", "content_create/content_create_object_not_present.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "title": "XSOAR_Page",
        "type": "page",
        "space_key": "XSOAR"
    }
    response = confluence_cloud_content_create_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Content'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output[1]
    assert response.readable_output == expected_readable_output


def test_confluence_cloud_comment_create_command_when_valid_response_is_returned(requests_mock):
    """
    To test confluence_cloud_comment_create command when valid response return.
    Given:
        - command arguments for create comment command
    When:
        - Calling `confluence-cloud-comment-create` command
    Then:
        - Returns the response data
    """
    from AtlassianConfluenceCloud import confluence_cloud_comment_create_command

    expected_response = util_load_json(os.path.join("test_data", "comment_create/comment_create_command_response.json"))
    requests_mock.post(BASE_URL + URL_SUFFIX["CONTENT"], json=expected_response)
    expected_context_output = util_load_json(os.path.join("test_data", "comment_create"
                                                                       "/comment_create_command_context.json"))

    with open(os.path.join("test_data", "comment_create/comment_create_command.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "container_id": "2031630",
        "body_value": "hello",
        "body_representation": "storage"
    }
    response = confluence_cloud_comment_create_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Comment'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


@pytest.mark.parametrize("args, err_msg", input_data.comment_create_invalid_args)
def test_confluence_cloud_comment_create_command_when_invalid_args_provided(args, err_msg):
    """
    To test confluence_cloud_comment_create command when invalid args are provided.
    Given:
        - invalid command arguments for create comment command
    When:
        - Calling `confluence-cloud-comment-create` command
    Then:
        - Returns the response message of invalid input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_comment_create_command
    with pytest.raises(ValueError) as de:
        confluence_cloud_comment_create_command(client, args)
    assert str(de.value) == err_msg


def test_confluence_cloud_user_list_command_when_valid_response_is_returned(requests_mock):
    """
    To test confluence_cloud_user_list command when valid response return.
    Given:
        - command arguments for list user command
    When:
        - Calling `confluence-cloud-user-list` command
    Then:
        - Returns the response data
    """
    from AtlassianConfluenceCloud import confluence_cloud_user_list_command

    expected_response = util_load_json("test_data/User/user_list_command_response.json")
    requests_mock.get(BASE_URL + URL_SUFFIX["USER"], json=expected_response, status_code=200)
    expected_context_output = util_load_json("test_data/User/user_list_command_context.json")

    with open("test_data/User/user_list_command.md", 'r') as f:
        expected_readable_output = f.read()

    args = {
        "limit": "2",
        "start": "1"
    }
    response = confluence_cloud_user_list_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.User'
    assert response.outputs_key_field == "accountId"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


@pytest.mark.parametrize("args, err_msg", input_data.list_user_invalid_args)
def test_confluence_cloud_user_list_command_when_invalid_args_are_provided(args, err_msg):
    """
    To test confluence_cloud_user_list command when invalid arguments are provided.
    Given:
        - invalid command arguments for list user command
    When:
        - Calling `confluence-cloud-user-list` command
    Then:
        - Returns the response message of invalid input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_user_list_command

    with pytest.raises(ValueError) as de:
        confluence_cloud_user_list_command(client, args)
    assert str(de.value) == err_msg


def test_confluence_cloud_user_list_command_when_empty_response_is_returned(requests_mock):
    """
    Test case scenario for successful execution of confluence_cloud_user_list command with an empty response.
    Given:
        - command arguments for list user command
    When:
        - Calling `confluence-cloud-user-list` command
    Then:
        - Returns no records for the given input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_user_list_command

    requests_mock.get(BASE_URL + URL_SUFFIX["USER"], json={"results": []}, status_code=200)

    command_results = confluence_cloud_user_list_command(client, {"limit": "0"})

    assert command_results.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('user(s)')


def test_confluence_cloud_content_search_command_when_valid_response_is_returned(requests_mock):
    """
    To test confluence_cloud_content_search command when valid response return.
    Given:
        - command arguments for search content command
    When:
        - Calling `confluence-cloud-content-search` command
    Then:
        - Returns the response data
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_search_command, DEFAULT_EXPANDED_FIELD_CONTENT

    expected_response = util_load_json(os.path.join("test_data", "content_search/content_search_command_response.json"))
    requests_mock.get(BASE_URL + URL_SUFFIX["CONTENT_SEARCH"], json=expected_response)
    expected_context_output = util_load_json(os.path.join("test_data", "content_search/"
                                                                       "content_search_command_context.json"))

    with open(os.path.join("test_data", "content_search/content_search_command.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "query": "type=page",
        "expand": DEFAULT_EXPANDED_FIELD_CONTENT,
        "next_token": "1223344resfdczcxdvcdsv"
    }
    response = confluence_cloud_content_search_command(client, args)

    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


@pytest.mark.parametrize("args, err_msg", input_data.content_search_invalid_args)
def test_confluence_cloud_content_search_command_when_invalid_arguments_are_provided(args, err_msg):
    """
    To test confluence_cloud_content_search command when invalid arguments are provided.
    Given:
        - invalid command arguments for search content command
    When:
        - Calling `confluence-cloud-content-search` command
    Then:
        - Returns the response message of invalid input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_search_command

    with pytest.raises(ValueError) as de:
        confluence_cloud_content_search_command(client, args)
    assert str(de.value) == err_msg


@pytest.mark.parametrize("args, err_msg", input_data.content_search_invalid_arg_value)
def test_confluence_cloud_content_search_command_when_invalid_argument_value_are_provided(args, err_msg,
                                                                                          requests_mock, capfd):
    """
    To test confluence_cloud_content_search command when invalid argument value are provided.
    Given:
        - invalid command arguments for search content command
    When:
        - Calling `confluence-cloud-content-search` command
    Then:
        - Raise DemistoException
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_search_command

    expected_response = util_load_json(os.path.join("test_data", "content_search"
                                                                 "/content_search_invalid_query_argument.json"))
    requests_mock.get(BASE_URL + URL_SUFFIX["CONTENT_SEARCH"], status_code=400, json=expected_response)

    with capfd.disabled():
        with pytest.raises(DemistoException) as ve:
            confluence_cloud_content_search_command(client, args)
        assert str(ve.value) == err_msg


def test_confluence_cloud_content_search_command_when_empty_response_is_returned(requests_mock):
    """
    To test confluence_cloud_content_search command when empty response returned.
    Given:
        - command arguments for search content command
    When:
        - Calling `confluence-cloud-content-search` command
    Then:
        - Returns no records for the given input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_search_command

    requests_mock.get(BASE_URL + URL_SUFFIX["CONTENT_SEARCH"], json={"results": []}, status_code=200)

    args = {
        "query": "type=page",
        "limit": 0
    }
    response = confluence_cloud_content_search_command(client, args)

    assert response.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("content(s)")


def test_confluence_cloud_content_list_command_when_valid_response_is_returned(requests_mock):
    """
    To test confluence_cloud_content_list command when valid response return.
    Given:
        - command arguments for list content command
    When:
        - Calling `confluence-cloud-content-list` command
    Then:
        - Returns the response data
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_list_command, DEFAULT_EXPANDED_FIELD_CONTENT

    expected_response = util_load_json(os.path.join("test_data", "content_list/content_list_command_response.json"))
    requests_mock.get(BASE_URL + URL_SUFFIX["CONTENT"], json=expected_response)
    expected_context_output = util_load_json(os.path.join("test_data", "content_list/"
                                                                       "content_list_command_context.json"))

    with open(os.path.join("test_data", "content_list/content_list_command.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "limit": 2,
        "expand": DEFAULT_EXPANDED_FIELD_CONTENT,
        "space_key": "~680738455",
        "sort_order": "asc",
        "sort_key": "id",
        "status": "current",
        "creation_date": "6 Aug 2021"
    }
    response = confluence_cloud_content_list_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Content'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


def test_confluence_cloud_content_list_command_when_empty_response_is_returned(requests_mock):
    """
    To test confluence_cloud_content_list command when empty response returned.
    Given:
        - command arguments for list content command
    When:
        - Calling `confluence-cloud-content-list` command
    Then:
        - Returns no records for the given input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_list_command

    requests_mock.get(BASE_URL + URL_SUFFIX["CONTENT"], json={"results": []}, status_code=200)

    args = {
        "limit": "0"
    }
    response = confluence_cloud_content_list_command(client, args)

    assert response.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("content(s)")


@pytest.mark.parametrize("args, err_msg", input_data.content_list_invalid_arg_value)
def test_confluence_cloud_content_list_command_when_invalid_arguments_are_provided(args, err_msg):
    """
    To test confluence_cloud_content_list command when invalid arguments are provided.
    Given:
        - invalid command arguments for list content command
    When:
        - Calling `confluence-cloud-content-list` command
    Then:
        - Returns the response message of invalid input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_list_command

    with pytest.raises(ValueError) as de:
        confluence_cloud_content_list_command(client, args)
    assert str(de.value) == err_msg


def test_confluence_cloud_space_create_command_when_valid_response_is_returned(requests_mock):
    """
    To test confluence_cloud_space_create command when valid response return.
    Given:
        - command arguments for create space command
    When:
        - Calling `confluence-cloud-space-create` command
    Then:
        - Returns the response data
    """
    from AtlassianConfluenceCloud import confluence_cloud_space_create_command

    expected_response = util_load_json(os.path.join("test_data", "space_create/space_create_command_response.json"))
    requests_mock.post(BASE_URL + URL_SUFFIX["SPACE"], json=expected_response)
    expected_context_output = util_load_json(os.path.join("test_data", "space_create"
                                                                       "/space_create_command_context.json"))

    with open(os.path.join("test_data", "space_create/space_create_command.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "name": "XSOAR_Project",
        "unique_key": "XSOAR",
    }
    response = confluence_cloud_space_create_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Space'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


@pytest.mark.parametrize("args, err_msg", input_data.create_space_invalid_args)
def test_confluence_cloud_space_create_command_when_invalid_args_are_provided(args, err_msg):
    """
    To test confluence_cloud_space_create command when invalid arguments are provided.
    Given:
        - invalid command arguments for create space command
    When:
        - Calling `confluence-cloud-space-create` command
    Then:
        - Returns the response message of invalid input arguments
    """
    from AtlassianConfluenceCloud import validate_create_space_args

    with pytest.raises(ValueError) as de:
        validate_create_space_args(args)
    assert str(de.value) == err_msg


@pytest.mark.parametrize("args, err_msg", input_data.create_space_invalid_permission)
def test_confluence_cloud_space_create_command_when_invalid_permission_are_provided(args, err_msg):
    """
    To test confluence_cloud_space_create command when invalid permissions are provided.
    Given:
        - invalid permission arguments for create space command
    When:
        - Calling `confluence-cloud-space-create` command
    Then:
        - Returns the response message of invalid input arguments
    """
    from AtlassianConfluenceCloud import validate_permissions

    with pytest.raises(ValueError) as de:
        validate_permissions(args)
    assert str(de.value) == err_msg


def test_confluence_cloud_space_create_command_when_valid_permission_are_provided():
    """
    To test confluence_cloud_space_create command when valid permissions are provided.
    Given:
        - valid permission arguments for create space command
    When:
        - Calling `confluence-cloud-space-create` command
    Then:
        - Returns the response
    """
    from AtlassianConfluenceCloud import validate_permissions
    args = {"permission_account_id": "123",
            "permission_group_name": "abc",
            "permission_operations": "read:space"}
    expected_result = util_load_json(os.path.join("test_data", "space_create/space_create_valid_permission.json"))

    actual_result = validate_permissions(args)
    assert expected_result == actual_result


def test_confluence_cloud_space_list_command_when_valid_response_is_returned(requests_mock):
    """
    To test confluence_cloud_space_list command when valid response return.
    Given:
        - command arguments for list space command
    When:
        - Calling `confluence-cloud-space-list` command
    Then:
        - Returns the response data
     """
    from AtlassianConfluenceCloud import confluence_cloud_space_list_command

    expected_response = util_load_json(os.path.join("test_data", "space_list/space_list_command_response.json"))
    requests_mock.get(BASE_URL + URL_SUFFIX["SPACE"], json=expected_response)
    expected_context_output = util_load_json(os.path.join("test_data", "space_list/space_list_command_context.json"))

    with open(os.path.join("test_data", "space_list/space_list_command.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "limit": "2",
        "status": "current",
        "favourite": "false",
        "type": "global"
    }
    response = confluence_cloud_space_list_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Space'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


def test_confluence_cloud_space_list_command_when_empty_response_is_returned(requests_mock):
    """
    To test confluence_cloud_space_list command when empty response returned.
    Given:
        - command arguments for list space command
    When:
        - Calling `confluence-cloud-space-list` command
    Then:
        - Returns no records for the given input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_space_list_command

    requests_mock.get(BASE_URL + URL_SUFFIX["SPACE"], json={"results": []}, status_code=200)

    args = {
        "limit": "0"
    }
    response = confluence_cloud_space_list_command(client, args)

    assert response.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("space(s)")


@pytest.mark.parametrize("args, err_msg", input_data.list_space_invalid_args)
def test_confluence_cloud_space_list_command_when_invalid_args_are_provided(args, err_msg):
    """
    To test confluence_cloud_space_list command when invalid arguments are provided.
    Given:
        - invalid command arguments for list space command
    When:
        - Calling `confluence-cloud-space-list` command
    Then:
        - Returns the response message of invalid input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_space_list_command

    with pytest.raises(ValueError) as de:
        confluence_cloud_space_list_command(client, args)
    assert str(de.value) == err_msg


def test_confluence_cloud_content_update_command_when_valid_response_is_returned(requests_mock):
    """
    To test confluence_cloud_content_update command when valid response return.
    Given:
        - command arguments for update content command
    When:
        - Calling `confluence-cloud-content-update` command
    Then:
        - Returns the response data
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_update_command

    expected_response = util_load_json(os.path.join("test_data", "content_create/content_create_command_response.json"))
    requests_mock.put(BASE_URL + URL_SUFFIX["CONTENT"] + '/2097159', json=expected_response)
    expected_context_output = util_load_json(os.path.join("test_data", "content_create"
                                                                       "/content_create_command_context.json"))

    with open(os.path.join("test_data", "content_create/content_create_command.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "content_id": "2097159",
        "title": "XSOAR_Page",
        "type": "page",
        "version": 2
    }
    response = confluence_cloud_content_update_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Content'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


@pytest.mark.parametrize("args, err_msg", input_data.content_update_invalid_arg_value)
def test_confluence_cloud_content_update_command_when_invalid_args_are_provided(args, err_msg):
    """
    To test confluence_cloud_content_update command when invalid arguments are provided.
    Given:
        - invalid command arguments for update content command
    When:
        - Calling `confluence-cloud-content-update` command
    Then:
        - Returns the response message of invalid input arguments
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_update_command

    with pytest.raises(ValueError) as de:
        confluence_cloud_content_update_command(client, args)
    assert str(de.value) == err_msg


def test_confluence_cloud_content_update_command_when_object_not_present(requests_mock):
    """
    To test confluence_cloud_content_update command when object is not present in response.
    Given:
        - command arguments for update content command
    When:
        - Calling `confluence-cloud-content-update` command
    Then:
        - Returns the response data with some missing values
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_update_command

    expected_response = util_load_json(
        os.path.join("test_data", "content_create/content_create_object_not_present.json"))
    requests_mock.put(BASE_URL + URL_SUFFIX["CONTENT"] + '/2097159', json=expected_response[0])
    expected_context_output = util_load_json(os.path.join("test_data", "content_create"
                                                                       "/content_create_object_not_present.json"))

    with open(os.path.join("test_data", "content_create/content_create_object_not_present.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "content_id": "2097159",
        "title": "XSOAR_Page",
        "type": "page",
        "version": 2
    }
    response = confluence_cloud_content_update_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Content'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output[1]
    assert response.readable_output == expected_readable_output


def test_confluence_cloud_comment_create_command_when_object_not_present(requests_mock):
    """
    To test confluence_cloud_comment_create command when object not present.
    Given:
        - command arguments for create comment command
    When:
        - Calling `confluence-cloud-comment-create` command
    Then:
        - Returns the response data with some missing values
    """
    from AtlassianConfluenceCloud import confluence_cloud_comment_create_command

    expected_response = util_load_json(
        os.path.join("test_data", "comment_create/comment_create_object_not_present.json"))
    requests_mock.post(BASE_URL + URL_SUFFIX["CONTENT"], json=expected_response[0])
    expected_context_output = util_load_json(os.path.join("test_data", "comment_create"
                                                                       "/comment_create_object_not_present.json"))

    with open(os.path.join("test_data", "comment_create/comment_create_object_not_present.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "container_id": "2031630",
        "body_value": "hello",
        "body_representation": "storage"
    }
    response = confluence_cloud_comment_create_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Comment'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output[1]
    assert response.readable_output == expected_readable_output


def test_confluence_cloud_space_list_command_when_key_not_present(requests_mock):
    """
    To test confluence_cloud_space_list command when key not present.
    Given:
        - command arguments for list space command
    When:
        - Calling `confluence-cloud-space-list` command
    Then:
        - Returns the response data with some missing values
    """
    from AtlassianConfluenceCloud import confluence_cloud_space_list_command

    expected_response = util_load_json(
        os.path.join("test_data", "space_list/space_list_command_key_not_present_response.json"))
    requests_mock.get(BASE_URL + URL_SUFFIX["SPACE"], json=expected_response)
    expected_context_output = util_load_json(os.path.join("test_data", "space_list"
                                                                       "/space_list_command_key_not_present_context"
                                                                       ".json"))

    with open(os.path.join("test_data", "space_list/space_list_command_key_not_present.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "limit": "2",
        "status": "current",
        "favourite": "false",
        "type": "global"
    }
    response = confluence_cloud_space_list_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Space'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


def test_confluence_cloud_content_search_command_when_object_not_present(requests_mock):
    """
    To test confluence_cloud_content_search command when object is not present in response.
    Given:
        - command arguments for search content command
    When:
        - Calling `confluence-cloud-content-search` command
    Then:
        - Returns the response data with some missing values
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_search_command, DEFAULT_EXPANDED_FIELD_CONTENT

    expected_response = util_load_json(
        os.path.join("test_data", "content_search/content_search_object_not_present_response.json"))
    requests_mock.get(BASE_URL + URL_SUFFIX["CONTENT_SEARCH"], json=expected_response)
    expected_context_output = util_load_json(os.path.join("test_data", "content_search"
                                                                       "/content_search_object_not_present_context.json"))

    with open(os.path.join("test_data", "content_search/content_search_object_not_present.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "query": "type=page",
        "expand": DEFAULT_EXPANDED_FIELD_CONTENT,
        "next_token": "1223344resfdczcxdvcdsv"
    }
    response = confluence_cloud_content_search_command(client, args)

    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


def test_confluence_cloud_content_list_command_when_when_object_not_present(requests_mock):
    """
    To test confluence_cloud_content_list command when object is not present in response.
    Given:
        - command arguments for list content command
    When:
        - Calling `confluence-cloud-content-list` command
    Then:
        - Returns the response data with some missing values
    """
    from AtlassianConfluenceCloud import confluence_cloud_content_list_command, DEFAULT_EXPANDED_FIELD_CONTENT

    expected_response = util_load_json(os.path.join("test_data", "content_list"
                                                                 "/content_list_object_not_present_response.json"))
    requests_mock.get(BASE_URL + URL_SUFFIX["CONTENT"], json=expected_response)
    expected_context_output = util_load_json(os.path.join("test_data", "content_list/"
                                                                       "content_list_object_not_present_context.json"))

    with open(os.path.join("test_data", "content_list/content_list_object_not_present.md"), 'r') as f:
        expected_readable_output = f.read()

    args = {
        "limit": 2,
        "expand": DEFAULT_EXPANDED_FIELD_CONTENT,
        "space_key": "~680738455",
        "sort_order": "asc",
        "sort_key": "id",
        "status": "current",
        "date": "6 Aug 2021"
    }
    response = confluence_cloud_content_list_command(client, args)

    assert response.outputs_prefix == 'ConfluenceCloud.Content'
    assert response.outputs_key_field == "id"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output
