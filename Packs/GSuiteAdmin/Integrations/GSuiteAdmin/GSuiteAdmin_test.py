import json
from unittest.mock import patch

import pytest

import demistomock as demisto
from GSuiteAdmin import MESSAGES, GSuiteClient, OUTPUT_PREFIX, HR_MESSAGES

with open('test_data/service_account_json.txt') as f:
    TEST_JSON = f.read()
MOCKER_HTTP_METHOD = 'GSuiteApiModule.GSuiteClient.http_request'


@pytest.fixture
def gsuite_client():
    headers = {
        'Content-Type': 'application/json'
    }
    return GSuiteClient(GSuiteClient.safe_load_non_strict_json(TEST_JSON), verify=False, proxy=False, headers=headers)


def test_main(mocker):
    """
    Scenario: Main should initialize gsuite_client class and called command respectively.

    Given:
    - params and args.

    When:
    - Initializing gsuite_client with the parameters provided and calling respective command.

    Then:
    - Ensure results is returned from command function.
    """
    import GSuiteAdmin
    params = {
        'user_service_account_json': TEST_JSON,
        'admin_email': 'user@domain.io'

    }
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(GSuiteAdmin, 'test_module', return_value='ok')
    GSuiteAdmin.main()
    assert GSuiteAdmin.test_module.called


@patch('GSuiteAdmin.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
    Scenario: Main should handle error while initializing gsuite_client class and called command respectively.

    Given:
    - params and args.

    When:
    - Initializing gsuite_client with the parameters provided and calling respective command.

    Then:
    - Ensure exception is raised.
    """
    import GSuiteAdmin
    params = {
        'user_service_account_json': TEST_JSON,

    }
    mocker.patch.object(GSuiteAdmin.demisto, 'params', return_value=params)
    mocker.patch.object(GSuiteAdmin.demisto, 'command', return_value='test-module')
    mocker.patch.object(GSuiteAdmin, 'test_module', side_effect=Exception)
    with capfd.disabled():
        GSuiteAdmin.main()

    mock_return_error.assert_called_once_with('Error: ')


def test_test_function(mocker, gsuite_client):
    """
    Scenario: Call to test-module should return 'ok' if API call succeeds.

    Given:
    - gsuite_client object

    When:
    - Calling test function.

    Then:
    - Ensure 'ok' should be return.
    """
    from GSuiteAdmin import test_module, GSuiteClient
    mocker.patch.object(GSuiteClient, 'set_authorized_http')
    mocker.patch.object(GSuiteClient, 'http_request')
    assert test_module(gsuite_client) == 'ok'


@patch(MOCKER_HTTP_METHOD)
def test_gsuite_mobile_update_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: Mobile update command successful execution.

    Given:
    - Working API integration and correct parameters

    When:
    - Calling command method gsuite_mobile_update_command.

    Then:
    - Ensure expected human readable output is being set.

    :param gsuite_client: gsuite_client object fixture
    :param mocker_http_request: mocker object for gsuite_client.http_request
    :return: None
    """

    mocker_http_request.return_value = {}

    from GSuiteAdmin import mobile_update_command
    response = mobile_update_command(gsuite_client, {'resource_id': 'RESOURCE_ID'})
    assert response.readable_output == HR_MESSAGES['MOBILE_UPDATE_SUCCESS'].format('RESOURCE_ID')


@patch(MOCKER_HTTP_METHOD)
def test_gsuite_mobile_update_command_failure(mocker_http_request, gsuite_client):
    """
    Scenario: Mobile update command execution failure.

    Given:
    - Non-working API integration or incorrect parameters

    When:
    - Calling command method gsuite_mobile_update_command.

    Then:
    - Ensure expected error output is being set.

    :param gsuite_client: gsuite_client object fixture
    :param mocker_http_request: mocker object for gsuite_client.http_request
    :return: None
    """

    mocker_http_request.side_effect = Exception('UPDATE_ERROR')

    from GSuiteAdmin import mobile_update_command
    with pytest.raises(Exception, match='UPDATE_ERROR'):
        mobile_update_command(gsuite_client, {})


@patch(MOCKER_HTTP_METHOD)
def test_gsuite_mobile_delete_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: Mobile delete command successful execution.

    Given:
    - Working API integration and correct parameters

    When:
    - Calling command method gsuite_mobile_delete_command.

    Then:
    - Ensure expected human readable output is being set.

    :param gsuite_client: gsuite_client object fixture
    :param mocker_http_request: mocker object for gsuite_client.http_request
    :return: None
    """

    mocker_http_request.return_value = {}

    from GSuiteAdmin import mobile_delete_command
    response = mobile_delete_command(gsuite_client, {'resource_id': 'DELETE_RESOURCE'})
    assert response.readable_output == HR_MESSAGES['MOBILE_DELETE_SUCCESS'].format('DELETE_RESOURCE')


@patch(MOCKER_HTTP_METHOD)
def test_gsuite_mobile_delete_command_failure(mocker_http_request, gsuite_client):
    """
    Scenario: Mobile delete command execution failure.

    Given:
    - Non-working API integration or incorrect parameters

    When:
    - Calling command method gsuite_mobile_delete_command.

    Then:
    - Ensure expected error output is being set.

    :param gsuite_client: gsuite_client object fixture
    :param mocker_http_request: mocker object for gsuite_client.http_request
    :return: None
    """

    mocker_http_request.side_effect = Exception('DELETE_ERROR')

    from GSuiteAdmin import mobile_delete_command
    with pytest.raises(Exception, match='DELETE_ERROR'):
        mobile_delete_command(gsuite_client, {})


def test_user_create_command(gsuite_client, mocker):
    """
    Scenario: gsuite-user-create should works if valid arguments are provided.

    Given:
    - Command args.

    When:
    - Calling gsuite-user-create command with the arguments provided.

    Then:
    - Ensure CommandResult entry should be as expected.
    """
    from GSuiteAdmin import user_create_command
    with open('test_data/user_create_args.json', 'r') as file:
        args = json.load(file)
    with open('test_data/user_create_response.json') as file:
        api_response = json.load(file)
    with open('test_data/user_create_entry_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value=api_response)
    command_result = user_create_command(gsuite_client, args)
    assert command_result.readable_output == expected_entry_context['HumanReadable']
    assert command_result.outputs == expected_entry_context['EntryContext']['GSuite.User(val.id == obj.id)']
    assert command_result.raw_response == expected_entry_context['Contents']
    assert command_result.outputs_key_field == ['id']
    assert command_result.outputs_prefix == 'GSuite.User'


@patch('GSuiteAdmin.GSuiteClient.http_request')
def test_user_alias_add_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For gsuite-user-alias-add command successful run.

    Given:
    - Command args.

    When:
    - Calling gsuite-user-alias-add command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs, readable_output, outputs_key_field, outputs_prefix should be as expected.
    """
    from GSuiteAdmin import user_alias_add_command

    with open('test_data/user_alias_add.json', encoding='utf-8') as data:
        expected_res = json.load(data)
    mocker_http_request.return_value = expected_res['Contents']

    args = expected_res['args']
    result = user_alias_add_command(gsuite_client, args)

    assert result.raw_response == expected_res['Contents']
    assert result.outputs == expected_res['Outputs']
    assert result.readable_output == expected_res['HumanReadable']
    assert result.outputs_key_field == ['id', 'alias']
    assert result.outputs_prefix == OUTPUT_PREFIX['ADD_ALIAS']


@patch('GSuiteAdmin.GSuiteClient.http_request')
def test_user_alias_add_command_wrong_argument(mocker_http_request, gsuite_client):
    """
    Scenario: Wrong argument given gsuite-user-alias-add command.

    Given:
    - Command args.

    When:
    - Calling gsuite-user-alias-add command with the parameters provided.

    Then:
    - Ensure command should raise Exception as expected.
    """
    from GSuiteAdmin import user_alias_add_command
    message = "message"
    mocker_http_request.side_effect = Exception(message)
    args = {'user_key': 'demo2@test.com',
            'alias': 'test_alias@test.com',
            'admin_email': 'admin@test.com'}
    with pytest.raises(Exception, match=message):
        user_alias_add_command(gsuite_client, args)


@patch('GSuiteAdmin.GSuiteClient.http_request')
def test_group_create_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For gsuite-group-create command success.

    Given:
    - Command args.

    When:
    - Calling gsuite-group-create command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs, readable_output, outputs_key_field, outputs_prefix should be as expected.
    """
    from GSuiteAdmin import group_create_command

    with open('test_data/group_create_test_data.json', encoding='utf-8') as data:
        test_data = json.load(data)
    response = test_data.get('response_data', {})
    mocker_http_request.return_value = response

    result = group_create_command(gsuite_client, test_data.get('args', {}))

    assert result.raw_response == response
    assert result.outputs == response
    assert result.readable_output.startswith("### " + HR_MESSAGES['GROUP_CREATE_SUCCESS'].format(response['name']))
    assert result.outputs_key_field == 'id'
    assert result.outputs_prefix == OUTPUT_PREFIX['GROUP']


@patch('GSuiteAdmin.GSuiteClient.http_request')
def test_group_create_command_failure(mocker_http_request, gsuite_client):
    """
    Scenario: For gsuite-group-create command failure.

    Given:
    - Command args and a non-working gsuite api integration.

    When:
    - Calling gsuite-group-create command with the parameters provided.

    Then:
    - Ensure command's  error response is as expected.
    """
    mocker_http_request.side_effect = ValueError("SOME_ERROR")

    from GSuiteAdmin import group_create_command

    with pytest.raises(Exception, match="SOME_ERROR"):
        group_create_command(gsuite_client, {})


def test_prepare_args_for_role_assignment_list():
    """
    Scenario: Valid arguments given for gsuite-role-assignment-list command.

    Given:
    - Command args.

    When:
    - Calling prepare_args_for_role_assignment_list with command arguments.

    Then:
    - Ensure prepared arguments should be returned.
    """
    from GSuiteAdmin import prepare_args_for_role_assignment_list
    arguments = {
        'page_token': 'page token',
        'role_id': 'role id',
        'user_key': 'user key',
        'customer_id': 'my_customer',
        'admin_email': 'admin@domain.com',
        'max_results': '5'
    }
    expected_arguments = {
        'pageToken': 'page token',
        'roleId': 'role id',
        'userKey': 'user key',
        'maxResults': 5
    }
    assert prepare_args_for_role_assignment_list(arguments) == expected_arguments


@pytest.mark.parametrize('args', [{'max_results': 'abc', 'customer_id': 'c1', 'admin_email': 'e1'},
                                  {'max_results': '-1', 'customer_id': 'c2', 'admin_email': 'e2'}])
def test_prepare_args_for_role_assignment_list_invalid_max_results_argument(args):
    """
    Scenario: Invalid max_results argument given for gsuite-role-assignment-list command.

    Given:
    - Command args.

    When:
    - Calling prepare_args_for_role_assignment_list with command arguments.

    Then:
    - Ensure ValueError will be raised with respective message.
    """
    from GSuiteAdmin import prepare_args_for_role_assignment_list
    with pytest.raises(ValueError, match=MESSAGES['INTEGER_ERROR'].format('max_results')):
        prepare_args_for_role_assignment_list(args)


def test_role_assignment_list(gsuite_client, mocker):
    """
    Scenario: gsuite-role-assignment-list command is called with valid arguments.

    Given:
    - Command args.

    When:
    - Calling role_assignment_list with command arguments.

    Then:
    - Ensure CommandResult should return data as expected.
    """
    from GSuiteAdmin import role_assignment_list_command

    arguments = {
        'customer_id': 'cfdge',
        'max_results': '1'
    }
    with open('test_data/role_assignment_list_response.json') as file:
        api_response = json.load(file)
    with open('test_data/role_assignment_list_entry_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch(MOCKER_HTTP_METHOD, side_effect=[api_response, {}])

    command_result = role_assignment_list_command(gsuite_client, arguments)
    assert command_result.readable_output == expected_entry_context['HumanReadable']
    assert command_result.outputs == expected_entry_context['EntryContext']
    assert command_result.raw_response == expected_entry_context['Contents']
    assert role_assignment_list_command(gsuite_client, {}).readable_output == HR_MESSAGES['NO_RECORDS'].format(
        'role assignment details')


def test_role_assignment_create(gsuite_client, mocker):
    """
    Scenario: gsuite-role-assignment-create command is called with valid arguments.

    Given:
    - Command args.

    When:
    - Calling role_assignment_list with command arguments.

    Then:
    - Ensure CommandResult should return data as expected.
    """
    from GSuiteAdmin import role_assignment_create_command

    arguments = {
        'customer_id': 'customer id',
        'scope_type': 'CUSTOMER',
        'role_id': 'role1',
        'assigned_to': '1234'
    }
    with open('test_data/role_assignment_create_response.json') as file:
        api_response = json.load(file)
    with open('test_data/role_assignment_create_entry_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch(MOCKER_HTTP_METHOD, return_value=api_response)
    command_result = role_assignment_create_command(gsuite_client, arguments)
    assert command_result.readable_output == expected_entry_context['HumanReadable']
    assert command_result.outputs == expected_entry_context['EntryContext'][
        'GSuite.RoleAssignment(val.roleAssignmentId == obj.roleAssignmentId)']
    assert command_result.raw_response == expected_entry_context['Contents']
    assert command_result.outputs_key_field == 'roleAssignmentId'
    assert command_result.outputs_prefix == 'GSuite.RoleAssignment'


@patch('GSuiteAdmin.GSuiteClient.http_request')
def test_role_create_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For gsuite-role-create command success.

    Given:
    - Command args.

    When:
    - Calling gsuite-role-create command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs, readable_output, outputs_key_field, outputs_prefix should be as expected.
    """
    from GSuiteAdmin import role_create_command

    with open('test_data/role_create_test_data.json', encoding='utf-8') as data:
        test_data = json.load(data)
    response_data = test_data['response']
    mocker_http_request.return_value = response_data

    result = role_create_command(gsuite_client, test_data['args'])

    assert result.raw_response == response_data
    assert result.outputs == response_data
    assert result.readable_output.startswith(
        "### " + HR_MESSAGES['ROLE_CREATE_SUCCESS'])
    assert result.outputs_key_field == 'roleId'
    assert result.outputs_prefix == OUTPUT_PREFIX['ROLE']


@patch('GSuiteAdmin.GSuiteClient.http_request')
def test_role_create_command_failure(mocker_http_request, gsuite_client):
    """
    Scenario: For gsuite-role-create command failure.

    Given:
    - Command args and a non-working gsuite api integration.

    When:
    - Calling gsuite-role-create command with the parameters provided.

    Then:
    - Ensure command's  error response is as expected.
    """
    mocker_http_request.side_effect = ValueError("SOME_ERROR")

    from GSuiteAdmin import role_create_command

    with pytest.raises(Exception, match="SOME_ERROR"):
        role_create_command(gsuite_client, {'role_privileges': 'test:test'})


@patch(MOCKER_HTTP_METHOD)
def test_gsuite_token_revoke_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: Token revoke command successful execution.

    Given:
    - Working API integration and correct parameters

    When:
    - Calling command method gsuite_token_revoke_command.

    Then:
    - Ensure expected human readable output is being set.
    """

    mocker_http_request.return_value = {}

    from GSuiteAdmin import token_revoke_command
    response = token_revoke_command(gsuite_client, {'client_id': 'CLIENT_ID'})
    assert response.readable_output == HR_MESSAGES['TOKEN_REVOKE_SUCCESS'].format('CLIENT_ID')


@patch(MOCKER_HTTP_METHOD)
def test_gsuite_token_revoke_command_failure(mocker_http_request, gsuite_client):
    """
    Scenario: Token revoke command failure.

    Given:
    - Non-working API integration or incorrect parameters

    When:
    - Calling command method gsuite_token_revoke_command.

    Then:
    - Ensure expected error output is being set.
    """

    mocker_http_request.side_effect = ValueError('SOME_ERROR')

    from GSuiteAdmin import token_revoke_command
    with pytest.raises(Exception, match='SOME_ERROR'):
        token_revoke_command(gsuite_client, {})


def test_datatransfer_list(gsuite_client, mocker):
    """
    Scenario: gsuite-datatransfer-list command is called with valid arguments.

    Given:
    - Command args.

    When:
    - Calling datatransfer_list with command arguments.

    Then:
    - Ensure CommandResult should return data as expected.
    """
    from GSuiteAdmin import datatransfer_list_command

    with open('test_data/datatransfer_list_response.json') as file:
        api_response = json.load(file)
    with open('test_data/datatransfer_list_entry_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch(MOCKER_HTTP_METHOD, side_effect=[api_response, {}])

    command_result = datatransfer_list_command(gsuite_client, {})
    assert command_result.readable_output == expected_entry_context['HumanReadable']
    assert command_result.outputs == expected_entry_context['EntryContext']
    assert command_result.raw_response == expected_entry_context['Contents']
    assert datatransfer_list_command(gsuite_client, {}).readable_output == HR_MESSAGES['NO_RECORDS'].format(
        'data transfer details')


def test_custom_user_schema_create(gsuite_client, mocker):
    """
    Scenario: gsuite-custom-user-schema-create command is called with valid arguments.

    Given:
    - Command args.

    When:
    - Calling custom_user_schema_create with command arguments.

    Then:
    - Ensure CommandResult should return data as expected.
    """
    from GSuiteAdmin import custom_user_schema_create_command

    arguments = {
        'customer_id': 'customer_id',
        'schema_name': 'new121',
        'schema_display_name': 'n2',
        'field_raw_json': '{"fields": []}'
    }
    with open('test_data/custom_user_schema_response.json') as file:
        api_response = json.load(file)
    with open('test_data/custom_user_schema_create_entry_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch(MOCKER_HTTP_METHOD, return_value=api_response)
    command_result = custom_user_schema_create_command(gsuite_client, arguments)
    assert command_result.readable_output == expected_entry_context['HumanReadable']
    assert command_result.outputs == expected_entry_context['EntryContext'][
        'GSuite.UserSchema(val.schemaId == obj.schemaId)']
    assert command_result.raw_response == expected_entry_context['Contents']
    assert command_result.outputs_key_field == 'schemaId'
    assert command_result.outputs_prefix == 'GSuite.UserSchema'


def test_prepare_args_for_custom_user_schema_create_required_argument_error():
    """
    Scenario: Required argument(s) are not provided.

    Given:
    - Command args.

    When:
    - Calling prepare_args_for_custom_user_schema_create with command arguments.

    Then:
    - Ensure ValueError should be raised with respective message.
    """
    from GSuiteAdmin import prepare_args_for_custom_user_schema
    with pytest.raises(ValueError, match=MESSAGES['REQUIRED_ARGS_CUSTOM_SCHEMA']):
        prepare_args_for_custom_user_schema({})


def test_custom_user_schema_update(gsuite_client, mocker):
    """
    Scenario: gsuite-custom-user-schema-update command is called with valid arguments.

    Given:
    - Command args.

    When:
    - Calling custom_user_schema_update with command arguments.

    Then:
    - Ensure CommandResult should return data as expected.
    """
    from GSuiteAdmin import custom_user_schema_update_command

    arguments = {
        'customer_id': 'customer_id',
        'schema_name': 'new1',
        'schema_display_name': 'n1',
        'field_raw_json': '{"fields": []}'
    }
    with open('test_data/custom_user_schema_response.json') as file:
        api_response = json.load(file)
    with open('test_data/custom_user_schema_update_entry_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch(MOCKER_HTTP_METHOD, return_value=api_response)
    command_result = custom_user_schema_update_command(gsuite_client, arguments)

    assert command_result.readable_output == expected_entry_context['HumanReadable']
    assert command_result.outputs == expected_entry_context['EntryContext'][
        'GSuite.UserSchema(val.schemaId == obj.schemaId)']
    assert command_result.raw_response == expected_entry_context['Contents']
    assert command_result.outputs_key_field == 'schemaId'
    assert command_result.outputs_prefix == 'GSuite.UserSchema'


def test_custom_user_schema_update_required_args_error(gsuite_client):
    """
    Scenario: gsuite-custom-user-schema-update command is called with no required arguments.

    Given:
    - Command args.

    When:
    - Calling custom_user_schema_update with command arguments.

    Then:
    - Ensure CommandResult should return data as expected.
    """
    from GSuiteAdmin import custom_user_schema_update_command

    with pytest.raises(ValueError, match=MESSAGES['CUSTOM_SCHEMA_UPDATE_REQUIRED_ARGS']):
        custom_user_schema_update_command(gsuite_client, {})

    with pytest.raises(ValueError, match=MESSAGES['REQUIRED_ARGS_CUSTOM_SCHEMA']):
        custom_user_schema_update_command(gsuite_client, {'schema_name': 'new_schema'})


@patch(MOCKER_HTTP_METHOD)
def test_datatransfer_request_create_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For datatransfer_request_create command success.

    Given:
    - Command args.

    When:
    - Calling datatransfer_request_create command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs, readable_output, outputs_prefix should be as expected.
    """
    from GSuiteAdmin import datatransfer_request_create_command

    with open('test_data/data_transfer_request_create_test_data.json') as data:
        test_data = json.load(data)
    response_data = test_data['output']
    mocker_http_request.return_value = response_data

    result = datatransfer_request_create_command(gsuite_client, test_data['args'])

    assert result.raw_response == response_data
    assert result.outputs == response_data
    assert result.readable_output.startswith(
        "### " + HR_MESSAGES['DATATRANSFER_REQUEST_CREATE_SUCCESS'])
    assert result.outputs_prefix == OUTPUT_PREFIX['DATA_TRANSFER_REQUEST_CREATE']


def test_get_transfer_params_list_from_str_invalid_param_format():
    """
    Scenario: get_transfer_params_list_from_str invalid params provided.

    Given:
    - incorrect command arguments

    When:
    - Calling command method get_transfer_params_list_from_str.

    Then:
    - Ensure expected error output is being set.
    """
    from GSuiteAdmin import get_transfer_params_list_from_str
    with pytest.raises(ValueError, match=MESSAGES['DATATRANSFER_TRANSFER_PARAM_FORMAT_ERROR']):
        get_transfer_params_list_from_str('abc')


def test_datatransfer_request_create_command_validation_failure(gsuite_client):
    """
    Scenario: datatransfer_request_create command validation logic failure.

    Given:
    - incorrect command arguments

    When:
    - Calling command method datatransfer_request_create_command.

    Then:
    - Ensure expected error output is being set.
    """

    from GSuiteAdmin import datatransfer_request_create_command
    with pytest.raises(Exception, match=MESSAGES['DATATRANSFER_MISSING_ARGUMENT'].format('\'old_owner_id\'')):
        datatransfer_request_create_command(gsuite_client, {})


def test_prepare_datatransfer_payload_from_arguments():
    """
    Scenario: For prepare_datatransfer_payload_from_arguments testing.

    Given:
    - datatransfer_request_create command arguments.

    When:
    - Calling prepare_datatransfer_payload_from_arguments method

    Then:
    - Ensure method returns valid request_payload
    """
    with open('test_data/data_transfer_request_create_test_data.json', encoding='utf-8') as data:
        test_data = json.load(data)

    args = test_data['args']
    output = test_data['request_payload']

    from GSuiteAdmin import prepare_datatransfer_payload_from_arguments
    assert prepare_datatransfer_payload_from_arguments(args) == output


@patch(MOCKER_HTTP_METHOD)
def test_user_delete_command(gsuite_client):
    """
    Scenario: user delete command successful execution.

    Given:
    - Working API integration and correct parameters

    When:
    - Calling command method user_delete_command.

    Then:
    - Ensure expected human readable output is being set.
    """
    from GSuiteAdmin import user_delete_command
    response = user_delete_command(gsuite_client, {'user_key': 'user1'})
    assert response.readable_output == HR_MESSAGES['USER_DELETE'].format('user1')


def test_user_update_command(gsuite_client, mocker):
    """
    Scenario: gsuite-user-update should works if valid arguments are provided.

    Given:
    - Command args.

    When:
    - Calling gsuite-user-update command with the arguments provided.

    Then:
    - Ensure CommandResult entry should be as expected.
    """
    from GSuiteAdmin import user_update_command
    with open('test_data/user_create_args.json', 'r') as file:
        args = json.load(file)
    args['archived'] = 'true'
    args['org_unit_path'] = '\\'
    with open('test_data/user_update_response.json') as file:
        api_response = json.load(file)
    with open('test_data/user_update_entry_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value=api_response)
    command_result = user_update_command(gsuite_client, args)
    assert command_result.readable_output == expected_entry_context['HumanReadable']
    assert command_result.outputs == expected_entry_context['EntryContext']['GSuite.User(val.id == obj.id)']
    assert command_result.raw_response == expected_entry_context['Contents']
    assert command_result.outputs_key_field == ['id']
    assert command_result.outputs_prefix == 'GSuite.User'
