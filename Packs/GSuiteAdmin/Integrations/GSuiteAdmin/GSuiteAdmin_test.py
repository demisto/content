import json
from unittest.mock import patch

import pytest
from CommonServerPython import DemistoException
import demistomock as demisto
from GSuiteAdmin import MESSAGES, GSuiteClient, OUTPUT_PREFIX, HR_MESSAGES, Client

with open('test_data/service_account_json.txt') as f:
    TEST_JSON = f.read()
MOCKER_HTTP_METHOD = 'GSuiteApiModule.GSuiteClient.http_request'


@pytest.fixture
def gsuite_client():
    headers = {
        'Content-Type': 'application/json'
    }
    return Client(GSuiteClient.safe_load_non_strict_json(TEST_JSON), verify=False, proxy=False, headers=headers)


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
    response = mobile_update_command(gsuite_client, {'resource_id': 'RESOURCE_ID', 'customer_id': '1234'})
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
        mobile_update_command(gsuite_client, {'customer_id': '1234'})


MOBILE_ACTION_ERROR_CASES = [
    ('Internal error encountered', MESSAGES.get('INVALID_RESOURCE_CUSTOMER_ID_ERROR', '')),
    ('Bad Request', MESSAGES.get('INVALID_RESOURCE_CUSTOMER_ID_ERROR', '')),
    ('Some other error', 'Some other error'),
]


@pytest.mark.parametrize('error_message, parsed_error_message', MOBILE_ACTION_ERROR_CASES)
def test_invalid_gsuite_mobile_update_command_command(mocker, gsuite_client, error_message, parsed_error_message):
    """
    Given:
        - A client, a resource id, and an action to execute on the mobile device.
    When:
        - Running the gsuite_mobile_update_command command, and receiving an error from the API.
    Then:
        - Validate that the ambiguous error message is mapped to a more human readable error message.
    """
    from GSuiteAdmin import mobile_update_command
    from CommonServerPython import DemistoException
    mocker.patch(MOCKER_HTTP_METHOD,
                 side_effect=DemistoException(message=error_message))
    with pytest.raises(DemistoException) as e:
        mobile_update_command(client=gsuite_client,
                              args={'customer_id': 'customer_id', 'resource_id': 'wrong_resource_id',
                                    'action': 'some_action'})
    assert parsed_error_message in str(e)


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
    response = mobile_delete_command(gsuite_client, {'resource_id': 'DELETE_RESOURCE', 'customer_id': '1234'})
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
        mobile_delete_command(gsuite_client, {'customer_id': '1234'})


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
    with open('test_data/user_create_args.json') as file:
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


def test_user_get_command(gsuite_client, mocker):
    """
    Scenario: gsuite-user-get should works if valid arguments are provided.

    Given:
    - Command args.

    When:
    - Calling gsuite-user-create command with the arguments provided.

    Then:
    - Ensure CommandResult entry should be as expected.
    """
    from GSuiteAdmin import user_get_command
    args = {'user': 'testuser'}
    with open('test_data/user_create_response.json') as file:
        api_response = json.load(file)
    with open('test_data/user_get_entry_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value=api_response)
    command_result = user_get_command(gsuite_client, args)
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


@patch('GSuiteAdmin.GSuiteClient.http_request')
def test_group_get_command(mocker_http_request, gsuite_client):
    """
    Scenario: For gsuite-group-get command

    Given:
    - Command args.

    When:
    - Calling gsuite-group-get command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs, readable_output, outputs_key_field, outputs_prefix should be as expected.
    """
    from GSuiteAdmin import group_get_command

    with open('test_data/group_get_test_data.json', encoding='utf-8') as data:
        test_data = json.load(data)
    response = test_data.get('response_data', {})
    mocker_http_request.return_value = response

    result = group_get_command(gsuite_client, test_data.get('args', {}))

    assert result.raw_response == response
    assert result.outputs == response
    assert result.readable_output.startswith("### " + HR_MESSAGES['GROUP_GET_SUCCESS'].format(response['name']))
    assert result.outputs_key_field == 'id'
    assert result.outputs_prefix == OUTPUT_PREFIX['GROUP']


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
        'max_results': '1',
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
    assert role_assignment_list_command(gsuite_client, {'customer_id': '1234'}).readable_output == \
        HR_MESSAGES['NO_RECORDS'].format('role assignment details')


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
        role_create_command(gsuite_client, {'role_privileges': 'test:test', 'customer_id': '1234'})


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
def test_gsuite_user_signout_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: User signout  command successful execution.

    Given:
    - Working API integration and correct parameters

    When:
    - Calling command method gsuite_token_revoke_command.

    Then:
    - Ensure expected human readable output is being set.
    """

    mocker_http_request.return_value = {}

    from GSuiteAdmin import user_signout_command
    response = user_signout_command(gsuite_client, {'user_key': 'USER_KEY'})
    assert response.readable_output == HR_MESSAGES['USER_SIGNOUT_SESSIONS'].format('USER_KEY')


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

    command_result = datatransfer_list_command(gsuite_client, {'customer_id': '1234'})
    assert command_result.readable_output == expected_entry_context['HumanReadable']
    assert command_result.outputs == expected_entry_context['EntryContext']
    assert command_result.raw_response == expected_entry_context['Contents']
    assert datatransfer_list_command(gsuite_client, {'customer_id': '1234'}).readable_output == HR_MESSAGES['NO_RECORDS'].format(
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
        custom_user_schema_update_command(gsuite_client, {'customer_id': '1234'})

    with pytest.raises(ValueError, match=MESSAGES['REQUIRED_ARGS_CUSTOM_SCHEMA']):
        custom_user_schema_update_command(gsuite_client, {'schema_name': 'new_schema', 'customer_id': '1234'})


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
    with open('test_data/user_create_args.json') as file:
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

# New Unit Tests


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


class MockResponse:
    """ This class will be used to mock a request response (only the json function in the requests.Response class) """

    def __init__(self, json_data):
        self.json_data = json_data

    def json(self):
        return self.json_data


CHROMEOS_ACTION_ERROR_CASES = [
    ('Delinquent account', MESSAGES.get('INVALID_RESOURCE_CUSTOMER_ID_ERROR', '')),
    ('Some other error', 'Some other error'),
]


@pytest.mark.parametrize('error_message, parsed_error_message', CHROMEOS_ACTION_ERROR_CASES)
def test_invalid_chromeos_action_command(mocker, gsuite_client, error_message, parsed_error_message):
    """
    Given:
        - A client, a resource id, and an action to execute on the chromeOS device.
    When:
        - Running the google_chromeos_device_action_command command, and receiving an error from the API.
    Then:
        - Validate that the ambiguous error message is mapped to a more human readable error message.
    """
    from GSuiteAdmin import gsuite_chromeos_device_action_command
    from CommonServerPython import DemistoException
    mocker.patch(MOCKER_HTTP_METHOD,
                 side_effect=DemistoException(message=error_message))
    with pytest.raises(DemistoException) as e:
        gsuite_chromeos_device_action_command(client=gsuite_client,
                                              args={'customer_id': 'customer_id', 'resource_id': 'wrong_resource_id',
                                                    'action': 'some_action'})
    assert parsed_error_message in str(e)


TEST_DATA_INVALID_PAGINATION_ARGUMENTS = [
    ({'page_size': '3', 'page_token': 'some_token', 'limit': '25'}, ('please supply either the argument limit,'
                                                                     ' or the argument page_token, or the arguments'
                                                                     ' page_token and page_size together')),
    ({'limit': '0'}, 'The limit argument can\'t be negative or equal to zero'),
    ({'limit': '-78'}, 'The limit argument can\'t be negative or equal to zero'),
    ({'page_token': 'some_token', 'page_size': '101'}, 'The maximum page size is')
]


@pytest.mark.parametrize('args, error_message', TEST_DATA_INVALID_PAGINATION_ARGUMENTS)
def test_invalid_pagination_arguments(args, error_message):
    """
    Given:
        - The pagination arguments supplied by the user.
    When:
        - Running the function prepare_pagination_arguments to check the content of the pagination arguments.
    Then:
        - Validate that an exception is thrown in response to invalid pagination arguments.
    """
    from GSuiteAdmin import prepare_pagination_arguments
    from CommonServerPython import DemistoException, arg_to_number
    with pytest.raises(DemistoException) as e:
        prepare_pagination_arguments(page_size=arg_to_number(args.get('page_size', '')),
                                     page_token=args.get('page_toke', ''),
                                     limit=arg_to_number(args.get('limit', '')))
    assert error_message in str(e)


def test_chromeos_device_action(mocker, gsuite_client):
    """
    Given:
        - A client, a resource id (that identifies a mobile device), and an action that affects the chromeos device
    When:
        - The command google-chromeosdevice-action is run with a correct action argument
    Then:
        - A CommandResults is returned that marks the command as successful
    """
    from GSuiteAdmin import gsuite_chromeos_device_action_command
    from CommonServerPython import CommandResults
    expected_command_result = CommandResults(
        readable_output=HR_MESSAGES.get('CHROMEOS_DEVICE_ACTION_SUCCESS', '').format('resource_id'),
    )
    mocker.patch(MOCKER_HTTP_METHOD, return_value={})
    command_result = gsuite_chromeos_device_action_command(client=gsuite_client,
                                                           args={'customer_id': 'customer_id', 'resource_id': 'resource_id',
                                                                 'action': 'correct_action'})
    assert command_result.to_context() == expected_command_result.to_context()


TEST_DATA_AUTO_PAGINATION_FILES_CASES = [
    ('test_data/mobile_devices_list/automatic_pagination/raw_results_3_pages.json',
     'test_data/mobile_devices_list/automatic_pagination/parsed_results_3_pages.json', {'limit': 7}),
    ('test_data/mobile_devices_list/automatic_pagination/raw_results_2_pages.json',
     'test_data/mobile_devices_list/automatic_pagination/parsed_results_2_pages.json', {'limit': 6})
]


@pytest.mark.parametrize('raw_results_file, parsed_results_file, pagination_args', TEST_DATA_AUTO_PAGINATION_FILES_CASES)
def test_mobile_device_list_automatic_pagination_result_instance(mocker, gsuite_client, raw_results_file, parsed_results_file,
                                                                 pagination_args):
    # Since there is not enough mobile devices to actually do pagination, all the requests being mocked
    # are under the impression that the maximum page is of size 3, this will give us the ability to mock the pagination process
    """
    Given:
        - Raw responses representing mobile devices and a limit argument.
    When:
        - Running the command device_list_automatic_pagination to parse the raw results and return an instance of
         PaginationResult that hold the relevant data using automatic pagination.
    Then:
        - Validate the content of the PaginationResult instance.
    """
    from GSuiteAdmin import MobileDevicesConfig, device_list_automatic_pagination, mobile_device_list_request
    query_params = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', **pagination_args}
    raw_responses = util_load_json(raw_results_file)
    expected_pagination_result_instance = create_pagination_result_automatic_instance(
        raw_responses=raw_responses,
        response_devices_list_key=MobileDevicesConfig.response_devices_list_key)
    mocker.patch(MOCKER_HTTP_METHOD, side_effect=raw_responses)
    pagination_result = device_list_automatic_pagination(request_by_device_type=mobile_device_list_request,
                                                         client=gsuite_client,
                                                         customer_id='customer_id',
                                                         query_params=query_params,
                                                         response_devices_list_key=MobileDevicesConfig.response_devices_list_key,
                                                         **pagination_args)
    assert pagination_result == expected_pagination_result_instance


@pytest.mark.parametrize('raw_results_file, parsed_results_file, pagination_args', TEST_DATA_AUTO_PAGINATION_FILES_CASES)
def test_mobile_device_list_automatic_pagination(mocker, gsuite_client, raw_results_file, parsed_results_file, pagination_args):
    # Since there is not enough mobile devices to actually do pagination, all the requests being mocked
    # are under the impression that the maximum page is of size 3, this will give us the ability to mock the pagination process
    """
    Given:
        - A client and query parameters for the API.
    When:
        - Running the command google_mobile_device_list_command to retrieve the mobile devices' list using automatic pagination.
    Then:
        - Validate the content of the context data and human readable.
    """
    from GSuiteAdmin import gsuite_mobile_device_list_command
    args = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', **pagination_args, 'customer_id': 'customer_id'}
    raw_responses = util_load_json(raw_results_file)
    expected_command_results = util_load_json(parsed_results_file)
    mocker.patch(MOCKER_HTTP_METHOD, side_effect=raw_responses)
    command_results = gsuite_mobile_device_list_command(client=gsuite_client, args=args)
    to_context = command_results.to_context()
    assert to_context.get('HumanReadable') == expected_command_results.get('HumanReadable')
    assert to_context.get('EntryContext') == expected_command_results.get('EntryContext')


TEST_DATA_MANUAL_PAGINATION_FILES_CASES = [
    ('test_data/mobile_devices_list/manual_pagination/raw_results_with_next_page_token.json',
     'test_data/mobile_devices_list/manual_pagination/parsed_results_with_next_page_token.json',
     {'page_token': 'dummy_next_page_token', 'page_size': 2}),
]


@pytest.mark.parametrize('raw_results_file, parsed_results_file, pagination_args', TEST_DATA_MANUAL_PAGINATION_FILES_CASES)
def test_mobile_device_list_manual_pagination_result_instance(mocker, gsuite_client, raw_results_file, parsed_results_file,
                                                              pagination_args):
    # Since there is not enough mobile devices to actually do pagination, all the requests being mocked
    # are under the impression that the maximum page is of size 3, this will give us the ability to mock the pagination process
    """
    Given:
        - Raw responses representing mobile devices, and page_token and page_size arguments.
    When:
        - Running the command device_list_automatic_pagination to parse the raw results and return an instance of
         PaginationResult that hold the relevant data using manual pagination.
    Then:
        - Validate the content of the PaginationResult instance.
    """
    from GSuiteAdmin import MobileDevicesConfig, device_list_manual_pagination, mobile_device_list_request
    query_params = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', **pagination_args}
    raw_responses = util_load_json(raw_results_file)
    expected_pagination_result_instance = create_pagination_result_manual_instance(
        raw_responses=raw_responses,
        response_devices_list_key=MobileDevicesConfig.response_devices_list_key)
    mocker.patch(MOCKER_HTTP_METHOD, side_effect=raw_responses)
    pagination_result = device_list_manual_pagination(request_by_device_type=mobile_device_list_request,
                                                      client=gsuite_client,
                                                      customer_id='customer_id',
                                                      query_params=query_params,
                                                      response_devices_list_key=MobileDevicesConfig.response_devices_list_key,
                                                      **pagination_args)
    assert pagination_result == expected_pagination_result_instance


@pytest.mark.parametrize('raw_results_file, parsed_results_file, pagination_args', TEST_DATA_MANUAL_PAGINATION_FILES_CASES)
def test_mobile_device_list_manual_pagination(mocker, gsuite_client, raw_results_file, parsed_results_file, pagination_args):
    # Since there is not enough mobile devices to actually do pagination, all the requests being mocked
    # are under the impression that the maximum page is of size 3, this will give us the ability to mock the pagination process
    """
    Given:
        - A client and query parameters for the API.
    When:
        - Running the command google_mobile_device_list_command to retrieve the mobile devices' list using manual pagination.
    Then:
        - Validate the content of the context data and human readable.
    """
    from GSuiteAdmin import gsuite_mobile_device_list_command
    args = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', **pagination_args, 'customer_id': 'customer_id'}
    raw_responses = util_load_json(raw_results_file)
    expected_command_results = util_load_json(parsed_results_file)
    mocker.patch(MOCKER_HTTP_METHOD, side_effect=raw_responses)
    command_results = gsuite_mobile_device_list_command(client=gsuite_client, args=args)
    to_context = command_results.to_context()
    assert to_context.get('HumanReadable') == expected_command_results.get('HumanReadable')
    assert to_context.get('EntryContext') == expected_command_results.get('EntryContext')


TEST_PAGINATION_ARGS_CASES = [
    ({'limit': '2'}),
    ({'page_size': '3'})
]


@pytest.mark.parametrize('pagination_args', TEST_PAGINATION_ARGS_CASES)
def test_mobile_device_list_empty_response(mocker, gsuite_client, pagination_args):
    """
    Given:
        - A client and query parameters for the API.
    When:
        - Running the command google_mobile_device_list_command to retrieve the mobile devices' and receiving no results.
    Then:
        - Validate the content of the context data and human readable.
    """
    from GSuiteAdmin import gsuite_mobile_device_list_command
    args = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', **pagination_args, 'customer_id': 'customer_id'}
    raw_responses = util_load_json('test_data/mobile_devices_list/no_results_found.json')
    expected_command_results = util_load_json('test_data/mobile_devices_list/parsed_no_results_found.json')
    mocker.patch(MOCKER_HTTP_METHOD, side_effect=raw_responses)
    command_results = gsuite_mobile_device_list_command(client=gsuite_client, args=args)
    to_context = command_results.to_context()
    assert to_context.get('HumanReadable') == expected_command_results.get('HumanReadable')
    assert to_context.get('EntryContext') == expected_command_results.get('EntryContext')


def create_pagination_result_automatic_instance(raw_responses: list[dict], response_devices_list_key: str) -> dict:
    """
        This will create a PaginationResult instance that reflect automatic pagination in order to check the return values of
        functions that return PaginationResult.
    """
    mocked_data = []
    for raw_response in raw_responses:
        mocked_data.extend(raw_response.get(response_devices_list_key, []))
    return {'data': mocked_data, 'raw_response': raw_responses}


def create_pagination_result_manual_instance(raw_responses: list[dict], response_devices_list_key: str) -> dict:
    """
        This will create a PaginationResult instance that reflect manual pagination in order to check the return values of
        functions that return PaginationResult.
    """
    assert len(raw_responses) <= 1, 'The length of the mocked raw responses of a manual pagination should be at most 1.'
    mocked_data = []
    mocked_next_page_token = ''
    for raw_response in raw_responses:
        mocked_data.extend(raw_response.get(response_devices_list_key, []))
        mocked_next_page_token = raw_response.get('nextPageToken', '')
    return {'data': mocked_data, 'raw_response': raw_responses, 'next_page_token': mocked_next_page_token}


def test_gsuite_reset_password(gsuite_client, mocker):
    """
    Scenario: User reset password command successful execution.

    Given:
    - Working API integration and correct parameters

    When:
    - Calling command gsuite_user_reset_password

    Then:
    - Ensure expected human readable output is being set.
    """

    from GSuiteAdmin import user_reset_password_command
    args = {'user_key': 'nikolic@demistodev.com'}
    with open('test_data/user_password_reset_response.json') as file:
        api_response = json.load(file)
    with open('test_data/user_password_reset_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value=api_response)
    command_result = user_reset_password_command(gsuite_client, args)
    assert command_result.readable_output == expected_entry_context['readable_output']
    assert command_result.outputs == expected_entry_context['outputs']
    assert command_result.raw_response == expected_entry_context['raw_response']
    assert command_result.outputs_key_field == ['id']
    assert command_result.outputs_prefix == 'GSuite.User'


def test_chromebrowser_move_ou_command(gsuite_client, mocker):
    """
        Scenario: chromebrowserdevice move successful execution.

        Given:
        - Working API integration and correct parameters

        When:
        - Calling command chromebrowser_move_ou_command

        Then:
        - Ensure no error returns
    """
    from GSuiteAdmin import chromebrowser_move_ou_command
    args = {"customer_id": "test", "resource_ids": "1111", "org_unit_path": "/testing"}
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value={})
    response = chromebrowser_move_ou_command(gsuite_client, args)
    assert response == f'Chrome browser devices have been moved to the new organization unit {args["org_unit_path"]}'


def test_chromebrowser_move_ou_command_missing_customerId(gsuite_client, mocker):
    """
        Scenario: chromebrowserdevice move successful execution.

        Given:
        - Working API integration and missing customer ID

        When:
        - Calling command chromebrowser_move_ou_command

        Then:
        - Catch the returned error
    """
    from GSuiteAdmin import chromebrowser_move_ou_command
    args = {"resource_ids": "1111", "org_unit_path": "/testing"}
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value={})
    with pytest.raises(DemistoException, match="Missing required customer ID - either provide as an argument or set a parameter"):
        chromebrowser_move_ou_command(gsuite_client, args)


@pytest.mark.parametrize(
    "args",
    [
        {"customer_id": "test", "limit": "1"},
        {"customer_id": "test", "limit": "10000"},
        {"customer_id": "test", "page_size": "1", "limit": "10000"},
        {"customer_id": "test", "page_token": "1aaa", "limit": "10000"},
        {"customer_id": "test", "page_size": "5000", "limit": "10000"},
    ]
)
def test_chromebrowser_list_command_multiple_limits(gsuite_client, mocker, args):
    """
        Scenario: chromebrowserdevice list successful execution.

        Given:
        - Working API integration and correct parameters

        When:
        - Calling command chromebrowser_list_command

        Then:
        - Ensure no error returns
    """
    from GSuiteAdmin import chromebrowser_list_command
    with open('test_data/chromebrowser_list_response.json') as file:
        api_response = json.load(file)
    with open('test_data/chromebrowser_list_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value=api_response)
    command_result = chromebrowser_list_command(gsuite_client, args)
    assert command_result.readable_output == expected_entry_context['readable_output']
    assert command_result.outputs == expected_entry_context['outputs']
    assert command_result.raw_response == expected_entry_context['raw_response']


def test_chromebrowser_list_command_device_id(gsuite_client, mocker):
    """
        Scenario: chromebrowserdevice list successful execution with specific device ID

        Given:
        - Working API integration and correct parameters

        When:
        - Calling command chromebrowser_list_command

        Then:
        - Ensure no error returns
    """
    from GSuiteAdmin import chromebrowser_list_command
    args = {"customer_id": "test", "device_id": "1111111111"}
    with open('test_data/chromebrowser_list_by_device_response.json') as file:
        api_response = json.load(file)
    with open('test_data/chromebrwoser_list_by_device_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value=api_response)
    command_result = chromebrowser_list_command(gsuite_client, args)
    assert command_result.readable_output == expected_entry_context['readable_output']
    assert command_result.outputs == expected_entry_context['outputs']
    assert command_result.raw_response == expected_entry_context['raw_response']


def test_modify_policy_command(gsuite_client, mocker):
    """
        Scenario: Policy Modify command successful execution.

        Given:
        - Working API integration and correct parameters

        When:
        - Calling command modify_policy_command

        Then:
        - Ensure no error returns
    """
    from GSuiteAdmin import modify_policy_command
    args = {"customer_id": "test", "target_type": "Group", "target_resource": "11111111",
            "policy_schema_filter": "chrome.users.apps.InstallType",
            "additional_target_keys": "{\"app_id\":\"chrome:11111111\"}",
            "policy_schema": "chrome.users.apps.InstallType", "policy_value": "BLOCKED", "update_mask": "appInstallType"}
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value={})
    response = modify_policy_command(gsuite_client, args)
    assert response == f'Policy has been modified for the customer {args["customer_id"]}'


def test_modify_policy_command_with_raw_json(gsuite_client, mocker):
    """
        Scenario: Policy Modify command successful execution.

        Given:
        - Working API integration and raw JSON file

        When:
        - Calling command modify_policy_command

        Then:
        - Ensure no error returns
    """
    from GSuiteAdmin import modify_policy_command
    args = {"customer_id": "test", "target_type": "Group", "policy_raw_json":
            "{\"requests\": [{\"policyTargetKey\": {\"targetResource\": \"groups/11111111\","
            "\"additionalTargetKeys\": {\"app_id\": \"chrome:11111111\"}},"
            "\"policyValue\": { \"policySchema\": \"chrome.users.apps.InstallType\","
            "\"value\": {\"appInstallType\": \"BLOCKED\"}}, \"updateMask\": \"appInstallType\"}]}"}
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value={})
    response = modify_policy_command(gsuite_client, args)
    assert response == f'Policy has been modified for the customer {args["customer_id"]}'


@pytest.mark.parametrize(
    "args",
    [
        {"customer_id": "test", "limit": "2"},
        {"customer_id": "test", "limit": "100000"},
        {"customer_id": "test", "page_size": "2", "limit": "1"},
        {"customer_id": "test", "page_token": "1aaa", "limit": "1"},
        {"customer_id": "test", "page_size": "2000", "limit": "1"},
    ]
)
def test_policy_schemas_command(gsuite_client, mocker, args):
    """
        Scenario: Policy Schema list command successful execution.

        Given:
        - Working API integration and correct parameters

        When:
        - Calling command policy_schemas_command

        Then:
        - Ensure no error returns
    """
    from GSuiteAdmin import policy_schemas_list_command
    with open('test_data/policy_schemas_list_reponse.json') as file:
        api_response = json.load(file)
    with open('test_data/policy_schemas_list_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value=api_response)
    command_result = policy_schemas_list_command(gsuite_client, args)
    assert command_result.readable_output == expected_entry_context['readable_output']
    assert command_result.outputs == expected_entry_context['outputs']
    assert command_result.raw_response == expected_entry_context['raw_response']


def test_policy_schemas_command_schema_name(gsuite_client, mocker):
    """
        Scenario: Policy Schema list command successful execution.

        Given:
        - Working API integration and specific schema name

        When:
        - Calling command policy_schemas_command

        Then:
        - Ensure no error returns
    """
    from GSuiteAdmin import policy_schemas_list_command
    args = {"customer_id": "test", "schema_name": "chrome.users.appsconfig.AllowedAppTypes"}
    with open('test_data/policy_schemas_list_reponse_schema_name.json') as file:
        api_response = json.load(file)
    with open('test_data/policy_schemas_list_context_schema_name.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value=api_response)
    command_result = policy_schemas_list_command(gsuite_client, args)
    assert command_result.readable_output == expected_entry_context['readable_output']
    assert command_result.outputs == expected_entry_context['outputs']
    assert command_result.raw_response == expected_entry_context['raw_response']


@pytest.mark.parametrize(
    "args",
    [
        {"customer_id": "test", "limit": "2", "policy_schema_filter": "chrome.users.apps.InstallType",
         "target_resource": "03ph8a2z1kjba6k", "target_type": "OrgUnit"},
        {"customer_id": "test", "limit": "10000", "policy_schema_filter": "chrome.users.apps.InstallType",
         "target_resource": "03ph8a2z1kjba6k", "target_type": "OrgUnit"},
        {"customer_id": "test", "page_size": "2", "limit": "4", "policy_schema_filter": "chrome.users.apps.InstallType",
         "target_resource": "03ph8a2z1kjba6k", "target_type": "OrgUnit"},
        {"customer_id": "test", "page_size": "5000", "limit": "10000", "policy_schema_filter": "chrome.users.apps.InstallType",
         "target_resource": "03ph8a2z1kjba6k", "target_type": "OrgUnit"},
        {"customer_id": "test", "page_token": "1aaaa", "limit": "10000", "policy_schema_filter": "chrome.users.apps.InstallType",
         "target_resource": "03ph8a2z1kjba6k", "target_type": "OrgUnit"},
    ]
)
def test_policy_resolve_command(gsuite_client, mocker, args):
    """
        Scenario: Policy resolve command successful execution.

        Given:
        - Working API integration and correct parameters

        When:
        - Calling command policy_resolve_command

        Then:
        - Ensure no error returns
    """
    from GSuiteAdmin import policy_resolve_command
    with open('test_data/policy_resolve_response.json') as file:
        api_response = json.load(file)
    with open('test_data/policy_resolve_context.json') as file:
        expected_entry_context = json.load(file)
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value=api_response)
    command_result = policy_resolve_command(gsuite_client, args)
    assert command_result.readable_output == expected_entry_context['readable_output']
    assert command_result.outputs == expected_entry_context['outputs']
    assert command_result.raw_response == expected_entry_context['raw_response']


def test_group_delete_command(gsuite_client, mocker):
    """
        Scenario: Delete group command successful execution.

        Given:
        - Working API integration and correct parameters

        When:
        - Calling command group_delete_command

        Then:
        - Ensure no error returns
    """
    from GSuiteAdmin import group_delete_command
    args = {"customer_id": "test", "target_resource": "111111", "policy_schema": "chrome.users.apps.InstallType",
            "additional_target_keys": "{\"app_id\":\"chrome:11111111\"}"}
    mocker.patch('GSuiteAdmin.GSuiteClient.http_request', return_value={})
    response = group_delete_command(gsuite_client, args)
    assert response == f'Policy has been deleted for the customer {args["customer_id"]}'
