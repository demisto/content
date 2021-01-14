from requests import Response, Session
from ServiceNow_IAM import *


SERVICENOW_USER_OUTPUT = {
    "sys_id": "mock_id",
    "user_name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "true",
    "email": "testdemisto2@paloaltonetworks.com"
}

SERVICENOW_DISABLED_USER_OUTPUT = {
    "sys_id": "mock_id",
    "user_name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "false",
    "email": "testdemisto2@paloaltonetworks.com"
}


def mock_client():
    client = Client(base_url='https://test.com')
    return client


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


def test_get_user_command__existing_user(mocker):
    """
    Given:
        - A ServiceNow IAM client object
        - A user-profile argument that contains an email of a user
    When:
        - The user exists in ServiceNow
        - Calling function get_user_command
    Then:
        - Ensure the resulted User Profile object holds the correct user details
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=SERVICENOW_USER_OUTPUT)
    mocker.patch.object(IAMUserProfile, 'update_with_app_data', return_value={})

    user_profile = get_user_command(client, args, 'mapper_in')
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'mock_user_name'
    assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
    assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


def test_get_user_command__non_existing_user(mocker):
    """
    Given:
        - A ServiceNow IAM client object
        - A user-profile argument that contains an email a user
    When:
        - The user does not exist in ServiceNow
        - Calling function get_user_command
    Then:
        - Ensure the resulted User Profile object holds information about an unsuccessful result.
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)

    user_profile = get_user_command(client, args, 'mapper_in')
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == IAMErrors.USER_DOES_NOT_EXIST[0]
    assert outputs.get('errorMessage') == IAMErrors.USER_DOES_NOT_EXIST[1]


def test_get_user_command__bad_response(mocker):
    """
    Given:
        - A ServiceNow IAM client object
        - A user-profile argument that contains an email of a non-existing user in ServiceNow
    When:
        - Calling function get_user_command
        - A bad response (500) is returned from ServiceNow's API
    Then:
        - Ensure the resulted User Profile object holds information about the bad response.
    """
    import demistomock as demisto

    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    bad_response = Response()
    bad_response.status_code = 500
    bad_response._content = b'{"error": {"detail": "details", "message": "message"}}'

    mocker.patch.object(demisto, 'error')
    mocker.patch.object(Session, 'request', return_value=bad_response)

    user_profile = get_user_command(client, args, 'mapper_in')
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == 500
    assert outputs.get('errorMessage') == 'message: details'


def test_create_user_command__success(mocker):
    """
    Given:
        - A ServiceNow IAM client object
        - A user-profile argument that contains an email of a non-existing user in ServiceNow
    When:
        - Calling function create_user_command
    Then:
        - Ensure a User Profile object with the user data is returned
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'create_user', return_value=SERVICENOW_USER_OUTPUT)

    user_profile = create_user_command(client, args, 'mapper_out', is_command_enabled=True)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'mock_user_name'
    assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
    assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


def test_create_user_command__user_already_exists(mocker):
    """
    Given:
        - A ServiceNow IAM client object
        - A user-profile argument that contains an email of a user
    When:
        - The user already exists in ServiceNow and disabled
        - allow-enable argument is false
        - Calling function create_user_command
    Then:
        - Ensure the command is considered successful and the user is still disabled
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}, 'allow-enable': 'false'}

    mocker.patch.object(client, 'get_user', return_value=SERVICENOW_DISABLED_USER_OUTPUT)
    mocker.patch.object(client, 'update_user', return_value=SERVICENOW_DISABLED_USER_OUTPUT)

    user_profile = create_user_command(client, args, 'mapper_out', is_command_enabled=True)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.UPDATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is False
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'mock_user_name'
    assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
    assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


def test_update_user_command__non_existing_user(mocker):
    """
    Given:
        - A ServiceNow IAM client object
        - A user-profile argument that contains user data
    When:
        - The user does not exist in ServiceNow
        - create-if-not-exists parameter is checked
        - Create User command is enabled
        - Calling function update_user_command
    Then:
        - Ensure the create action is executed
        - Ensure a User Profile object with the user data is returned
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'create_user', return_value=SERVICENOW_USER_OUTPUT)

    user_profile = update_user_command(client, args, 'mapper_out', is_command_enabled=True,
                                       is_create_user_enabled=True, create_if_not_exists=True)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'mock_user_name'
    assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
    assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


def test_update_user_command__command_is_disabled(mocker):
    """
    Given:
        - A ServiceNow IAM client object
        - A user-profile argument that contains user data
    When:
        - Update User command is disabled
        - Calling function update_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'update_user', return_value=SERVICENOW_USER_OUTPUT)

    user_profile = update_user_command(client, args, 'mapper_out', is_command_enabled=False,
                                       is_create_user_enabled=False, create_if_not_exists=False)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.UPDATE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == 'Command is disabled.'


def test_update_user_command__allow_enable(mocker):
    """
    Given:
        - An ServiceNow IAM client object
        - A user-profile argument that contains user data
    When:
        - The user is disabled in ServiceNow
        - allow-enable argument is true
        - Calling function update_user_command
    Then:
        - Ensure the user is enabled at the end of the command execution.
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'},
            'allow-enable': 'true'}

    mocker.patch.object(client, 'get_user', return_value=SERVICENOW_DISABLED_USER_OUTPUT)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'update_user', return_value=SERVICENOW_USER_OUTPUT)

    user_profile = update_user_command(client, args, 'mapper_out', is_command_enabled=True,
                                       is_create_user_enabled=False, create_if_not_exists=False)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.UPDATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'mock_user_name'
    assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
    assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


def test_disable_user_command__non_existing_user(mocker):
    """
    Given:
        - A ServiceNow IAM client object
        - A user-profile argument that contains an email of a user
    When:
        - create-if-not-exists parameter is unchecked
        - The user does not exist in ServiceNow
        - Calling function disable_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)

    user_profile = disable_user_command(client, args, is_command_enabled=True)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.DISABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == IAMErrors.USER_DOES_NOT_EXIST[1]


def test_get_mapping_fields_command(mocker):
    """
    Given:
        - A ServiceNow IAM client object
    When:
        - ServiceNow user schema contains the fields 'field1' and 'field2'
        - Calling function get_mapping_fields_command
    Then:
        - Ensure a GetMappingFieldsResponse object that contains the ServiceNow fields is returned
    """
    client = mock_client()
    mocker.patch.object(client, 'get_service_now_fields', return_value={'field1': 'desc1', 'field2': 'desc2'})

    mapping_response = get_mapping_fields_command(client)
    mapping = mapping_response.extract_mapping()[0]

    assert mapping.get(IAMUserProfile.INDICATOR_TYPE, {}).get('field1') == 'desc1'
    assert mapping.get(IAMUserProfile.INDICATOR_TYPE, {}).get('field2') == 'desc2'
