from requests import Response, Session
from Okta_IAM import Client, get_user_command, create_user_command, update_user_command, \
    enable_user_command, disable_user_command, get_mapping_fields_command
from CommonServerPython import IAMErrors, IAMUserProfile, IAMActions


OKTA_USER_OUTPUT = {
    "id": "mock_id",
    "status": "PROVISIONED",
    "profile": {
        "firstName": "mock_first_name",
        "lastName": "mock_last_name",
        "login": "testdemisto2@paloaltonetworks.com",
        "email": "testdemisto2@paloaltonetworks.com"
    }
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
        - An Okta IAM client object
        - A user-profile argument that contains an email of a user
    When:
        - The user exists in Okta
        - Calling function get_user_command
    Then:
        - Ensure the resulted User Profile object holds the correct user details
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=OKTA_USER_OUTPUT)
    mocker.patch.object(IAMUserProfile, 'update_with_app_data', return_value={})

    user_profile = get_user_command(client, args, 'mapper_in')
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'testdemisto2@paloaltonetworks.com'
    assert outputs.get('details', {}).get('profile', {}).get('firstName') == 'mock_first_name'
    assert outputs.get('details', {}).get('profile', {}).get('lastName') == 'mock_last_name'


def test_get_user_command__non_existing_user(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email a user
    When:
        - The user does not exist in Okta
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
        - An Okta IAM client object
        - A user-profile argument that contains an email of a non-existing user in Okta
    When:
        - Calling function get_user_command
        - A bad response (500) is returned from Okta's API
    Then:
        - Ensure the resulted User Profile object holds information about the bad response.
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    bad_response = Response()
    bad_response.status_code = 500
    bad_response._content = b'{"errorCode": "mock_error_code", ' \
                            b'"errorSummary": "mock_error_summary", ' \
                            b'"errorCauses": [{"errorSummary": "reason_1"}, ' \
                            b'{"errorSummary": "reason_2"}]}'

    mocker.patch.object(Session, 'request', return_value=bad_response)

    user_profile = get_user_command(client, args, 'mapper_in')
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == 'mock_error_code'
    assert outputs.get('errorMessage') == 'mock_error_summary. Reason:\n1. reason_1\n2. reason_2\n'


def test_create_user_command__success(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email of a non-existing user in Okta
    When:
        - Calling function create_user_command
    Then:
        - Ensure a User Profile object with the user data is returned
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'create_user', return_value=OKTA_USER_OUTPUT)

    user_profile = create_user_command(client, args, 'mapper_out', is_command_enabled=True)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'testdemisto2@paloaltonetworks.com'
    assert outputs.get('details', {}).get('profile', {}).get('firstName') == 'mock_first_name'
    assert outputs.get('details', {}).get('profile', {}).get('lastName') == 'mock_last_name'


def test_create_user_command__user_already_exists(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email of a user
    When:
        - The user already exists in Okta
        - Calling function create_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=OKTA_USER_OUTPUT)

    user_profile = create_user_command(client, args, 'mapper_out', is_command_enabled=True)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == IAMErrors.USER_ALREADY_EXISTS[1]


def test_update_user_command__non_existing_user(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains user data
    When:
        - The user does not exist in Okta
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
    mocker.patch.object(client, 'create_user', return_value=OKTA_USER_OUTPUT)

    user_profile = update_user_command(client, args, 'mapper_out', is_command_enabled=True,
                                       is_create_user_enabled=True, create_if_not_exists=True)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'testdemisto2@paloaltonetworks.com'
    assert outputs.get('details', {}).get('profile', {}).get('firstName') == 'mock_first_name'
    assert outputs.get('details', {}).get('profile', {}).get('lastName') == 'mock_last_name'


def test_update_user_command__command_is_disabled(mocker):
    """
    Given:
        - An Okta IAM client object
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
    mocker.patch.object(client, 'update_user', return_value=OKTA_USER_OUTPUT)

    user_profile = update_user_command(client, args, 'mapper_out', is_command_enabled=False,
                                       is_create_user_enabled=False, create_if_not_exists=False)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.UPDATE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == 'Command is disabled.'


def test_enable_user_command__non_existing_user(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email of a user
    When:
        - create-if-not-exists parameter is unchecked
        - The user does not exist in Okta
        - Calling function enable_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)

    user_profile = enable_user_command(client, args, 'mapper_out', is_command_enabled=True,
                                       is_create_user_enabled=True, create_if_not_exists=False)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.ENABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == IAMErrors.USER_DOES_NOT_EXIST[1]


def test_disable_user_command__user_is_already_disabled(mocker):
    """
    Given:
        - An Okta IAM client object
        - A user-profile argument that contains an email of a user
    When:
        - The user is already disabled in Okta
        - Calling function disable_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    bad_response = Response()
    bad_response.status_code = 500
    bad_response._content = b'{"errorCode": "E0000007", ' \
                            b'"errorSummary": "mock_error_summary", ' \
                            b'"errorCauses": [{"errorSummary": "reason_1"}, ' \
                            b'{"errorSummary": "reason_2"}]}'

    mocker.patch.object(Session, 'request', return_value=bad_response)

    user_profile = disable_user_command(client, args, is_command_enabled=True)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.DISABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == 'Deactivation failed because the user is already disabled.'


def test_get_mapping_fields_command(mocker):
    """
    Given:
        - An Okta IAM client object
    When:
        - Okta user schema contains the fields 'field1' and 'field2'
        - Calling function get_mapping_fields_command
    Then:
        - Ensure a GetMappingFieldsResponse object that contains the Okta fields is returned
    """
    client = mock_client()

    mocker.patch.object(client, 'get_okta_fields', return_value={'field1': 'description1', 'field2': 'description2'})

    mapping_response = get_mapping_fields_command(client)
    mapping = mapping_response.extract_mapping()[0]

    assert mapping.get(IAMUserProfile.INDICATOR_TYPE, {}).get('field1') == 'description1'
    assert mapping.get(IAMUserProfile.INDICATOR_TYPE, {}).get('field2') == 'description2'
