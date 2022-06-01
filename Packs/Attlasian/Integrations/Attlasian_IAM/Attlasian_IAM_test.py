from Attlasian_IAM import Client, get_mapping_fields
from IAMApiModule import *

APP_USER_OUTPUT = {
    "schemas": [
        "urn:scim:schemas:extension:atlassian-external:1.0",
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    ],
    "userName": "Demisto",
    "emails": [
        {
            "value": "testdemisto@paloaltonetworks.com",
            "type": "work",
            "primary": True
        }
    ],
    "name": {
        "familyName": "test1",
        "givenName": "demisto2"
    },
    "meta": {
        "resourceType": "User",
        "location": "https://api.atlassian.com/scim/directory/"
                    "315e79ae-404a-4061-8a88-df91c8c7db34/Users/a59238e6-487e-451d-a534-d67aa4c48350",
        "lastModified": "2021-02-21T11:57:56.537169Z",
        "created": "2021-02-21T11:57:56.537169Z"
    },
    "groups": [],
    "urn:scim:schemas:extension:atlassian-external:1.0": {
        "atlassianAccountId": "5f45327791e67a003fed461e"
    },
    "id": "a59238e6-487e-451d-a534-d67aa4c48350",
    "active": True
}

USER_APP_DATA = IAMUserAppData("mock_id", "mock_user_name", is_active=True, app_data=APP_USER_OUTPUT)

APP_DISABLED_USER_OUTPUT = {
    "schemas": [
        "urn:scim:schemas:extension:atlassian-external:1.0",
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    ],
    "userName": "Demisto",
    "emails": [
        {
            "value": "testdemisto@paloaltonetworks.com",
            "type": "work",
            "primary": True
        }
    ],
    "name": {
        "familyName": "test1",
        "givenName": "demisto2"
    },
    "meta": {
        "resourceType": "User",
        "location": "https://api.atlassian.com/scim/directory/"
                    "315e79ae-404a-4061-8a88-df91c8c7db34/Users/a59238e6-487e-451d-a534-d67aa4c48350",
        "lastModified": "2021-02-21T11:57:56.537169Z",
        "created": "2021-02-21T11:57:56.537169Z"
    },
    "groups": [],
    "urn:scim:schemas:extension:atlassian-external:1.0": {
        "atlassianAccountId": "5f45327791e67a003fed461e"
    },
    "id": "a59238e6-487e-451d-a534-d67aa4c48350",
    "active": False
}

DISABLED_USER_APP_DATA = IAMUserAppData("mock_id", "mock_user_name", is_active=False, app_data=APP_DISABLED_USER_OUTPUT)


def mock_client():
    client = Client(base_url='https://test.com',
                    directory_id='test123',
                    verify=False,
                    headers={})
    return client


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


def test_get_user_command__existing_user(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an email of a user
    When:
        - The user exists in the application
        - Calling function get_user_command
    Then:
        - Ensure the resulted User Profile object holds the correct user details
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=USER_APP_DATA)
    mocker.patch.object(IAMUserProfile, 'update_with_app_data', return_value={})

    user_profile = IAMCommand().get_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'mock_user_name'
    assert outputs.get('details', {}).get('name').get('givenName') == 'demisto2'
    assert outputs.get('details', {}).get('name').get('familyName') == 'test1'


def test_get_user_command__non_existing_user(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an email a user
    When:
        - The user does not exist in the application
        - Calling function get_user_command
    Then:
        - Ensure the resulted User Profile object holds information about an unsuccessful result.
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)

    user_profile = IAMCommand().get_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == IAMErrors.USER_DOES_NOT_EXIST[0]
    assert outputs.get('errorMessage') == IAMErrors.USER_DOES_NOT_EXIST[1]


def test_create_user_command__success(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an email of a non-existing user in the application
    When:
        - Calling function create_user_command
    Then:
        - Ensure a User Profile object with the user data is returned
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={'email': 'testdemisto2@paloaltonetworks.com'})
    mocker.patch.object(client, 'create_user', return_value=USER_APP_DATA)

    user_profile = IAMCommand(get_user_iam_attrs=['email']).create_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'mock_user_name'
    assert outputs.get('details', {}).get('name').get('givenName') == 'demisto2'
    assert outputs.get('details', {}).get('name').get('familyName') == 'test1'


def test_create_user_command__user_already_exists(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an email of a user
    When:
        - The user already exists in the application and disabled
        - allow-enable argument is false
        - Calling function create_user_command
    Then:
        - Ensure the command is considered successful and the user is still disabled
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}, 'allow-enable': 'false'}

    mocker.patch.object(client, 'get_user', return_value=DISABLED_USER_APP_DATA)
    mocker.patch.object(client, 'update_user', return_value=DISABLED_USER_APP_DATA)

    user_profile = IAMCommand().create_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.UPDATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is False
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'mock_user_name'
    assert outputs.get('details', {}).get('name').get('givenName') == 'demisto2'
    assert outputs.get('details', {}).get('name').get('familyName') == 'test1'


def test_update_user_command__non_existing_user(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains user data
    When:
        - The user does not exist in the application
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
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={'email': 'testdemisto2@paloaltonetworks.com'})
    mocker.patch.object(client, 'create_user', return_value=USER_APP_DATA)

    user_profile = IAMCommand(create_if_not_exists=True).update_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'mock_user_name'
    assert outputs.get('details', {}).get('name').get('givenName') == 'demisto2'
    assert outputs.get('details', {}).get('name').get('familyName') == 'test1'


def test_update_user_command__command_is_disabled(mocker):
    """
    Given:
        - An app client object
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
    mocker.patch.object(client, 'update_user', return_value=USER_APP_DATA)

    user_profile = IAMCommand(is_update_enabled=False).update_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.UPDATE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == 'Command is disabled.'


def test_disable_user_command__non_existing_user(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an email of a user
    When:
        - create-if-not-exists parameter is unchecked
        - The user does not exist in the application
        - Calling function disable_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)

    user_profile = IAMCommand().disable_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.DISABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == IAMErrors.USER_DOES_NOT_EXIST[1]


def test_get_mapping_fields_command(mocker):
    """
    Given:
        - An app client object
    When:
        - User schema in the application contains the fields 'field1' and 'field2'
        - Calling function get_mapping_fields_command
    Then:
        - Ensure a GetMappingFieldsResponse object that contains the application fields is returned
    """
    client = mock_client()
    mocker.patch.object(client, 'get_app_fields', return_value={'field1': 'desc1', 'field2': 'desc2'})

    mapping_response = get_mapping_fields(client)
    mapping = mapping_response.extract_mapping()

    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field1') == 'desc1'
    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field2') == 'desc2'
