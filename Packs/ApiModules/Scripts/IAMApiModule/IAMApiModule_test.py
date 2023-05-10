from IAMApiModule import *
import pytest
from copy import deepcopy

APP_USER_OUTPUT = {
    "user_id": "mock_id",
    "user_name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "email": "testdemisto2@paloaltonetworks.com"
}

USER_APP_DATA = IAMUserAppData("mock_id", "mock_user_name", is_active=True, app_data=APP_USER_OUTPUT)

APP_DISABLED_USER_OUTPUT = {
    "user_id": "mock_id",
    "user_name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "false",
    "email": "testdemisto2@paloaltonetworks.com"
}

DISABLED_USER_APP_DATA = IAMUserAppData("mock_id", "mock_user_name", is_active=False, app_data=APP_DISABLED_USER_OUTPUT)


class MockCLient():
    def get_user(self):
        return None

    def create_user(self):
        return None

    def update_user(self):
        return None

    def enable_user(self):
        return None

    def disable_user(self):
        return None


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
    client = MockCLient()
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
    assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
    assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


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
    client = MockCLient()
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
    client = MockCLient()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(client, 'create_user', return_value=USER_APP_DATA)

    user_profile = IAMCommand(get_user_iam_attrs=['email']).create_user(client, args)
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
        - An app client object
        - A user-profile argument that contains an email of a user
    When:
        - The user already exists in the application and disabled
        - allow-enable argument is false
        - Calling function create_user_command
    Then:
        - Ensure the command is considered successful and the user is still disabled
    """
    client = MockCLient()
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
    assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
    assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


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
    client = MockCLient()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(client, 'create_user', return_value=USER_APP_DATA)

    user_profile = IAMCommand(create_if_not_exists=True).update_user(client, args)
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
        - An app client object
        - A user-profile argument that contains user data
    When:
        - Update User command is disabled
        - Calling function update_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    client = MockCLient()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

    mocker.patch.object(client, 'get_user', return_value=None)
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
    client = MockCLient()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)

    user_profile = IAMCommand().disable_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.DISABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == IAMErrors.USER_DOES_NOT_EXIST[1]


@pytest.mark.parametrize("not_existing", (" ", "testdemisto2@paloaltonetworks.com"))
def test_enable_user_command__non_existing_user(mocker, not_existing):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an email of a user
    When:
        - create-if-not-exists parameter is unchecked
        - The user does not exist in the application
        - Calling function enable_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    client = MockCLient()
    args = {'user-profile': {'email': not_existing}}

    mocker.patch.object(client, 'get_user', return_value=None)

    user_profile = IAMCommand().enable_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.ENABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == IAMErrors.USER_DOES_NOT_EXIST[1]


@pytest.mark.parametrize("given_name, is_correct", [("mock_given_name", True), ("wrong_name", False)])
def test_enable_user_command__with_wrong_and_correct_given_name(mocker, given_name, is_correct):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an email of a user and a given name
    When:
        - The given name is correct and matches an existing user
        - The given name is wrong and dos not match an existing user
    Then:
        - That name will be saved under the givenname section.
    """
    client = MockCLient()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': given_name}}
    disabled_user_data = IAMUserAppData("mock_userid", "mock_username", False, {"user_id": "mock_id",
                                                                                "user_name": "mock_user_name",
                                                                                "first_name": given_name,
                                                                                "last_name": "mock_last_name",
                                                                                "email": "testdemisto2@paloaltonetworks.com"})
    enabled_user_data = deepcopy(disabled_user_data)
    enabled_user_data.is_active = True
    mocker.patch.object(client, 'get_user', return_value=disabled_user_data)
    mocker.patch.object(client, 'enable_user', return_value=enabled_user_data)

    user_profile = IAMCommand().enable_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.ENABLE_USER
    assert outputs.get('details', {}).get('first_name') == given_name


@pytest.mark.parametrize("input", [{'user-profile': {'email': ""}}, {'user-profile': {}}])
def test_enable_user_command__empty_json_as_argument(input):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an empty json with no user profile
    When:
        - Calling function enable_user_command
    Then:
        - Ensure the command will return the correct error
    """
    class NewMockClient():
        @staticmethod
        def handle_exception(user_profile: IAMUserProfile,
                             e: Union[DemistoException, Exception],
                             action: IAMActions):
            raise e

    client = NewMockClient()
    iamcommand = IAMCommand(get_user_iam_attrs=['id', 'username', 'email'])

    with pytest.raises(DemistoException) as e:
        iamcommand.enable_user(client, input)
    assert e.value.message == ("Your user profile argument must contain at least one attribute that is mapped into one of the following attributes in the outgoing mapper: ['id', 'username', 'email']")    # noqa: E501
