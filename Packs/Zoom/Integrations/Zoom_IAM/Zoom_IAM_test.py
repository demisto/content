from Zoom_IAM import Client

from IAMApiModule import *

APP_USER_OUTPUT = {
    "user_id": "mock_id",
    "user_name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "true",
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


def mock_client():
    client = Client(base_url='https://test.com', api_key="mockkey", api_secret="mocksecret")
    return client


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


def test_disable_user_command__allow_disable(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains user data
    When:
        - The user is enabled in the application
        - allow-disable argument is true
        - Calling function disable_user_command
    Then:
        - Ensure the user is disabled at the end of the command execution.
    """
    client = mock_client()
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'},
            'allow-disable': 'true'}
    mocker.patch.object(client, 'get_user', return_value=USER_APP_DATA)
    mocker.patch.object(client, 'disable_user', return_value=DISABLED_USER_APP_DATA)

    user_profile = IAMCommand().disable_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.DISABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is False
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'mock_user_name'
    assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
    assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


def test_disable_user_command__non_existing_user(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an email of a user
    When:
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
