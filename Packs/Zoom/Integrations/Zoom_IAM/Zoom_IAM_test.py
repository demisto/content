from Zoom_IAM import Client
from IAMApiModule import *
from freezegun import freeze_time
import Zoom_IAM

APP_USER_OUTPUT = {
    "user_id": "mock_id",
    "user_name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "email": "testdemisto2@paloaltonetworks.com"
}

USER_APP_DATA = IAMUserAppData("mock_id", "mock_user_name", is_active=True, app_data=APP_USER_OUTPUT)
USER_APP_DATA_DISABLED = IAMUserAppData("mock_id", "mock_user_name", is_active=False, app_data=APP_USER_OUTPUT)

APP_DISABLED_USER_OUTPUT = {
    "user_id": "mock_id",
    "user_name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "false",
    "email": "testdemisto2@paloaltonetworks.com"
}

APP_ENABLED_USER_OUTPUT = {
    "user_id": "mock_id",
    "user_name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "true",
    "email": "testdemisto2@paloaltonetworks.com"
}

DISABLED_USER_APP_DATA = IAMUserAppData("mock_id", "mock_user_name", is_active=False, app_data=APP_DISABLED_USER_OUTPUT)
ENABLED_USER_APP_DATA = IAMUserAppData("mock_id", "mock_user_name", is_active=True, app_data=APP_ENABLED_USER_OUTPUT)


def mock_client_ouath(mocker):

    mocker.patch.object(Client, 'get_oauth_token')
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    return client


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


def test_generate_oauth_token(mocker):
    """
        Given -
           client
        When -
            generating a token
        Then -
            Validate the parameters and the result are as expected
    """
    client = mock_client_ouath(mocker)

    m = mocker.patch.object(client, '_http_request', return_value={'access_token': 'token'})
    res = client.generate_oauth_token()
    assert m.call_args[1]['method'] == 'POST'
    assert m.call_args[1]['full_url'] == 'https://zoom.us/oauth/token'
    assert m.call_args[1]['params'] == {'account_id': 'mockaccount',
                                        'grant_type': 'account_credentials'}
    assert m.call_args[1]['auth'] == ('mockclient', 'mocksecret')

    assert res == 'token'


@freeze_time("1988-03-03T11:00:00")
def test_get_oauth_token__while_old_token_still_valid(mocker):
    """
        Given -
           client
        When -
            asking for a token while the previous token is still valid
        Then -
            Validate that a new token will not be generated, and the old token will be returned
            Validate that the old token is the one
            stored in the get_integration_context dict.
    """
    mocker.patch.object(Zoom_IAM, "get_integration_context",
                        return_value={"generation_time": "1988-03-03T10:50:00",
                                      'oauth_token': "old token"})
    generate_token_mock = mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    assert not generate_token_mock.called
    assert client.access_token == "old token"


def test_get_oauth_token___old_token_expired(mocker):
    """
        Given -
           client
        When -
            asking for a token when the previous token was expired
        Then -
            Validate that a func that creates a new token has been called
            Validate that a new token was stored in the get_integration_context dict.
    """
    mocker.patch.object(Zoom_IAM, "get_integration_context",
                        return_value={"generation_time": "1988-03-03T10:00:00",
                                      'oauth_token': "old token"})
    generate_token_mock = mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    assert generate_token_mock.called
    assert client.access_token != "old token"


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
    client = mock_client_ouath(mocker)
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
    client = mock_client_ouath(mocker)
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    user_profile = IAMCommand().disable_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.DISABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == IAMErrors.USER_DOES_NOT_EXIST[1]


def test_enable_user_command__allow_enable(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains user data
    When:
        - The user is disabled in the application
        - allow-enable argument is true
        - Calling function enable_user_command
    Then:
        - Ensure the user is enabled at the end of the command execution.
    """
    client = mock_client_ouath(mocker)
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'},
            'allow-enable': 'true'}
    mocker.patch.object(client, 'get_user', return_value=USER_APP_DATA_DISABLED)
    mocker.patch.object(client, 'enable_user', return_value=ENABLED_USER_APP_DATA)

    user_profile = IAMCommand().enable_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.ENABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == 'mock_id'
    assert outputs.get('username') == 'mock_user_name'
    assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
    assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


def test_enable_user_command__non_existing_user(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an email of a user
    When:
        - The user does not exist in the application
        - Calling function enable_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    client = mock_client_ouath(mocker)
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)

    user_profile = IAMCommand().enable_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.ENABLE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == IAMErrors.USER_DOES_NOT_EXIST[1]
