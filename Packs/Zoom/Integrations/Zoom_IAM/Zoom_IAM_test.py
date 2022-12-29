from Zoom_IAM import Client
from IAMApiModule import *
from freezegun import freeze_time
import Zoom_IAM
import pytest

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


@pytest.mark.parametrize("result", (" ", "None"))
def test_get_oauth_token__if_not_ctx(mocker, result):
    """
        Given -
           client
        When -
            asking for the latest token's generation_time and the result is None
            or empty
        Then -
            Validate that a new token will be generated.
    """
    mocker.patch.object(Zoom_IAM, "get_integration_context",
                        return_value={'token_info': {"generation_time": result,
                                      'oauth_token': "old token"}})
    generate_token_mock = mocker.patch.object(Client, "generate_oauth_token")
    Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    assert generate_token_mock.called


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
                        return_value={'token_info': {"generation_time": "1988-03-03T10:50:00",
                                      'oauth_token': "old token"}})
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
                        return_value={'token_info': {"generation_time": "1988-03-03T10:00:00",
                                      'oauth_token': "old token"}})
    generate_token_mock = mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    assert generate_token_mock.called
    assert client.access_token != "old token"


@pytest.mark.parametrize("return_val", ({'token_info': {}}, {'token_info': {'generation_time': None}}))
def test_get_oauth_token___old_token_is_unreachable(mocker, return_val):
    """
        Given -
           client
        When -
            asking for a token when the previous token is unreachable
        Then -
            Validate that a func that creates a new token has been called
            Validate that a new token was stored in the get_integration_context dict.
    """
    mocker.patch.object(Zoom_IAM, "get_integration_context",
                        return_value=return_val)
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


def test_check_authentication_type_arguments__with_extra_jwt_member(mocker):
    """
        Given -
           client
        When -
            creating a client with an extra authentication type argument
        Then -
            Validate that the error wil raise as excepted
    """
    with pytest.raises(DemistoException) as e:
        Zoom_IAM.check_authentication_type_arguments(account_id="mockaccount",
                                                     client_id="mockclient", client_secret="mocksecret",
                                                     api_key="blabla", api_secret="")
    assert e.value.message == """Too many fields were filled.
                                   You should fill the Account ID, Client ID, and Client Secret fields (OAuth),
                                   OR the API Key and API Secret fields (JWT - Deprecated)"""


def test_check_authentication_type_arguments__with_extra_AOuth_member(mocker):
    """
        Given -
           client
        When -
            creating a client with an extra authentication type argument
        Then -
            Validate that the error wil raise as excepted
    """
    with pytest.raises(DemistoException) as e:
        Zoom_IAM.check_authentication_type_arguments(account_id="",
                                                     client_id="", client_secret="mocksecret",
                                                     api_key="blabla", api_secret="ertert")
    assert e.value.message == """Too many fields were filled.
                                   You should fill the Account ID, Client ID, and Client Secret fields (OAuth),
                                   OR the API Key and API Secret fields (JWT - Deprecated)"""


def test_test_moudle__reciving_errors(mocker):
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(Client, "test", side_effect=DemistoException('Invalid access token'))

    from Zoom_IAM import test_module
    assert test_module(client=client) == 'Invalid credentials. Please verify that your credentials are valid.'


def test_test_moudle__reciving_errors_1(mocker):
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(Client, "test", side_effect=DemistoException("The Token's Signature resulted invalid"))

    from Zoom_IAM import test_module
    assert test_module(client=client) == 'Invalid API Secret. Please verify that your API Secret is valid.'


def test_test_moudle__reciving_errors_2(mocker):
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(Client, "test", side_effect=DemistoException("Invalid client_id or client_secret"))

    from Zoom_IAM import test_module
    assert test_module(client=client) == 'Invalid Client ID or Client Secret. Please verify that your ID and Secret is valid.'


def test_test_moudle__reciving_errors_3(mocker):
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(Client, "test", side_effect=DemistoException("mockerror"))

    from Zoom_IAM import test_module
    assert test_module(client=client) == 'Problem reaching Zoom API, check your credentials. Error message: mockerror'


def test_http_request___when_raising_invalid_token_message(mocker):
    """
  Given -
     client
  When -
      asking for a connection when the first try fails, and return an
      'Invalid access token' error messoge
  Then -
      Validate that a retry to connect with a new token has been done
    """

    m = mocker.patch.object(Zoom_IAM.BaseClient, "_http_request",
                            side_effect=DemistoException('Invalid access token'))
    generate_token_mock = mocker.patch.object(Client, "generate_oauth_token", return_value="mock")
    mocker.patch.object(Zoom_IAM, "get_integration_context",
                        return_value={'token_info': {"generation_time": "1988-03-03T10:50:00",
                                      'oauth_token': "old token"}})
    try:
        client = Client(base_url='https://test.com', account_id="mockaccount",
                        client_id="mockclient", client_secret="mocksecret")
        # a command that uses http_request
        client.test()
    except Exception:
        pass
    assert m.call_count == 2
    assert generate_token_mock.called
