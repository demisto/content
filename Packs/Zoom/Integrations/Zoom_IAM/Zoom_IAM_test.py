from Zoom_IAM import Client
from IAMApiModule import *
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


def test_get_error_details():
    """
    Given:
        - An error response from the API
    When:
        - Calling function get_error_details
    Then:
        - Ensure the error details are returned as expected
    """
    from Zoom_IAM import get_error_details
    assert get_error_details({"code": "mock", "message": "mockerror"}) == "mock: mockerror"


@pytest.mark.parametrize('returned, expected', [(None, 'NoneType'),
                                                ({'users': None}, 'IAMUserAppData')])
def test_get_user(mocker, returned, expected):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an email of a user
    When:
        - Calling function get_user
            1. results is None
            2. results is a dict with 'users' key is None
    Then:
        - Ensure the user profile is returned as expected
    """
    client = mock_client_ouath(mocker)
    args = {'user-profile': {'email': 'blabla'}}
    mocker.patch.object(client, 'error_handled_http_request', return_value=returned)
    res = client.get_user(client, args)
    assert expected == type(res).__name__


def test_test_moudle(mocker):
    """
    Given:
        - An app client object
    When:
        - Calling function test_module
    Then:
        - Ensure the test module is returned as expected
    """
    client = mock_client_ouath(mocker)
    mocker.patch.object(Client, "get_user")
    from Zoom_IAM import test_module
    res = test_module(client)
    assert res == "ok"
