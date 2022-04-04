from requests import Response, Session
from LenelIAM import Client, get_mapping_fields
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


def mock_client(mocker):
    mocker.patch.object(Client, 'get_client_token', return_value=None)
    client = Client(base_url='https://test.com', username='mock_username', version='1.0', password='mock_password')
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
    client = mock_client(mocker)
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
    client = mock_client(mocker)
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)

    user_profile = IAMCommand().get_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == IAMErrors.USER_DOES_NOT_EXIST[0]
    assert outputs.get('errorMessage') == IAMErrors.USER_DOES_NOT_EXIST[1]


def test_get_user_command__bad_response(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains an email of a non-existing user in the application
    When:
        - Calling function get_user_command
        - A bad response (500) is returned from the application API
    Then:
        - Ensure the resulted User Profile object holds information about the bad response.
    """
    import demistomock as demisto

    client = mock_client(mocker)
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    bad_response = Response()
    bad_response.status_code = 500
    bad_response._content = b'{"error": {"detail": "details", "message": "message"}}'

    mocker.patch.object(demisto, 'error')
    mocker.patch.object(Session, 'request', return_value=bad_response)

    user_profile = IAMCommand().get_user(client, args)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == 500
    assert outputs.get('errorMessage') == 'message: details'


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
    client = mock_client(mocker)
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'create_user', return_value=USER_APP_DATA)

    user_profile = IAMCommand().create_user(client, args)
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
    client = mock_client(mocker)
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
    client = mock_client(mocker)
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

    mocker.patch.object(client, 'get_user', return_value=None)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
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
    client = mock_client(mocker)
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


def test_update_user_command__allow_enable(mocker):
    """
    Given:
        - An app client object
        - A user-profile argument that contains user data
    When:
        - The user is disabled in the application
        - allow-enable argument is true
        - Calling function update_user_command
    Then:
        - Ensure the user is enabled at the end of the command execution.
    """
    client = mock_client(mocker)
    args = {'user-profile': {'email': 'testdemisto2@paloaltonetworks.com', 'givenname': 'mock_first_name'},
            'allow-enable': 'true'}

    mocker.patch.object(client, 'get_user', return_value=DISABLED_USER_APP_DATA)
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'update_user', return_value=USER_APP_DATA)

    user_profile = IAMCommand().update_user(client, args)
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
        - An app client object
        - A user-profile argument that contains an email of a user
    When:
        - create-if-not-exists parameter is unchecked
        - The user does not exist in the application
        - Calling function disable_user_command
    Then:
        - Ensure the command is considered successful and skipped
    """
    client = mock_client(mocker)
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
    client = mock_client(mocker)
    mocker.patch.object(client, 'get_app_fields', return_value={'field1': 'desc1', 'field2': 'desc2'})

    mapping_response = get_mapping_fields(client)
    mapping = mapping_response.extract_mapping()

    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field1') == 'desc1'
    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field2') == 'desc2'


def test_get_cardholder():
    res = Client.get_cardholder('ID', 'test_id')
    assert res == 'ID=test_id'


def test_client_get_user(mocker):
    mock_res = {
        "count": 1,
        "item_list": [
            {
                "property_value_map": {
                    "ACTIVE__XR": False,
                    "ADDRESS": "3rd Floor, Office 305",
                    "ALLOWEDVISITORS": True,
                    "CITY": "Rome",
                    "COMPANY": 0,
                    "COUNTRY": 0,
                    "COUNTRYCODE": 0,
                    "COUNTRY__XR": "Italy",
                    "EMAIL": "test@paloaltonetworks.com",
                    "ID": 11111,
                    "LASTCHANGED": "2021-10-27T00:10:32-07:00",
                    "LASTNAME": "test last name",
                    "REGION": 0,
                    "SSNO": "00001",
                }
            },
        ]
    }

    client = mock_client(mocker)
    mocker.patch.object(client, '_http_request', return_value=mock_res)
    user = client.get_user('email', 'test@paloaltonetworks.com')
    assert user.id == 11111
    assert not user.is_active
    assert not user.username


def test_client_create_user(mocker):
    mock_res = {
        "property_value_map": {
            "ID": 11111
        },
        "type_name": "Lnl_Cardholder",
        "version": "1.0"
    }
    mock_param = {'ADDRESS': '3rd Floor, Office 305', 'CITY': 'Venice', 'COUNTRYCODE__XR': 'IT', 'COUNTRY__XR': 'Italy',
                  'EMAIL': 'test@paloaltonetworks.com', 'FIRSTNAME': 'test', 'HIREDATE': '04/01/2021',
                  'LASTNAME': 'test2', 'SSNO': '00013', 'STATE': 'Venice',
                  'TITLE': 'Major Account Manager Public Sector - Italy', 'TYPE__XR': 'Regular',
                  'USERNAME': 'test@paloaltonetworks.com', 'ZIPCODE': '00144'}

    client = mock_client(mocker)
    mocker.patch.object(client, '_http_request', return_value=mock_res)
    user = client.create_user(mock_param)
    assert user.id == 11111
    assert user.is_active
    assert user.username == 'test@paloaltonetworks.com'


update_mock_res = {
    "property_value_map": {
        "ID": 11111
    },
    "type_name": "Lnl_Cardholder",
    "version": "1.0"
}
get_mock_res = {"count": 1, "item_list": [
    {
        "property_value_map": {
            "ACTIVE__XR": None,
            "ADDRESS": "6rd Floor, Office 305",
            "ALLOWEDVISITORS": True,
            "CITY": "Rome",
            "COMPANY": 0,
            "COUNTRY": 0,
            "COUNTRYCODE": 0,
            "COUNTRY__XR": "Italy",
            "EMAIL": "test@paloaltonetworks.com",
            "ID": 11111,
            "LASTCHANGED": "2021-10-27T00:10:32-07:00",
            "LASTNAME": "test last name",
            "REGION": 0,
            "SSNO": "00001",
        }
    },
]}


def http_request_side_effect(**args):
    user_active_status = args['json_data']['property_value_map']['ACTIVE__XR'] if 'json_data' in args else None
    if user_active_status is True:
        get_mock_res['item_list'][0]['property_value_map']['ACTIVE__XR'] = 'true'
    elif user_active_status is False:
        get_mock_res['item_list'][0]['property_value_map']['ACTIVE__XR'] = 'false'

    if args['method'] == 'GET':
        return get_mock_res
    else:
        return update_mock_res


def test_client_update_user(mocker):
    user_id = 11111
    user_data = {'ACTIVE__XR': 'true', 'ADDRESS': '6rd Floor, Office 305', 'CITY': 'Venice', 'COUNTRYCODE__XR': 'IT',
                 'COUNTRY__XR': 'Italy', 'EMAIL': 'test@paloaltonetworks.com', 'FIRSTNAME': 'test', 'HIREDATE': '04/01/2021',
                 'LASTNAME': 'test2', 'SSNO': '00013', 'STATE': 'Venice',
                 'TITLE': 'Major Account Manager Public Sector - Italy', 'TYPE__XR': 'Regular',
                 'USERNAME': 'test@paloaltonetworks.com', 'ZIPCODE': '00144'}

    client = mock_client(mocker)
    mocker.patch.object(client, '_http_request', side_effect=http_request_side_effect)
    user = client.update_user(user_id, user_data)
    assert user.id == 11111
    assert user.full_data['ADDRESS'] == '6rd Floor, Office 305'


def test_client_enable_user(mocker):
    user_id = 11111
    client = mock_client(mocker)
    mocker.patch.object(client, '_http_request', side_effect=http_request_side_effect)
    user = client.enable_user(user_id)
    assert user.id == 11111
    assert user.is_active is True


def test_client_disable_user(mocker):
    user_id = 11111
    client = mock_client(mocker)
    mocker.patch.object(client, '_http_request', side_effect=http_request_side_effect)
    mocker.patch.object(client, 'get_badges', return_value={})

    user = client.disable_user(user_id)
    assert user.id == 11111
    assert user.is_active is False


def test_client_disable_user_and_badges(mocker):
    user_id = 11111
    client = mock_client(mocker)
    mocker.patch.object(client, '_http_request', side_effect=http_request_side_effect)
    mocker.patch.object(client, 'get_badges', return_value={
        'item_list': [{
            'property_value_map': {
                'BADGEKEY': 'mock_badge_key'
            }
        }]
    })
    mocker.patch.object(client, 'deactivate_badge', return_value={'info': 'badge was deactivated'})
    info = mocker.patch.object(demisto, 'info')
    user = client.disable_user(user_id)
    assert user.id == 11111
    assert user.is_active is False
    assert info.call_args.args[0] == 'Deactivated badge for user: 11111. Badge Key: mock_badge_key'


def test_client_disable_user_and_badges_faliure(mocker):
    user_id = 11111
    client = mock_client(mocker)
    mocker.patch.object(client, '_http_request', side_effect=http_request_side_effect)
    mocker.patch.object(client, 'get_badges', return_value={
        'item_list': [{
            'property_value_map': {
                'BADGEKEY': 'mock_badge_key'
            }
        }]
    })
    mocker.patch.object(client, 'deactivate_badge', return_value={})
    info = mocker.patch.object(demisto, 'error')
    user = client.disable_user(user_id)
    assert user.id == 11111
    assert user.is_active is False
    assert 'Failed to deactivate badge for user' in info.call_args.args[0]
