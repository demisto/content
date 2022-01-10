import requests_mock
from ClarizenIAM import Client, main
from IAMApiModule import *
import pytest
APP_USER_OUTPUT = {
    'id': '/User/1234',
    'username': 'mock_user_name',
    'first_name': 'mock_first_name',
    'last_name': 'mock_last_name',
    'state': {'id': '/State/Active'},
    'email': 'emploee@paloaltonetworks.com',
}

APP_DISABLED_USER_OUTPUT = {
    'id': '/User/1234',
    'username': 'mock_user_name',
    'first_name': 'mock_first_name',
    'last_name': 'mock_last_name',
    'state': {'id': '/State/Disabled'},
    'email': 'emploee@paloaltonetworks.com',
}

BASE_URL = 'https://test.com'


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


class TestGetUserCommand:
    @pytest.fixture(autouse=True)
    def setup(self, mocker) -> None:
        mocker.patch.object(Client, 'get_session_id', return_value='SessionID')
        mocker.patch.object(Client, 'get_manager_id', return_value='')
        mocker.patch.object(Client, 'get_app_fields', return_value={})
        self.client = Client(base_url=BASE_URL, headers={})

    def test_existing_user(self):
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
        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            }
        }

        with requests_mock.Mocker() as m:
            m.post(f'{BASE_URL}/data/findUserQuery', json={'entities': [{'id': '/User/1234'}]})
            m.get(f'{BASE_URL}/data/objects/User/1234', json=APP_USER_OUTPUT)

            user_profile = IAMCommand().get_user(self.client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == '1234'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'

    def test_non_existing_user(self):
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
        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            }
        }

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', json={})

            user_profile = IAMCommand().get_user(self.client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is False
        assert outputs.get('errorCode') == IAMErrors.USER_DOES_NOT_EXIST[0]
        assert outputs.get('errorMessage') == IAMErrors.USER_DOES_NOT_EXIST[1]

    def test_get_bad_response(self, mocker):
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
        mocker.patch.object(demisto, 'error')

        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            }
        }

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', status_code=500, json={'error': {'message': 'INTERNAL SERVER ERROR'}})

            user_profile = IAMCommand().get_user(self.client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is False
        assert outputs.get('errorCode') == 500
        assert "INTERNAL SERVER ERROR: {'error': {'message': 'INTERNAL SERVER ERROR'}}" in outputs.get('errorMessage')


class TestCreateUserCommand:
    @pytest.fixture(autouse=True)
    def setup(self, mocker) -> None:
        mocker.patch.object(Client, 'get_session_id', return_value='SessionID')
        mocker.patch.object(Client, 'get_manager_id', return_value='')
        mocker.patch.object(Client, 'get_app_fields', return_value={})
        self.client = Client(base_url=BASE_URL, headers={})

    def test_success(self):
        """
        Given:
            - An app client object
            - A user-profile argument that contains an email of a non-existing user in the application
        When:
            - Calling function create_user_command
        Then:
            - Ensure a User Profile object with the user data is returned
        """
        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            }
        }

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', json={})  # Get user by email (check if there is a user before creating it)
            m.put('/data/objects/User', json={'id': '/User/1234'})  # Create user
            m.get('/data/objects/User/1234', json=APP_USER_OUTPUT)  # Get user by id (after creating the user)

            user_profile = IAMCommand().create_user(self.client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.CREATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == '1234'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'

    def test_user_already_exists(self):
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
        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            },
            'allow-enable': 'false',
        }

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', json={'entities': [{'id': '/User/1234'}]})
            m.get('/data/objects/User/1234', json=APP_DISABLED_USER_OUTPUT)
            m.post('/data/objects/User/1234', json=APP_DISABLED_USER_OUTPUT)

            user_profile = IAMCommand().create_user(self.client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is False
        assert outputs.get('id') == '1234'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


class TestUpdateUserCommand:
    @pytest.fixture(autouse=True)
    def setup(self, mocker) -> None:
        mocker.patch.object(Client, 'get_session_id', return_value='SessionID')
        mocker.patch.object(Client, 'get_manager_id', return_value='')
        mocker.patch.object(Client, 'get_app_fields', return_value={})
        self.client = Client(base_url=BASE_URL, headers={})

    def test_non_existing_user(self):
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
        args = {'user-profile': {'email': 'emploee@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', json={})
            m.put('/data/objects/User', json={'id': '/User/1234'})
            m.get('/data/objects/User/1234', json=APP_USER_OUTPUT)

            user_profile = IAMCommand(create_if_not_exists=True).update_user(self.client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.CREATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == '1234'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'

    def test_command_is_disabled(self):
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
        args = {'user-profile': {'email': 'emploee@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

        user_profile = IAMCommand(is_update_enabled=False).update_user(self.client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('skipped') is True
        assert outputs.get('reason') == 'Command is disabled.'

    def test_allow_enable(self):
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
        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            },
            'allow-enable': 'true',
        }

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', json={'entities': [{'id': '/User/1234'}]})
            m.get('/data/objects/User/1234', json=APP_USER_OUTPUT)
            m.post('/data/objects/User/1234', json=APP_USER_OUTPUT)

            user_profile = IAMCommand().update_user(self.client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == '1234'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


class TestDisableUserCommand:
    @pytest.fixture(autouse=True)
    def setup(self, mocker) -> None:
        mocker.patch.object(Client, 'get_session_id', return_value='SessionID')
        mocker.patch.object(Client, 'get_manager_id', return_value='')
        mocker.patch.object(Client, 'get_app_fields', return_value={})
        self.client = Client(base_url=BASE_URL, headers={})

    def test_success(self):
        """
        Given:
            - An app client object
            - A user-profile argument that contains an email of a user
        When:
            - Calling function disable_user_command
        Then:
            - Ensure that the command is successful and the user is disabled
        """
        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            }
        }

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', json={'entities': [{'id': '/User/1234'}]})
            m.get('/data/objects/User/1234', json=APP_DISABLED_USER_OUTPUT)
            m.post('/data/lifecycle', json={})

            user_profile = IAMCommand().disable_user(self.client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.DISABLE_USER
        assert outputs.get('skipped')
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'

    def test_non_existing_user(self):
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
        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            }
        }

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', json={})

            user_profile = IAMCommand().disable_user(self.client, args)

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
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://test.com'})
    mocker.patch.object(demisto, 'command', return_value='get-mapping-fields')
    mock_result = mocker.patch('ClarizenIAM.return_results')

    schema = {
        'entityDescriptions': [
            {
                'fields': [
                    {'name': 'field1', 'label': 'desc1'},
                    {'name': 'field2', 'label': 'desc2'},
                ]
            }
        ]
    }

    mocker.patch.object(Client, 'get_session_id', return_value='SessionID')
    mocker.patch.object(Client, 'get_manager_id', return_value='')
    with requests_mock.Mocker() as m:
        m.get('https://test.com/V2.0/services/metadata/describeEntities', json=schema)
        main()

    mapping = mock_result.call_args.args[0].extract_mapping()

    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field1') == 'desc1'
    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field2') == 'desc2'
