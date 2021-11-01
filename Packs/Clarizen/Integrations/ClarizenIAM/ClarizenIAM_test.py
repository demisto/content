import requests_mock
from ClarizenIAM import Client, main
from IAMApiModule import *

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


def mock_client():
    client = Client(base_url='https://test.com', auth=('testdemisto', '123456'))
    return client


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


class TestGetUserCommand:
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
        client = mock_client()
        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            }
        }

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', json={'entities': [{'id': '/User/1234'}]})
            m.get('/data/objects/User/1234', json=APP_USER_OUTPUT)

            user_profile = IAMCommand().get_user(client, args)

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
        client = mock_client()
        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            }
        }

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', json={})

            user_profile = IAMCommand().get_user(client, args)

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
        import demistomock as demisto
        mocker.patch.object(demisto, 'error')

        client = mock_client()
        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            }
        }

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', status_code=500, json={'error': {'message': 'INTERNAL SERVER ERROR'}})

            user_profile = IAMCommand().get_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is False
        assert outputs.get('errorCode') == 500
        assert outputs.get('errorMessage') == "INTERNAL SERVER ERROR: {'error': {'message': 'INTERNAL SERVER ERROR'}}"


class TestCreateUserCommand:
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
        client = mock_client()
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

            user_profile = IAMCommand().create_user(client, args)

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
        client = mock_client()
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

            user_profile = IAMCommand().create_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is False
        assert outputs.get('id') == '1234'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


class TestUpdateUserCommand:
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
        client = mock_client()
        args = {'user-profile': {'email': 'emploee@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', json={})
            m.put('/data/objects/User', json={'id': '/User/1234'})
            m.get('/data/objects/User/1234', json=APP_USER_OUTPUT)

            user_profile = IAMCommand(create_if_not_exists=True).update_user(client, args)

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
        client = mock_client()
        args = {'user-profile': {'email': 'emploee@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

        user_profile = IAMCommand(is_update_enabled=False).update_user(client, args)

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
        client = mock_client()
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

            user_profile = IAMCommand().update_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == '1234'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'


class TestDisableUserCommand:
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
        client = mock_client()
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

            user_profile = IAMCommand().disable_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.DISABLE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is False
        assert outputs.get('id') == '1234'
        assert outputs.get('username') == 'mock_user_name'
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
        client = mock_client()
        args = {
            'user-profile': {
                'email': 'emploee@paloaltonetworks.com',
                'manageremailaddress': 'manager@paloaltonetworks.com',
            }
        }

        with requests_mock.Mocker() as m:
            m.post('/data/findUserQuery', json={})

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
    import demistomock as demisto
    mocker.patch.object(demisto, 'params', return_value={'url': 'https://test.com'})
    mocker.patch.object(demisto, 'command', return_value='get-mapping-fields')
    mock_result = mocker.patch('ClarizenIAM.return_results')

    schema = {
        'entityDescriptions': {
            'fields': [
                {'name': 'field1', 'label': 'desc1'},
                {'name': 'field2', 'label': 'desc2'},
            ]
        }
    }

    with requests_mock.Mocker() as m:
        m.get('https://test.com/V2.0/services/metadata/describeEntities', json=schema)

        main()

    mapping = mock_result.call_args.args[0].extract_mapping()

    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field1') == 'desc1'
    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field2') == 'desc2'
