import requests_mock
from OracleIAM import Client, main
from IAMApiModule import *

APP_USER_OUTPUT = {
    "id": "123456",
    "userName": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "true",
    "email": "test@test.com"
}

APP_DISABLED_USER_OUTPUT = {
    "id": "123456",
    "userName": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "false",
    "email": "test@test.com"
}

APP_UPDATED_USER_OUTPUT = {
    "id": "123456",
    "userName": "new_mock_user_name",
    "first_name": "new_mock_first_name",
    "last_name": "new_mock_last_name",
    "active": "true",
    "email": "new_test@test.com"

}


def mock_client():
    client = Client(base_url='https://test.com', headers={})
    return client


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


class TestOracleIAM:
    def test_get_user_command__existing_user(self):
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

        with requests_mock.Mocker() as m:
            m.post('https://test.com/oauth2/v1/token', json={})
            m.get('https://test.com/admin/v1/Users?filter=userName eq "mock_user_name"',
                  json={'Resources': [{'id': '123456'}]})
            m.get('https://test.com/admin/v1/Users/123456', json=APP_USER_OUTPUT)

            client = mock_client()
            args = {'user-profile': {'username': 'mock_user_name'}}
            user_profile = IAMCommand(attr='username').get_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is True
        assert outputs.get('active') == 'true'
        assert outputs.get('id') == '123456'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'

    def test_get_user_command__non_existing_user(self):
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
        with requests_mock.Mocker() as m:
            m.post('https://test.com/oauth2/v1/token', json={})
            m.get('https://test.com/admin/v1/Users?filter=userName eq "mock_user_name"',
                  json={'Resources': []})

            client = mock_client()
            args = {'user-profile': {'username': 'mock_user_name'}}
            user_profile = IAMCommand(attr='username').get_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is False
        assert outputs.get('errorCode') == IAMErrors.USER_DOES_NOT_EXIST[0]
        assert outputs.get('errorMessage') == IAMErrors.USER_DOES_NOT_EXIST[1]

    def test_get_user_command__bad_response(self, mocker):
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

        with requests_mock.Mocker() as m:
            m.post('https://test.com/oauth2/v1/token', json={})
            m.get('https://test.com/admin/v1/Users?filter=userName eq "mock_user_name"', status_code=500,
                  json={"detail": "INTERNAL SERVER ERROR"})

            client = mock_client()
            args = {'user-profile': {'username': 'mock_user_name'}}
            user_profile = IAMCommand(attr='username').get_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is False
        assert outputs.get('errorCode') == 500
        assert outputs.get('errorMessage') == 'INTERNAL SERVER ERROR'

    def test_create_user_command__success(self):
        """
        Given:
            - An app client object
            - A user-profile argument that contains an email of a non-existing user in the application
        When:
            - Calling function create_user_command
        Then:
            - Ensure a User Profile object with the user data is returned
        """
        with requests_mock.Mocker() as m:
            m.post('https://test.com/oauth2/v1/token', json={})
            m.get('https://test.com/admin/v1/Users?filter=userName eq "mock_user_name"', json={'Resources': []})
            m.post('https://test.com/admin/v1/Users', json=APP_USER_OUTPUT)

            client = mock_client()
            args = {'user-profile': {'username': 'mock_user_name'}}
            user_profile = IAMCommand(attr='username').create_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.CREATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') == 'true'
        assert outputs.get('id') == '123456'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'

    def test_create_user_command__user_already_exists(self):
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
        with requests_mock.Mocker() as m:
            m.post('https://test.com/oauth2/v1/token', json={})
            m.get('https://test.com/admin/v1/Users?filter=userName eq "mock_user_name"',
                  json={'Resources': [{'id': '123456'}]})
            m.get('https://test.com/admin/v1/Users/123456', json=APP_DISABLED_USER_OUTPUT)
            m.patch('https://test.com/admin/v1/Users/123456', json=APP_DISABLED_USER_OUTPUT)

            client = mock_client()
            args = {'user-profile': {'username': 'mock_user_name'}}
            user_profile = IAMCommand(attr='username').create_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') == 'false'
        assert outputs.get('id') == '123456'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'

    def test_update_user_command__non_existing_user(self):
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
        with requests_mock.Mocker() as m:
            m.post('https://test.com/oauth2/v1/token', json={})
            m.get('https://test.com/admin/v1/Users?filter=userName eq "mock_user_name"', json={'Resources': []})
            m.post('https://test.com/admin/v1/Users', json=APP_USER_OUTPUT)

            client = mock_client()
            args = {'user-profile': {'username': 'mock_user_name'}}
            user_profile = IAMCommand(create_if_not_exists=True, attr='username').update_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.CREATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') == 'true'
        assert outputs.get('id') == '123456'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'

    def test_update_user_command__command_is_disabled(self):
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
        with requests_mock.Mocker() as m:
            m.post('https://test.com/oauth2/v1/token', json={})

            client = mock_client()
            args = {'user-profile': {'username': 'mock_user_name'}}
            user_profile = IAMCommand(is_update_enabled=False, attr='username').update_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('skipped') is True
        assert outputs.get('reason') == 'Command is disabled.'

    def test_update_user_command__allow_enable(self):
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
        with requests_mock.Mocker() as m:
            m.post('https://test.com/oauth2/v1/token', json={})
            m.get('https://test.com/admin/v1/Users?filter=userName eq "mock_user_name"',
                  json={'Resources': [{'id': '123456'}]})
            m.get('https://test.com/admin/v1/Users/123456', json=APP_USER_OUTPUT)
            m.patch('https://test.com/admin/v1/Users/123456', json=APP_UPDATED_USER_OUTPUT)

            client = mock_client()
            args = {'user-profile': {'username': 'mock_user_name'}, 'allow-enable': 'true'}
            user_profile = IAMCommand(attr='username').update_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') == 'true'
        assert outputs.get('id') == '123456'
        assert outputs.get('username') == 'new_mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'new_mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'new_mock_last_name'

    def test_disable_user_command__non_existing_user(self):
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
        with requests_mock.Mocker() as m:
            m.post('https://test.com/oauth2/v1/token', json={})
            m.get('https://test.com/admin/v1/Users?filter=userName eq "mock_user_name"', json={'Resources': []})

            client = mock_client()
            args = {'user-profile': {'username': 'mock_user_name'}}
            user_profile = IAMCommand(attr='username').disable_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.DISABLE_USER
        assert outputs.get('success') is True
        assert outputs.get('skipped') is True
        assert outputs.get('reason') == IAMErrors.USER_DOES_NOT_EXIST[1]

    def test_get_mapping_fields_command(self, mocker):
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
        mocker.patch.object(demisto, 'command', return_value='get-mapping-fields')
        mocker.patch.object(demisto, 'params', return_value={'url': 'https://test.com'})
        mock_result = mocker.patch('OracleIAM.return_results')

        schema = {
            'attributes': [
                {'name': 'field1', 'description': 'desc1'},
                {'name': 'field2', 'description': 'desc2'},
            ]
        }

        with requests_mock.Mocker() as m:
            m.post('https://test.com/oauth2/v1/token', json={})
            m.get('https://test.com/admin/v1/Schemas/urn:ietf:params:scim:schemas:core:2.0:User', json=schema)

            main()

        mapping = mock_result.call_args.args[0].extract_mapping()

        assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field1') == 'desc1'
        assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field2') == 'desc2'
