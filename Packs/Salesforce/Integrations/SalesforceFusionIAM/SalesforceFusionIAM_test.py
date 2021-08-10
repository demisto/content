from requests import Response, Session
from SalesforceFusionIAM import Client, get_mapping_fields
from IAMApiModule import *
import requests_mock

URI_PREFIX = '/services/data/v51.0/'

APP_USER_OUTPUT = {
    "id": "mock_id",
    "Work_Email__c": "mock_user_name",
    "userName": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "true",
    "email": "testdemisto@paloaltonetworks.com"
}

# USER_APP_DATA = IAMUserAppData("mock_id", "mock_user_name", is_active=True, app_data=APP_USER_OUTPUT)

APP_DISABLED_USER_OUTPUT = {
    "id": "mock_id",
    "Work_Email__c": "mock_user_name",
    "userName": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "false",
    "email": "testdemisto@paloaltonetworks.com"
}

APP_UPDATED_USER_OUTPUT = {
    "id": "mock_id",
    "Work_Email__c": "mock_update_user_name",
    "userName": "mock_update_user_name",
    "first_name": "mock_update_first_name",
    "last_name": "mock_update_last_name",
    "active": "false",
    "email": "testdemisto@paloaltonetworks.com"
}

DISABLED_USER_APP_DATA = IAMUserAppData("mock_id", "mock_user_name", is_active=False, app_data=APP_DISABLED_USER_OUTPUT)

demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}


def mock_client():
    client = Client(base_url='https://test.com')
    return client


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


class TestCRUDCommands:
    def test_get_user_command__existing_user(self, mocker):
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
        args = {'user-profile': {'email': 'testdemisto@paloaltonetworks.com'}}

        mocker.patch.object(IAMUserProfile, 'update_with_app_data', return_value={})

        with requests_mock.Mocker() as m:
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json=APP_USER_OUTPUT)
            m.get(f'{URI_PREFIX}parameterizedSearch/', json={"searchRecords": [{"Id": "mock_id"}]})

            user_profile = IAMCommand().get_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
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
        client = mock_client()
        args = {'user-profile': {'email': 'testdemisto@paloaltonetworks.com'}}

        with requests_mock.Mocker() as m:
            m.get(f'{URI_PREFIX}parameterizedSearch/', json={})

            user_profile = IAMCommand().get_user(client, args)

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
        client = mock_client()

        args = {'user-profile': {'email': 'testdemisto@paloaltonetworks.com'}}
        error_msg = {"detail": "something has gone wrong on the website's server", "message": "INTERNAL SERVER ERROR"}
        mocker.patch.object(demisto, 'error')

        with requests_mock.Mocker() as m:
            m.get(f'{URI_PREFIX}parameterizedSearch/', status_code=500, json=error_msg)

            user_profile = IAMCommand().get_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is False
        assert outputs.get('errorCode') == 500
        assert outputs.get('errorMessage') == 'INTERNAL SERVER ERROR: something has gone wrong on the website\'s server'

    def test_create_user_command__success(self, mocker):
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
        args = {'user-profile': {'email': 'testdemisto@paloaltonetworks.com'}}

        with requests_mock.Mocker() as m:
            # User does not exist
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json={})
            m.get(f'{URI_PREFIX}parameterizedSearch/', json={})
            # Create the user
            m.post(f'{URI_PREFIX}sobjects/FF__Key_Contact__c', json=APP_USER_OUTPUT)

            user_profile = IAMCommand().create_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.CREATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'

    def test_create_user_command__user_already_exists(self, mocker):
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
        args = {'user-profile': {'email': 'testdemisto@paloaltonetworks.com'}}

        with requests_mock.Mocker() as m:
            # User already exist
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json=APP_UPDATED_USER_OUTPUT)
            m.get(f'{URI_PREFIX}parameterizedSearch/', json={"searchRecords": [{"Id": "mock_id"}]})
            # Update the user
            m.post(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json={})

            user_profile = IAMCommand().create_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
        # The updated user output
        assert outputs.get('username') == 'mock_update_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_update_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_update_last_name'

    def test_update_user_command__non_existing_user(self, mocker):
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
        args = {'user-profile': {'email': 'testdemisto@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

        with requests_mock.Mocker() as m:
            # User does not exist
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json={})
            m.get(f'{URI_PREFIX}parameterizedSearch/', json={})
            # The create user endpoint
            m.post(f'{URI_PREFIX}sobjects/FF__Key_Contact__c', json=APP_USER_OUTPUT)
            # The update user endpoint
            m.post(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json={})

            user_profile = IAMCommand(create_if_not_exists=True).update_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.CREATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_last_name'

    def test_update_user_command__command_is_disabled(self, mocker):
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
        args = {'user-profile': {'email': 'testdemisto@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

        user_profile = IAMCommand(is_update_enabled=False).update_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('skipped') is True
        assert outputs.get('reason') == 'Command is disabled.'

    def test_update_user_command__allow_enable(self, mocker):
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
        args = {'user-profile': {'email': 'testdemisto@paloaltonetworks.com', 'givenname': 'mock_first_name'},
                'allow-enable': 'true'}

        with requests_mock.Mocker() as m:
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json=APP_UPDATED_USER_OUTPUT)
            m.get(f'{URI_PREFIX}parameterizedSearch/', json={"searchRecords": [{"Id": "mock_id"}]})
            m.post(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json={})

            user_profile = IAMCommand().update_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
        assert outputs.get('username') == 'mock_update_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_update_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_update_last_name'

    def test_disable_user_command__non_existing_user(self, mocker):
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
        args = {'user-profile': {'email': 'testdemisto@paloaltonetworks.com'}}

        with requests_mock.Mocker() as m:
            # User does not exist
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json={})
            m.get(f'{URI_PREFIX}parameterizedSearch/', json={})

            user_profile = IAMCommand().disable_user(client, args)

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
        client = mock_client()
        schema = {
            'result': [
                {'name': 'field1', 'label': 'desc1'},
                {'name': 'field2', 'label': 'desc2'},
            ]
        }
        with requests_mock.Mocker() as m:
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/describe/', json=schema)

            mapping_response = get_mapping_fields(client)

        mapping = mapping_response.extract_mapping()

        assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field1') == 'desc1'
        assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field2') == 'desc2'
