from SalesforceFusionIAM import Client, main
from IAMApiModule import *
import requests_mock

URI_PREFIX = '/services/data/v51.0/'

APP_USER_OUTPUT = {
    "id": "mock_id",
    "Work_Email__c": "mock_user_name",
    "Name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "true",
    "email": "testdemisto@paloaltonetworks.com"
}

APP_DISABLED_USER_OUTPUT = {
    "id": "mock_id",
    "Work_Email__c": "mock_user_name",
    "Name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "false",
    "email": "testdemisto@paloaltonetworks.com"
}

APP_UPDATED_USER_OUTPUT = {
    "id": "mock_id",
    "Work_Email__c": "mock_update_user_name",
    "Name": "mock_update_user_name",
    "first_name": "mock_update_first_name",
    "last_name": "mock_update_last_name",
    "active": "false",
    "email": "testdemisto@paloaltonetworks.com"
}


def mock_client():
    client = Client(base_url='https://test.com')
    return client


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


class TestSalesforceFusionIAM:
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
        args = {'user-profile': {'Work_Email__c': 'testdemisto@paloaltonetworks.com'}}

        mocker.patch.object(IAMUserProfile, 'update_with_app_data', return_value={})

        with requests_mock.Mocker() as m:
            m.post('https://test.com/services/oauth2/token?grant_type=password', json={})
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json=APP_USER_OUTPUT)
            m.get(
                f'{URI_PREFIX}parameterizedSearch?q=testdemisto@paloaltonetworks.com&sobject=FF__Key_Contact__c'
                f'&FF__Key_Contact__c.where=Work_Email__c=%27testdemisto@paloaltonetworks.com%27'
                f'&FF__Key_Contact__c.fields=Id, FF__First_Name__c, FF__Last_Name__c, Work_Email__c, Name',
                json={"searchRecords": [{"Id": "mock_id"}]}
            )

            client = mock_client()
            user_profile = IAMCommand(get_user_iam_attrs=['Work_Email__c']).get_user(client, args)

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
        args = {'user-profile': {'Work_Email__c': 'testdemisto@paloaltonetworks.com'}}

        with requests_mock.Mocker() as m:
            m.post('https://test.com/services/oauth2/token?grant_type=password', json={})
            m.get(
                f'{URI_PREFIX}parameterizedSearch?q=testdemisto@paloaltonetworks.com&sobject=FF__Key_Contact__c'
                f'&FF__Key_Contact__c.where=Work_Email__c=%27testdemisto@paloaltonetworks.com%27'
                f'&FF__Key_Contact__c.fields=Id, FF__First_Name__c, FF__Last_Name__c, Work_Email__c, Name',
                json={}
            )

            client = mock_client()
            user_profile = IAMCommand(get_user_iam_attrs=['Work_Email__c']).get_user(client, args)

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

        args = {'user-profile': {'Work_Email__c': 'testdemisto@paloaltonetworks.com'}}
        error_msg = {"detail": "something has gone wrong on the website's server", "message": "INTERNAL SERVER ERROR"}
        mocker.patch.object(demisto, 'error')

        with requests_mock.Mocker() as m:
            m.post('https://test.com/services/oauth2/token?grant_type=password', json={})
            m.get(
                f'{URI_PREFIX}parameterizedSearch?q=testdemisto@paloaltonetworks.com&sobject=FF__Key_Contact__c'
                f'&FF__Key_Contact__c.where=Work_Email__c=%27testdemisto@paloaltonetworks.com%27'
                f'&FF__Key_Contact__c.fields=Id, FF__First_Name__c, FF__Last_Name__c, Work_Email__c, Name',
                status_code=500, json=error_msg
            )

            client = mock_client()
            user_profile = IAMCommand(get_user_iam_attrs=['Work_Email__c']).get_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is False
        assert outputs.get('errorCode') == 500
        assert outputs.get('errorMessage') == 'INTERNAL SERVER ERROR: something has gone wrong on the website\'s server'

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
        args = {'user-profile': {'Work_Email__c': 'testdemisto@paloaltonetworks.com'}}

        with requests_mock.Mocker() as m:
            m.post('https://test.com/services/oauth2/token?grant_type=password', json={})
            # User does not exist
            m.get(
                f'{URI_PREFIX}parameterizedSearch?q=testdemisto@paloaltonetworks.com&sobject=FF__Key_Contact__c'
                f'&FF__Key_Contact__c.where=Work_Email__c=%27testdemisto@paloaltonetworks.com%27'
                f'&FF__Key_Contact__c.fields=Id, FF__First_Name__c, FF__Last_Name__c, Work_Email__c, Name',
                json={}
            )
            # Create the user
            m.post(f'{URI_PREFIX}sobjects/FF__Key_Contact__c', json=APP_USER_OUTPUT)

            client = mock_client()
            user_profile = IAMCommand(get_user_iam_attrs=['Work_Email__c']).create_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.CREATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
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
        args = {'user-profile': {'Work_Email__c': 'testdemisto@paloaltonetworks.com'}}

        with requests_mock.Mocker() as m:
            m.post('https://test.com/services/oauth2/token?grant_type=password', json={})
            # User already exist
            m.get(f'https://test.com{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json=APP_UPDATED_USER_OUTPUT)
            m.post(f'https://test.com{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id?_HttpMethod=PATCH',
                   json=APP_UPDATED_USER_OUTPUT)
            m.get(
                f'{URI_PREFIX}parameterizedSearch?q=testdemisto@paloaltonetworks.com&sobject=FF__Key_Contact__c'
                f'&FF__Key_Contact__c.where=Work_Email__c=%27testdemisto@paloaltonetworks.com%27'
                f'&FF__Key_Contact__c.fields=Id, FF__First_Name__c, FF__Last_Name__c, Work_Email__c, Name',
                json={"searchRecords": [{"Id": "mock_id"}]}
            )
            # Update the user
            m.post(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json={})

            client = mock_client()
            user_profile = IAMCommand(get_user_iam_attrs=['Work_Email__c']).create_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
        # The updated user output
        assert outputs.get('username') == 'mock_update_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_update_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_update_last_name'

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
        args = {'user-profile': {'Work_Email__c': 'testdemisto@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

        with requests_mock.Mocker() as m:
            m.post('https://test.com/services/oauth2/token?grant_type=password', json={})
            # User does not exist
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json={})
            m.get(
                f'{URI_PREFIX}parameterizedSearch?q=testdemisto@paloaltonetworks.com&sobject=FF__Key_Contact__c'
                f'&FF__Key_Contact__c.where=Work_Email__c=%27testdemisto@paloaltonetworks.com%27'
                f'&FF__Key_Contact__c.fields=Id, FF__First_Name__c, FF__Last_Name__c, Work_Email__c, Name',
                json={}
            )
            # The create user endpoint
            m.post(f'{URI_PREFIX}sobjects/FF__Key_Contact__c', json=APP_USER_OUTPUT)
            # The update user endpoint
            m.post(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json={})

            client = mock_client()
            user_profile = IAMCommand(get_user_iam_attrs=['Work_Email__c'],
                                      create_if_not_exists=True).update_user(client, args)

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
        args = {'user-profile': {'Work_Email__c': 'testdemisto@paloaltonetworks.com', 'givenname': 'mock_first_name'}}

        with requests_mock.Mocker() as m:
            m.post('https://test.com/services/oauth2/token?grant_type=password', json={})

            client = mock_client()

        user_profile = IAMCommand(get_user_iam_attrs=['Work_Email__c'],
                                  is_update_enabled=False).update_user(client, args)

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
        args = {'user-profile': {'Work_Email__c': 'testdemisto@paloaltonetworks.com', 'givenname': 'mock_first_name'},
                'allow-enable': 'true'}

        with requests_mock.Mocker() as m:
            m.post('https://test.com/services/oauth2/token?grant_type=password', json={})
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json=APP_UPDATED_USER_OUTPUT)
            m.get(
                f'{URI_PREFIX}parameterizedSearch?q=testdemisto@paloaltonetworks.com&sobject=FF__Key_Contact__c'
                f'&FF__Key_Contact__c.where=Work_Email__c=%27testdemisto@paloaltonetworks.com%27'
                f'&FF__Key_Contact__c.fields=Id, FF__First_Name__c, FF__Last_Name__c, Work_Email__c, Name',
                json={"searchRecords": [{"Id": "mock_id"}]}
            )
            m.post(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json={})

            client = mock_client()
            user_profile = IAMCommand(get_user_iam_attrs=['Work_Email__c']).update_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
        assert outputs.get('username') == 'mock_update_user_name'
        assert outputs.get('details', {}).get('first_name') == 'mock_update_first_name'
        assert outputs.get('details', {}).get('last_name') == 'mock_update_last_name'

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
        args = {'user-profile': {'Work_Email__c': 'testdemisto@paloaltonetworks.com'}}

        with requests_mock.Mocker() as m:
            m.post('https://test.com/services/oauth2/token?grant_type=password', json={})
            # User does not exist
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/mock_id', json={})
            m.get(
                f'{URI_PREFIX}parameterizedSearch?q=testdemisto@paloaltonetworks.com&sobject=FF__Key_Contact__c'
                f'&FF__Key_Contact__c.where=Work_Email__c=%27testdemisto@paloaltonetworks.com%27'
                f'&FF__Key_Contact__c.fields=Id, FF__First_Name__c, FF__Last_Name__c, Work_Email__c, Name',
                json={"searchRecords": [{"Id": "mock_id"}]}
            )

            client = mock_client()
            user_profile = IAMCommand(get_user_iam_attrs=['Work_Email__c']).disable_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.DISABLE_USER
        assert outputs.get('success') is True
        assert outputs.get('skipped') is True
        assert outputs.get('reason') == IAMErrors.USER_DOES_NOT_EXIST[1]

    def test_get_mapping_fields_command__runs_the_all_integration_flow(self, mocker):
        """
        Given:
            - An app client object
        When:
            - User schema in the application contains the fields 'field1' and 'field2'
            - Calling the main function with the get-mapping-fields command
        Then:
            - Ensure a GetMappingFieldsResponse object that contains the application fields is returned
        """
        mocker.patch.object(demisto, 'command', return_value='get-mapping-fields')
        mocker.patch.object(demisto, 'params', return_value={'url': 'https://test.com', 'secret_token': '123456'})
        mock_result = mocker.patch('SalesforceFusionIAM.return_results')

        schema = {
            'fields': [
                {'name': 'field1', 'label': 'desc1'},
                {'name': 'field2', 'label': 'desc2'},
            ]
        }

        with requests_mock.Mocker() as m:
            m.post('https://test.com/services/oauth2/token?grant_type=password', json={})
            m.get(f'{URI_PREFIX}sobjects/FF__Key_Contact__c/describe/', json=schema)

            main()

        mapping = mock_result.call_args.args[0].extract_mapping()

        assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field1') == 'desc1'
        assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field2') == 'desc2'
