from requests import Response, Session
from SAPIAM import main
from IAMApiModule import *
import demistomock as demisto

MOCK_ARGS = {
    'user-profile': {
        'email': 'testdemisto@paloaltonetworks.com',
        'username': 'test_demisto',
        'id': '1234',
    }
}

MOCK_PARAMS = {
    'url': 'https://test.com',
    'deactivate_uri': 'deactivate_uri',
    'credentials': {'identifier': '1234', 'password': '5678'},
}

APP_USER_OUTPUT = {
    "user_id": "mock_id",
    "user_name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "true",
    "email": "testdemisto@paloaltonetworks.com",
}

APP_DISABLED_USER_OUTPUT = {
    "user_id": "mock_id",
    "user_name": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": "false",
    "email": "testdemisto@paloaltonetworks.com",
}
#
#
# def mock_client():
#     client = Client(base_url='https://test.com')
#     return client
#

def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


class TestGetUserCommand:
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
        mocker.patch.object(demisto, 'command', return_value='iam-get-user')
        mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
        mocker.patch.object(demisto, 'args', return_value=MOCK_ARGS)
        mock_results = mocker.patch('demistomock.results')

        main()

        assert mock_results.call_args[0][0]['Contents']['action'] == IAMActions.GET_USER
        assert mock_results.call_args[0][0]['Contents']['success'] is True
        assert mock_results.call_args[0][0]['Contents']['active'] is True
        assert mock_results.call_args[0][0]['Contents']['id'] == '1234'
        assert mock_results.call_args[0][0]['Contents']['username'] == 'test_demisto'

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


class TestDisableUserCommand:
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
    client = mock_client()
    mocker.patch.object(client, 'get_app_fields', return_value={'field1': 'desc1', 'field2': 'desc2'})

    mapping_response = get_mapping_fields(client)
    mapping = mapping_response.extract_mapping()

    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field1') == 'desc1'
    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field2') == 'desc2'
