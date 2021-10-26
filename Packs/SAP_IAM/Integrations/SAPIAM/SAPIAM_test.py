import requests_mock
from SAPIAM import Client, get_mapping_fields, main
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
    'disable_user_enabled': True,
}

APP_DISABLE_USER_OUTPUT = {
    "MT_Account_Terminate_Response": {
        "user_id": "1234",
        "user_name": "test_demisto",
        "first_name": "mock_first_name",
        "last_name": "mock_last_name",
        "IsActive": False,
        "email": "testdemisto@paloaltonetworks.com",
    }
}


def mock_client():
    client = Client(base_url='https://test.com', headers={})
    return client


class TestGetUserCommand:
    def test_existing_user(self, mocker):
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
        demisto_results_mock = mocker.patch('demistomock.results')

        main()

        assert demisto_results_mock.call_args[0][0]['Contents']['action'] == IAMActions.GET_USER
        assert demisto_results_mock.call_args[0][0]['Contents']['success'] is True
        assert demisto_results_mock.call_args[0][0]['Contents']['active'] is True
        assert demisto_results_mock.call_args[0][0]['Contents']['id'] == '1234'
        assert demisto_results_mock.call_args[0][0]['Contents']['username'] == 'test_demisto'


class TestDisableUserCommand:
    def test_success(self, mocker):
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
        mocker.patch.object(demisto, 'command', return_value='iam-disable-user')
        mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
        mocker.patch.object(demisto, 'args', return_value=MOCK_ARGS)
        demisto_results_mock = mocker.patch.object(demisto, 'results')

        with requests_mock.Mocker() as m:
            m.post('/deactivate_uri', json=APP_DISABLE_USER_OUTPUT)

            main()

        assert demisto_results_mock.call_args[0][0]['Contents']['action'] == IAMActions.DISABLE_USER
        assert demisto_results_mock.call_args[0][0]['Contents']['success'] is True
        assert demisto_results_mock.call_args[0][0]['Contents']['active'] is False
        assert demisto_results_mock.call_args[0][0]['Contents']['id'] == '1234'
        assert demisto_results_mock.call_args[0][0]['Contents']['username'] == 'test_demisto'


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
