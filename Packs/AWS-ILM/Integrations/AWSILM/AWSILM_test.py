from AWSILM import Client, main, get_group_command, create_group_command, update_group_command, delete_group_command
from IAMApiModule import *
import requests_mock

userUri = '/scim/v2/Users/'
groupUri = '/scim/v2/Groups/'

APP_USER_OUTPUT = {
    "id": "mock_id",
    "userName": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": True,
    "email": "testdemisto@paloaltonetworks.com",
}

APP_DISABLED_USER_OUTPUT = {
    "id": "mock_id",
    "userName": "mock_user_name",
    "first_name": "mock_first_name",
    "last_name": "mock_last_name",
    "active": False,
    "email": "testdemisto@paloaltonetworks.com",
}

APP_UPDATED_USER_OUTPUT = {
    "id": "mock_id",
    "userName": "mock_user_name",
    "first_name": "new_mock_first_name",
    "last_name": "new_mock_last_name",
    "active": True,
    "email": "testdemisto@paloaltonetworks.com",
}

APP_GROUP_OUTPUT = {
    "id": "mock_id",
    "displayName": "The group name",
}


def mock_client():
    client = Client(base_url='https://test.com')
    return client


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')
    return outputs


class TestCURDCommands:
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
        client = mock_client()
        args = {'user-profile': {'username': 'mock_user_name'}}

        with requests_mock.Mocker() as m:
            m.get(userUri, json={"totalResults": 1, "Resources": [APP_USER_OUTPUT]})

            user_profile = IAMCommand(attr='username').get_user(client, args)

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
        args = {'user-profile': {'username': 'mock_user_name'}}

        with requests_mock.Mocker() as m:
            m.get(userUri, json={"totalResults": 0, "Resources": []})

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

        client = mock_client()
        args = {'user-profile': {'username': 'mock_user_name'}}

        with requests_mock.Mocker() as m:
            m.get(f'{userUri}?filter=userName eq "mock_user_name"', status_code=500,
                  json={"detail": "INTERNAL SERVER ERROR"})

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
        client = mock_client()
        args = {'user-profile': {'username': 'mock_user_name'}}

        with requests_mock.Mocker() as m:
            m.get(userUri, json={"totalResults": 0, "Resources": []})
            m.post(userUri, json=APP_USER_OUTPUT)

            user_profile = IAMCommand(attr='username').create_user(client, args)

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
        client = mock_client()
        args = {'user-profile': {'username': 'mock_user_name'}, 'allow-enable': 'false'}

        with requests_mock.Mocker() as m:
            m.get(userUri, json={"totalResults": 1, "Resources": [APP_USER_OUTPUT]})
            m.get(f'{userUri}mock_id', json=APP_USER_OUTPUT)
            m.patch(f'{userUri}mock_id', json=APP_UPDATED_USER_OUTPUT)

            user_profile = IAMCommand(attr='username').create_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'new_mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'new_mock_last_name'

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
        client = mock_client()
        args = {'user-profile': {'username': 'mock_user_name'}}

        with requests_mock.Mocker() as m:
            m.get(userUri, json={"totalResults": 0, "Resources": []})
            m.post(userUri, json=APP_USER_OUTPUT)

            user_profile = IAMCommand(create_if_not_exists=True, attr='username').create_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.CREATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
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
        client = mock_client()
        args = {'user-profile': {'username': 'mock_user_name'}, 'allow-enable': 'true'}

        with requests_mock.Mocker() as m:
            m.get('https://test.com/scim/v2/Users/?filter=userName eq "mock_user_name"',
                  json={"totalResults": 1, "Resources": [APP_DISABLED_USER_OUTPUT]})
            m.get(f'{userUri}mock_id', json=APP_DISABLED_USER_OUTPUT)
            m.patch(f'{userUri}mock_id', json=APP_UPDATED_USER_OUTPUT)

            user_profile = IAMCommand(attr='username').update_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
        assert outputs.get('username') == 'mock_user_name'
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
        client = mock_client()
        args = {'user-profile': {'username': 'mock_user_name'}}

        with requests_mock.Mocker() as m:
            m.get(userUri, json={"totalResults": 0, "Resources": []})

            user_profile = IAMCommand(attr='username').disable_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.DISABLE_USER
        assert outputs.get('success') is True
        assert outputs.get('skipped') is True
        assert outputs.get('reason') == IAMErrors.USER_DOES_NOT_EXIST[1]


class TestGroupCommands:
    def test_get_group(self, mocker):
        client = mock_client()
        args = {"scim": "{\"id\": \"1234\", \"displayName\": \"The group name\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            # m.get(groupUri, json={'total_results': 1, 'Resources': [APP_GROUP_OUTPUT]})
            m.get(f'{groupUri}1234', json=APP_GROUP_OUTPUT)

            get_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['details'] == APP_GROUP_OUTPUT

    def test_get_group__non_existing_group(self, mocker):
        client = mock_client()
        args = {"scim": "{\"id\": \"1234\", \"displayName\": \"The group name\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.get(f'{groupUri}1234', status_code=404, json={'totalResults': 0, 'Resources': []})

            get_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['errorCode'] == 404
        assert mock_result.call_args.kwargs['outputs']['errorMessage'] == 'Group Not Found'

    def test_get_group__id_and_display_name_empty(self, mocker):
        client = mock_client()
        args = {"scim": "{}"}
        import demistomock as demisto
        mock_result = mocker.patch.object(demisto, 'results')

        # with requests_mock.Mocker() as m:
        #     m.get(f'{groupUri}1234', json={'total_results': 0, 'Resources': []})

        get_group_command(client, args)

        assert mock_result == "You must supply either 'id' or 'displayName' in the scim data"

    def test_get_group__display_name(self, mocker):
        client = mock_client()
        args = {"scim": "{\"displayName\": \"The group name\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.get(f'{groupUri}', json={'totalResults': 1, 'Resources': [APP_GROUP_OUTPUT]})

            get_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['details'] == APP_GROUP_OUTPUT

    def test_create_group(self, mocker):
        client = mock_client()
        args = {"scim": "{\"displayName\": \"The group name\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.post(f'{groupUri}', status_code=201, json=APP_GROUP_OUTPUT)

            create_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['details'] == APP_GROUP_OUTPUT

    def test_create_group__group_already_exist(self, mocker):
        client = mock_client()
        args = {"scim": "{\"displayName\": \"The group name\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.post(f'{groupUri}', status_code=400, json={"code": 400, "message": "Group already exist"})

            create_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['errorCode'] == 400
        assert mock_result.call_args.kwargs['outputs']['errorMessage'] == "Group already exist"

    def test_update_group(self, mocker):
        client = mock_client()
        args = {"scim": "{\"id\": \"1234\"}", "memberIdsToAdd": ["111111"],
                "memberIdsToDelete": ["222222"]}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.patch(f'{groupUri}1234', status_code=204, json={})

            update_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['id'] == '1234'

    # def test_update_group__nothing_to_update(self, mocker):
    #     client = mock_client()
    #     args = {"scim": "{\"id\": \"1234\", \"displayName\": \"The group name\"}"}
    #     mock_result = mocker.patch('AWSILM.CommandResults')
    #
    #     with requests_mock.Mocker() as m:
    #         m.patch(f'{groupUri}1234', status_code=204, json={})
    #
    #         update_group_command(client, args)
    #
    #     assert mock_result.call_args.kwargs['outputs']['id'] == '1234'
    #     assert mock_result.call_args.kwargs['outputs']['displayName'] == 'The group name'

    def test_delete_group(self, mocker):
        client = mock_client()
        args = {"scim": "{\"id\": \"1234\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.delete(f'{groupUri}1234', status_code=204, json={})

            delete_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['id'] == '1234'

    def test_delete_group__non_existing_group(self, mocker):
        client = mock_client()
        args = {"scim": "{\"id\": \"1234\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.delete(f'{groupUri}1234', status_code=404, json={})

            delete_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['errorCode'] == 404
        assert mock_result.call_args.kwargs['outputs']['errorMessage'] == "Group Not Found"


def test_get_mapping_fields_command__runs_the_all_integration_flow(mocker):
    """
    Given:
        - An app client object
    When:
        - User schema in the application contains the fields 'field1' and 'field2'
        - Calling the main function with the get-mapping-fields command
    Then:
        - Ensure a GetMappingFieldsResponse object that contains the application fields is returned
    """
    import demistomock as demisto
    mocker.patch.object(demisto, 'command', return_value='get-mapping-fields')
    mocker.patch.object(demisto, 'params', return_value={'url': 'http://example.com', 'tenant_id': 'tenant'})
    mock_result = mocker.patch('AWSILM.return_results')

    schema = {
        'result': [
            {'name': 'field1', 'description': 'desc1'},
            {'name': 'field2', 'description': 'desc2'},
        ]
    }

    with requests_mock.Mocker() as m:
        m.get('http://example.com/tenant/schema', json=schema)

        main()

    mapping = mock_result.call_args.args[0].extract_mapping()

    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field1') == 'desc1'
    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}).get('field2') == 'desc2'
