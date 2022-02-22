import pytest
import requests_mock
from AWSILM import Client, main, get_group_command, create_group_command, update_group_command, delete_group_command

from IAMApiModule import *

userUri = '/scim/v2/Users/'
groupUri = '/scim/v2/Groups/'
RETURN_ERROR_TARGET = 'AWSILM.return_error'

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


class TestGetUserCommand:

    @pytest.mark.parametrize('args, mock_url', [({'user-profile': {'userName': 'mock_user_name'}}, userUri),
                                                ({'user-profile': {'userName': 'mock_user_name', 'id': 'mock_id'}},
                                                 f'{userUri}mock_id')])
    def test_existing_user(self, args, mock_url):
        """
        Given:
            - An app client object
            - A user-profile argument that contains an email of a user
        When:
            - The user exists in the application
            - Calling function get_user_command
        Cases:
        Case a: Calling user command with valid username in user profile.
        Case b: Calling user command with valid username and valid id in user profile.

        Then:
            - Ensure the resulted User Profile object holds the correct user details
        Case a: Ensure the URL corresponding to username is called.
        Case b: Ensure the URL corresponding to ID is called.
        """
        from AWSILM import SUPPORTED_GET_USER_IAM_ATTRIBUTES
        client = mock_client()

        with requests_mock.Mocker() as m:
            m.get(mock_url, json={"totalResults": 1, "Resources": [APP_USER_OUTPUT]})

            user_profile = IAMCommand(get_user_iam_attrs=SUPPORTED_GET_USER_IAM_ATTRIBUTES).get_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
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
        args = {'user-profile': {'userName': 'mock_user_name'}}

        with requests_mock.Mocker() as m:
            m.get(userUri, json={"totalResults": 0, "Resources": []})

            user_profile = IAMCommand(get_user_iam_attrs=['userName']).get_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is False
        assert outputs.get('errorCode') == IAMErrors.USER_DOES_NOT_EXIST[0]
        assert outputs.get('errorMessage') == IAMErrors.USER_DOES_NOT_EXIST[1]

    def test_bad_response(self, mocker):
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
        args = {'user-profile': {'userName': 'mock_user_name'}}

        with requests_mock.Mocker() as m:
            m.get(f'{userUri}?filter=userName eq "mock_user_name"', status_code=500,
                  json={"detail": "INTERNAL SERVER ERROR"})

            user_profile = IAMCommand(get_user_iam_attrs=['userName']).get_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.GET_USER
        assert outputs.get('success') is False
        assert outputs.get('errorCode') == 500
        assert 'INTERNAL SERVER ERROR' in outputs.get('errorMessage')


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
        args = {'user-profile': {'userName': 'mock_user_name'}}

        with requests_mock.Mocker() as m:
            m.get(userUri, json={"totalResults": 0, "Resources": []})
            m.post(userUri, json=APP_USER_OUTPUT)

            user_profile = IAMCommand(get_user_iam_attrs=['userName']).create_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.CREATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
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
        args = {'user-profile': {'userName': 'mock_user_name'}, 'allow-enable': 'false'}

        with requests_mock.Mocker() as m:
            m.get(userUri, json={"totalResults": 1, "Resources": [APP_USER_OUTPUT]})
            m.get(f'{userUri}mock_id', json=APP_USER_OUTPUT)
            m.patch(f'{userUri}mock_id', json=APP_UPDATED_USER_OUTPUT)

            user_profile = IAMCommand(get_user_iam_attrs=['userName']).create_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'new_mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'new_mock_last_name'


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
        args = {'user-profile': {'userName': 'mock_user_name'}}

        with requests_mock.Mocker() as m:
            m.get(userUri, json={"totalResults": 0, "Resources": []})
            m.post(userUri, json=APP_USER_OUTPUT)

            user_profile = IAMCommand(create_if_not_exists=True, get_user_iam_attrs=['userName']).update_user(client,
                                                                                                              args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.CREATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
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
        args = {'user-profile': {'userName': 'mock_user_name'}}

        user_profile = IAMCommand(is_update_enabled=False, get_user_iam_attrs=['userName']).update_user(client, args)

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
        args = {'user-profile': {'userName': 'mock_user_name'}, 'allow-enable': 'true'}

        with requests_mock.Mocker() as m:
            m.get('https://test.com/scim/v2/Users/?filter=userName eq "mock_user_name"',
                  json={"totalResults": 1, "Resources": [APP_DISABLED_USER_OUTPUT]})
            m.get(f'{userUri}mock_id', json=APP_DISABLED_USER_OUTPUT)
            m.patch(f'{userUri}mock_id', json=APP_UPDATED_USER_OUTPUT)

            user_profile = IAMCommand(get_user_iam_attrs=['userName']).update_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.UPDATE_USER
        assert outputs.get('success') is True
        assert outputs.get('active') is True
        assert outputs.get('id') == 'mock_id'
        assert outputs.get('username') == 'mock_user_name'
        assert outputs.get('details', {}).get('first_name') == 'new_mock_first_name'
        assert outputs.get('details', {}).get('last_name') == 'new_mock_last_name'


class TestDisableUserCommand:
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
        args = {'user-profile': {'userName': 'mock_user_name'}}

        with requests_mock.Mocker() as m:
            m.get(userUri, json={"totalResults": 0, "Resources": []})

            user_profile = IAMCommand(get_user_iam_attrs=['userName']).disable_user(client, args)

        outputs = get_outputs_from_user_profile(user_profile)

        assert outputs.get('action') == IAMActions.DISABLE_USER
        assert outputs.get('success') is True
        assert outputs.get('skipped') is True
        assert outputs.get('reason') == IAMErrors.USER_DOES_NOT_EXIST[1]


class TestGetGroupCommand:
    """
    Given:
        - An app client object
        - A scim argument that contains a displayName of a group
    When:
        - The group exists in the application
        - Calling the main function with 'iam-get-group' command
    Then:
        - Ensure the resulted 'CommandResults' object holds the correct group details
    """

    def test_with_id(self, mocker):
        client = mock_client()
        args = {"scim": "{\"id\": \"1234\", \"displayName\": \"The group name\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            # m.get(groupUri, json={'total_results': 1, 'Resources': [APP_GROUP_OUTPUT]})
            m.get(f'{groupUri}1234', json=APP_GROUP_OUTPUT)

            get_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['details'] == APP_GROUP_OUTPUT

    def test_with_display_name(self, mocker):
        """
        Given:
            - An app client object
            - A scim argument that contains a displayName of a group
        When:
            - The group exists in the application
            - Calling the main function with 'iam-get-group' command
        Then:
            - Ensure the resulted 'CommandResults' object holds the correct group details
        """
        client = mock_client()
        args = {"scim": "{\"displayName\": \"The group name\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.get(f'{groupUri}', json={'totalResults': 1, 'Resources': [APP_GROUP_OUTPUT]})

            get_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['details'] == APP_GROUP_OUTPUT

    def test_non_existing_group(self, mocker):
        """
        Given:
            - An app client object
            - A scim argument that contains an ID and displayName of a non_existing group
        When:
            - The group not exists in the application
            - Calling the main function with 'iam-get-group' command
        Then:
            - Ensure the resulted 'CommandResults' object holds information about an unsuccessful result.
        """
        client = mock_client()
        args = {"scim": "{\"id\": \"1234\", \"displayName\": \"The group name\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.get(f'{groupUri}1234', status_code=404, text='Group Not Found')

            get_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['errorCode'] == 404
        assert mock_result.call_args.kwargs['outputs']['errorMessage'] == 'Group Not Found'

    def test_id_and_display_name_empty(self):
        """
        Given:
            - An app client object
            - A scim argument that not contains an ID and displayName of a group
        When:
            - Calling the main function with 'iam-get-group' command
        Then:
            - Ensure that an error is raised with an expected message.
        """
        client = mock_client()
        args = {"scim": "{}"}

        with pytest.raises(Exception) as e:
            get_group_command(client, args)

        assert str(e.value) == 'You must supply either "id" or "displayName" in the scim data'


class TestCreateGroupCommand:
    def test_success(self, mocker):
        """
        Given:
            - An app client object
            - A scim argument that contains a displayName of a non-existing group in the application
        When:
            - Calling the main function with 'iam-create-group' command
        Then:
            - Ensure the resulted 'CommandResults' object holds information about the created group.
        """
        client = mock_client()
        args = {"scim": "{\"displayName\": \"The group name\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.post(f'{groupUri}', status_code=201, json=APP_GROUP_OUTPUT)

            create_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['details'] == APP_GROUP_OUTPUT

    def test_group_already_exist(self):
        """
        Given:
            - An app client object
            - A scim argument that contains a displayName of an existing group in the application
        When:
            - Calling the main function with 'iam-create-group' command
        Then:
            - Ensure that an error is raised with an expected message.
        """
        client = mock_client()
        args = {"scim": "{\"displayName\": \"The group name\"}"}

        with requests_mock.Mocker() as m:
            m.post(f'{groupUri}', status_code=400, text="Group already exist")

            with pytest.raises(Exception) as e:
                create_group_command(client, args)

        assert e.value.res.status_code == 400
        assert 'Group already exist' in str(e.value)

    def test_display_name_empty(self):
        """
        Given:
            - An app client object
            - A scim argument that not contains a displayName
        When:
            - Calling the main function with 'iam-create-group' command
        Then:
            - Ensure that an error is raised with an expected message.
        """
        client = mock_client()
        args = {"scim": "{}"}

        with pytest.raises(Exception) as e:
            create_group_command(client, args)

        assert str(e.value) == 'You must supply "displayName" of the group in the scim data'


class TestUpdateGroupCommand:
    def test_success(self, mocker):
        """
        Given:
            - An app client object
            - A scim argument that contains a group ID and a memberIdsToAdd/memberIdsToDelete argument
                of the members who are supposed to be updated.
        When:
            - Calling the main function with 'iam-update-group'
        Then:
            - Ensure the resulted 'CommandResults' object holds information about the updated group.
        """
        client = mock_client()
        args = {"scim": "{\"id\": \"1234\"}", "memberIdsToAdd": ["111111"],
                "memberIdsToDelete": ["222222"]}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.patch(f'{groupUri}1234', status_code=204, json={})

            update_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['id'] == '1234'

    def test_nothing_to_update(self):
        """
        Given:
            - An app client object
            - A scim argument that contains a group ID.
        When:
            - Calling the main function with 'iam-update-group'
        Then:
            - Ensure that an error is raised with an expected message.
        """
        client = mock_client()
        args = {"scim": "{\"id\": \"1234\", \"displayName\": \"The group name\"}"}

        with pytest.raises(Exception) as e:
            update_group_command(client, args)

        assert str(e.value) == 'You must supply either "memberIdsToAdd" or "memberIdsToDelete" in the arguments'


class TestDeleteGroupCommand:
    def test_success(self, mocker):
        """
        Given:
            - An app client object
            - A scim argument that contains a group ID.
        When:
            - Calling the main function with 'iam-delete-group'
        Then:
            - Ensure the resulted 'CommandResults' object holds information about the deleted group.
        """
        client = mock_client()
        args = {"scim": "{\"id\": \"1234\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.delete(f'{groupUri}1234', status_code=204, json={})

            delete_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['id'] == '1234'

    def test_non_existing_group(self, mocker):
        """
        Given:
            - An app client object
            - A scim argument that contains a non-existing group ID.
        When:
            - Calling the main function with 'iam-delete-group'
        Then:
            - Ensure that an error is raised with an expected message.
        """
        client = mock_client()
        args = {"scim": "{\"id\": \"1234\"}"}
        mock_result = mocker.patch('AWSILM.CommandResults')

        with requests_mock.Mocker() as m:
            m.delete(f'{groupUri}1234', status_code=404, text="Group Not Found")

            delete_group_command(client, args)

        assert mock_result.call_args.kwargs['outputs']['errorCode'] == 404
        assert mock_result.call_args.kwargs['outputs']['errorMessage'] == 'Group Not Found'

    def test_id_is_empty(self):
        """
        Given:
            - An app client object
            - A scim argument that not contains a group ID.
        When:
            - Calling the main function with 'iam-delete-group'
        Then:
            - Ensure that an error is raised with an expected message.
        """
        client = mock_client()
        args = {"scim": "{}"}

        with pytest.raises(Exception) as e:
            delete_group_command(client, args)

        assert str(e.value) == "The group id needs to be provided."


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
    from AWSILM import AWS_DEFAULT_SCHEMA_MAPPING
    mocker.patch.object(demisto, 'command', return_value='get-mapping-fields')
    mocker.patch.object(demisto, 'params', return_value={'url': 'http://example.com', 'tenant_id': 'tenant'})
    mock_result = mocker.patch('AWSILM.return_results')
    main()
    mapping = mock_result.call_args.args[0].extract_mapping()

    assert mapping.get(IAMUserProfile.DEFAULT_INCIDENT_TYPE, {}) == AWS_DEFAULT_SCHEMA_MAPPING
