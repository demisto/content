import pytest

from unittest.mock import patch

from CommonServerPython import *

from GoogleDrive import MESSAGES, OUTPUT_PREFIX, HR_MESSAGES, GSuiteClient

with open('test_data/service_account_json.txt') as f:
    TEST_JSON = f.read()

MOCKER_HTTP_METHOD = 'GSuiteApiModule.GSuiteClient.http_request'


@pytest.fixture
def gsuite_client():
    headers = {
        'Content-Type': 'application/json'
    }
    return GSuiteClient(GSuiteClient.safe_load_non_strict_json(TEST_JSON), verify=False, proxy=False, headers=headers)


def test_test_function(mocker, gsuite_client):
    """
    Scenario: Call to test-module should return 'ok' if API call succeeds.

    Given:
    - client object

    When:
    - Calling test function.

    Then:
    - Ensure 'ok' should be return.
    """
    from GoogleDrive import test_module, GSuiteClient
    mocker.patch.object(GSuiteClient, 'set_authorized_http')
    mocker.patch.object(GSuiteClient, 'http_request')
    assert test_module(gsuite_client, {}, {}) == 'ok'


@patch(MOCKER_HTTP_METHOD)
def test_drive_create_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For google-drive-create command success.

    Given:
    - Command args.

    When:
    - Calling google-drive-create command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs, readable_output, outputs_key_field, outputs_prefix should be as expected.
    """
    from GoogleDrive import drive_create_command

    with open('test_data/drive_create_response.json', encoding='utf-8') as data:
        response_data = json.load(data)
    mocker_http_request.return_value = response_data

    result = drive_create_command(gsuite_client, {})

    assert result.raw_response == response_data
    assert result.outputs == response_data
    assert result.readable_output.startswith("### " + HR_MESSAGES['DRIVE_CREATE_SUCCESS'])
    assert result.outputs_key_field == 'id'
    assert result.outputs_prefix == OUTPUT_PREFIX['GOOGLE_DRIVE_HEADER']


@patch(MOCKER_HTTP_METHOD)
def test_drive_create_command_failure(mocker_http_request, gsuite_client):
    """
    Scenario: For google-drive-create command failure.

    Given:
    - Command args and a non-working google api integration.

    When:
    - Calling google-drive-create command with the parameters provided.

    Then:
    - Ensure command's  error response is as expected.
    """
    mocker_http_request.side_effect = ValueError("SOME_ERROR")

    from GoogleDrive import drive_create_command

    with pytest.raises(Exception, match="SOME_ERROR"):
        drive_create_command(gsuite_client, {})


@patch(MOCKER_HTTP_METHOD)
def test_drive_changes_list_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For google-drive-changes-list command successful run.

    Given:
    - Command args.

    When:
    - Calling google-drive-changes-list command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs and readable_output should be as expected.
    """
    from GoogleDrive import drive_changes_list_command

    with open('test_data/drive_changes_response.json', encoding='utf-8') as data:
        mock_response = json.load(data)
    with open('test_data/drive_changes_drive_context.json', encoding='utf-8') as data:
        expected_res = json.load(data)
    mocker_http_request.return_value = mock_response

    with open('test_data/drive_changes_hr.txt') as data:
        expected_hr = data.read()
    args = {'user_id': 'user@test.com', 'page_token': '1'}
    result = drive_changes_list_command(gsuite_client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_drive_changes_list_command_wrong_argument(mocker_http_request, gsuite_client):
    """
    Scenario: Wrong argument given google-drive-changes-list command.

    Given:
    - Command args.

    When:
    - Calling google-drive-changes-list command with the parameters provided.

    Then:
    - Ensure command should raise Exception as expected.
    """
    from GoogleDrive import drive_changes_list_command
    message = "message"
    mocker_http_request.side_effect = Exception(message)
    args = {'page_token': '1', 'user_id': 'user@test.comm', 'fields': 'advance'}
    with pytest.raises(Exception, match=message):
        drive_changes_list_command(gsuite_client, args)


def test_prepare_params_for_drive_changes_list():
    """
    Scenario: Arguments given for google-drive-changes-list command.

    Given:
    - Command args.

    When:
    - Calling prepare_params_for_drive_changes_list with command arguments.

    Then:
    - Ensure prepared arguments should be returned or return valid value error.
    """
    from GoogleDrive import prepare_params_for_drive_changes_list
    fields = 'fields'
    arguments = {
        'page_token': '1',
        'drive_id': 'driveId',
        'include_corpus_removals': 'false',
        'include_items_from_all_drives': 'false',
        'include_removed': 'false',
        'restrict_to_my_drive': 'false',
        'supports_all_drives': 'false',
        fields: 'advance',
        'page_size': '1',
        'spaces': 'drive,appDataFolder',
        'include_permissions_for_view': 'published'
    }
    expected_arguments = {
        'pageToken': '1',
        'driveId': 'driveId',
        'includeCorpusRemovals': False,
        'includeItemsFromAllDrives': False,
        'includeRemoved': False,
        'restrictToMyDrive': False,
        'supportsAllDrives': False,
        fields: '*',
        'pageSize': 1,
        'spaces': 'drive,appDataFolder',
        'includePermissionsForView': 'published'
    }
    assert prepare_params_for_drive_changes_list(arguments) == expected_arguments

    arguments = {fields: 'some'}
    with pytest.raises(ValueError) as e:
        prepare_params_for_drive_changes_list(arguments)
    assert MESSAGES['DRIVE_CHANGES_FIELDS'].format(fields) == str(e.value)

    arguments = {'page_size': '-1'}
    with pytest.raises(ValueError) as e:
        prepare_params_for_drive_changes_list(arguments)
    assert MESSAGES['INTEGER_ERROR'].format('page_size') == str(e.value)


def test_prepare_body_for_drive_activity():
    """
    Scenario: Arguments given for prepare_body_for_drive_activity method.

    Given:
    - args.

    When:
    - Calling prepare_body_for_drive_activity with command arguments.

    Then:
    - Ensure method should return dict.
    """
    from GoogleDrive import prepare_body_for_drive_activity
    args = {
        'folder_name': 'items/1',
        'item_name': 'items/2',
        'filter': 'time >= "2020-09-17T13:19:10.197Z"',
        'time_range': '5 days',
        'action_detail_case_include': 'RENAME',
        'action_detail_case_remove': 'CREATE',
        'page_token': 'token123'
    }

    expected_body = {
        'ancestorName': args.get('folder_name'),
        'itemName': args.get('item_name'),
        'pageToken': args.get('page_token'),
        'filter': args.get('filter')
    }
    assert expected_body == prepare_body_for_drive_activity(args)


@patch(MOCKER_HTTP_METHOD)
def test_drive_activity_list_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For google-drive-activity-list command successful run.

    Given:
    - Command args.

    When:
    - Calling google-drive-activity-list command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs should be as expected.
    """
    from GoogleDrive import drive_activity_list_command

    with open('test_data/drive_activity_response.json', encoding='utf-8') as data:
        mock_response = json.load(data)
    with open('test_data/drive_activity_context.json', encoding='utf-8') as data:
        expected_res = json.load(data)
    mocker_http_request.return_value = mock_response

    args = {}
    result = drive_activity_list_command(gsuite_client, args)
    assert result.raw_response == mock_response
    assert result.outputs == expected_res


@patch(MOCKER_HTTP_METHOD)
def test_drive_activity_list_command_human_readable(mocker_http_request, gsuite_client):
    """
    Scenario: For google-drive-activity-list command successful run.

    Given:
    - Command args.

    When:
    - Calling google-drive-activity-list command with the parameters provided.

    Then:
    - Ensure command's  human redable should be as expected.
    """
    from GoogleDrive import drive_activity_list_command

    with open('test_data/drive_activity_primary_activities.json', encoding='utf-8') as data:
        mock_response = json.load(data)
    with open('test_data/drive_activity_list_hr.txt') as data:
        expected_hr = data.read()

    mocker_http_request.return_value = mock_response

    args = {}
    result = drive_activity_list_command(gsuite_client, args)

    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_drive_activity_list_command_no_records(mocker_http_request, gsuite_client):
    """
    Scenario: For google-drive-activity-list command when no records found.

    Given:
    - Command args.

    When:
    - Calling google-drive-activity-list command with the parameters provided.

    Then:
    - Ensure command's  readable_output.
    """
    from GoogleDrive import drive_activity_list_command

    mocker_http_request.return_value = {"activities": []}

    args = {}
    result = drive_activity_list_command(gsuite_client, args)

    assert result.readable_output == "No Drive Activity found."


def test_validate_params_for_fetch_incidents_error():
    """
    Scenario: Parameters provided for fetch-incidents.

    Given:
    - Configuration parameters.

    When:
    - Calling validate_params_for_fetch_incidents with parameters.

    Then:
    - Ensure parameters validation.
    """
    from GoogleDrive import validate_params_for_fetch_incidents
    params = {
        'isFetch': True,
        'drive_item_search_value': 'create',
        'max_fetch': 'abc',
        'user_id': 'helo'
    }
    with pytest.raises(ValueError, match=MESSAGES['FETCH_INCIDENT_REQUIRED_ARGS']):
        validate_params_for_fetch_incidents(params)
        params.pop('drive_item_search_value')
        params['drive_item_search_field'] = 'create'
        validate_params_for_fetch_incidents(params)

    with pytest.raises(ValueError, match=MESSAGES['MAX_INCIDENT_ERROR']):
        params.pop('drive_item_search_value')
        validate_params_for_fetch_incidents(params)


def test_prepare_args_for_fetch_incidents():
    """
    Scenario: Prepare request body for fetch-incidents.

    Given:
    - Configuration parameters.

    When:
    - Calling prepare_args_for_fetch_incidents with parameters.

    Then:
    - Ensure body preparation.
    """
    from GoogleDrive import prepare_args_for_fetch_incidents
    params = {
        'action_detail_case_include': ['create', 'edit'],
    }
    assert prepare_args_for_fetch_incidents(0, params) == {
        'filter': 'time > 0 AND detail.action_detail_case: (CREATE EDIT)', 'pageSize': 100}
    with pytest.raises(ValueError, match=MESSAGES['FETCH_INCIDENT_REQUIRED_ARGS']):
        prepare_args_for_fetch_incidents(0, {'drive_item_search_value': 'a'})


def test_fetch_incidents(gsuite_client, mocker):
    """
    Scenario: fetch_incidents called with valid arguments.

    Given:
    - Configuration parameters.

    When:
    - Calling fetch_incidents with parameters.

    Then:
    - Ensure successful execution of fetch_incidents.
    """
    from GoogleDrive import fetch_incidents
    params = {
        'drive_item_search_field': 'create',
        'drive_item_search_value': 'create',
        'action_detail_case_include': ['create', 'edit'],
        'user_id': 'user@domain.io'
    }
    with open('test_data/fetch_incidents_response.json') as file:
        fetch_incidents_response = json.load(file)
    mocker.patch(MOCKER_HTTP_METHOD, return_value=fetch_incidents_response)
    with open('test_data/fetch_incidents_output.json') as file:
        fetch_incidents_output = json.load(file)
    mocker.patch(MOCKER_HTTP_METHOD, return_value=fetch_incidents_response)
    params['first_fetch'] = '10 day'
    params['max_incidents'] = 10
    fetch_incident = fetch_incidents(gsuite_client, {}, params)
    assert fetch_incident[0] == fetch_incidents_output['incidents']


def test_main_fetch_incidents(mocker):
    """
    Given working service integration
    When fetch-incidents is called from main()
    Then demistomock.incidents and demistomock.setLastRun should be called with respected values.

    :param args: Mocker objects.
    :return: None
    """
    from GoogleDrive import main, demisto
    with open('test_data/fetch_incidents_output.json') as file:
        fetch_incidents_output = json.load(file)
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'params',
                        return_value={'user_service_account_json': TEST_JSON, 'max_incidents': 1,
                                      'first_fetch': '10 minutes', 'isFetch': True, 'user_id': 'hellod'})
    mocker.patch('GoogleDrive.fetch_incidents',
                 return_value=(fetch_incidents_output['incidents'], fetch_incidents_output['last_fetch']))
    main()

    demisto.incidents.assert_called_once_with(fetch_incidents_output['incidents'])
    demisto.setLastRun.assert_called_once_with(fetch_incidents_output['last_fetch'])


def test_flatten_move_keys_for_fetch_incident():
    """
    Scenario: Move action parents dictionary should be flatten.

    Given:
    - Move list.

    When:
    - Calling flatten_move_keys_for_fetch_incident with parameters.

    Then:
    - Ensure Dict is flatten as expected.
    """
    from GoogleDrive import flatten_move_keys_for_fetch_incident
    name = 'drive name'
    title = 'drive title'
    output = {
        'driveitemname': name,
        'driveitemtitle': title,
        'driveitemisdrivefile': True,
        'driveitemfoldertype': 'folder type',
        'drivename': name,
        'drivetitle': title
    }
    move = {
        'addedParents': [{'driveItem': {
            'name': name,
            'title': title,
            'driveFile': {},
            'driveFolder': {
                'type': 'folder type'
            }
        },
            'drive': {'name': name,
                      'title': title}}]
    }
    move['removedParents'] = move['addedParents']
    flatten_move_keys_for_fetch_incident(move)
    assert move == {'addedParents': [output], 'removedParents': [output]}


def test_flatten_comment_mentioned_user_keys_for_fetch_incident():
    """
    Scenario: Move action parents dictionary should be flatten.

    Given:
    - Comment mentioned  users list.

    When:
    - Calling flatten_comment_mentioned_user_keys_for_fetch_incident with parameters.

    Then:
    - Ensure Dict is flatten as expected.
    """
    from GoogleDrive import flatten_comment_mentioned_user_keys_for_fetch_incident
    mentioned_users = {'mentionedUsers': [{
        'knownUser': {'personName': 'person name',
                      'isCurrentUser': True},
        'deletedUser': {},
        'unknownUser': {}
    }]}
    output = {'mentionedUsers': [{'personName': 'person name',
                                  'isCurrentUser': True,
                                  'isDeletedUser': True,
                                  'isUnknownUser': True
                                  }]}
    flatten_comment_mentioned_user_keys_for_fetch_incident(mentioned_users)
    assert mentioned_users == output


class TestDriveMethods:

    @patch(MOCKER_HTTP_METHOD)
    def test_drives_list_command_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-drives-list command successful run.

        Given:
        - Command args.

        When:
        - Calling google-drive-drives-list command with the parameters provided.

        Then:
        - Ensure command's raw_response, outputs should be as expected.
        """
        from GoogleDrive import drives_list_command

        with open('test_data/drives_list_response.json', encoding='utf-8') as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {
            'use_domain_admin_access': True
        }
        result = drives_list_command(gsuite_client, args)

        assert 'GoogleDrive.Drive' in result.outputs
        assert result.outputs.get('GoogleDrive.Drive').get('PageToken') == 'myNextPageToken'
        assert len(result.outputs['GoogleDrive.Drive'].get('Drive')) == 4

        assert result.raw_response == mock_response

        assert result.readable_output.startswith("### Total Retrieved Drive(s): ")
        assert HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Drive(s)', 4) in result.readable_output

    @patch(MOCKER_HTTP_METHOD)
    def test_drives_list_command_failure(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drives-list command failure.

        Given:
        - Command args and a non-working google api integration.

        When:
        - Calling google-drives-list command with the parameters provided.

        Then:
        - Ensure command's error response is as expected.
        """
        mocker_http_request.side_effect = DemistoException("SOME_ERROR")

        from GoogleDrive import drives_list_command

        args = {
            'use_domain_admin_access': True
        }

        with pytest.raises(DemistoException, match="SOME_ERROR"):
            drives_list_command(gsuite_client, args)

    @patch(MOCKER_HTTP_METHOD)
    def test_drive_get_command_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-drive-get command successful run.

        Given:
        - Command args.

        When:
        - Calling google-drive-drive-get command with the parameters provided.

        Then:
        - Ensure command's raw_response, outputs should be as expected.
        """
        from GoogleDrive import drive_get_command

        with open('test_data/drive_get_response.json', encoding='utf-8') as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {
            'use_domain_admin_access': True
        }
        result = drive_get_command(gsuite_client, args)

        assert 'GoogleDrive.Drive' in result.outputs
        assert result.outputs.get('GoogleDrive.Drive').get('Drive').get('id') == '17'

        assert result.raw_response == mock_response

        assert HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Drive(s)', 1) in result.readable_output
        assert '17' in result.readable_output

    @patch(MOCKER_HTTP_METHOD)
    def test_drive_get_command_failure(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-get command failure.

        Given:
        - Command args and a non-working google api integration.

        When:
        - Calling google-drive-get command with the parameters provided.

        Then:
        - Ensure command's error response is as expected.
        """
        mocker_http_request.side_effect = ValueError("SOME_ERROR")

        from GoogleDrive import drive_get_command

        args = {
            'use_domain_admin_access': True
        }

        with pytest.raises(ValueError, match="SOME_ERROR"):
            drive_get_command(gsuite_client, args)


class TestFileMethods:

    @patch(MOCKER_HTTP_METHOD)
    def test_files_list_command_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-files-list command successful run.

        Given:
        - Command args.

        When:
        - Calling google-drive-files-list command with the parameters provided.

        Then:
        - Ensure command's raw_response, outputs should be as expected.
        """
        from GoogleDrive import files_list_command

        with open('test_data/files_list_response.json', encoding='utf-8') as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {
            'use_domain_admin_access': True
        }
        result = files_list_command(gsuite_client, args)

        assert 'GoogleDrive.File' in result.outputs
        assert result.outputs.get('GoogleDrive.File').get('PageToken') == 'myNextPageToken'
        assert len(result.outputs['GoogleDrive.File'].get('File')) == 2

        assert result.raw_response == mock_response

        assert result.readable_output.startswith("### Total Retrieved File(s): ")
        assert HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('File(s)', 2) in result.readable_output

    @patch(MOCKER_HTTP_METHOD)
    def test_files_list_command_failure(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-files-list command failure.

        Given:
        - Command args and a non-working google api integration.

        When:
        - Calling google-files-list command with the parameters provided.

        Then:
        - Ensure command's error response is as expected.
        """
        mocker_http_request.side_effect = DemistoException("SOME_ERROR")

        from GoogleDrive import files_list_command

        args = {
            'use_domain_admin_access': True
        }

        with pytest.raises(DemistoException, match="SOME_ERROR"):
            files_list_command(gsuite_client, args)

    @patch(MOCKER_HTTP_METHOD)
    def test_file_get_command_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-file-get command successful run.

        Given:
        - Command args.

        When:
        - Calling google-drive-file-get command with the parameters provided.

        Then:
        - Ensure command's raw_response, outputs should be as expected.
        """
        from GoogleDrive import file_get_command

        with open('test_data/file_get_response.json', encoding='utf-8') as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {
            'use_domain_admin_access': True
        }
        result = file_get_command(gsuite_client, args)

        assert 'GoogleDrive.File' in result.outputs
        assert result.outputs.get('GoogleDrive.File').get('File').get('id') == '17'

        assert result.raw_response == mock_response

        assert HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('File(s)', 1) in result.readable_output
        assert '17' in result.readable_output

    @patch(MOCKER_HTTP_METHOD)
    def test_file_get_command_failure(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-file-get command failure.

        Given:
        - Command args and a non-working google api integration.

        When:
        - Calling google-file-get command with the parameters provided.

        Then:
        - Ensure command's error response is as expected.
        """
        mocker_http_request.side_effect = ValueError("SOME_ERROR")

        from GoogleDrive import file_get_command

        args = {
            'use_domain_admin_access': True
        }

        with pytest.raises(ValueError, match="SOME_ERROR"):
            file_get_command(gsuite_client, args)


class TestFilePermissionMethods:

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_list_command_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-file-permission-list command successful run.

        Given:
        - Command args.

        When:
        - Calling google-drive-file-permission-list command with the parameters provided.

        Then:
        - Ensure command's raw_response, outputs should be as expected.
        """
        from GoogleDrive import file_permission_list_command

        with open('test_data/file_permission_list_response.json', encoding='utf-8') as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {
            'use_domain_admin_access': True
        }
        result = file_permission_list_command(gsuite_client, args)

        assert 'GoogleDrive.FilePermission' in result.outputs
        assert len(result.outputs['GoogleDrive.FilePermission']) == 1

        assert result.raw_response == mock_response

        assert result.readable_output.startswith("### Total")
        assert HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Permission(s)', 1) in result.readable_output

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_list_command_failure(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-file-permission-list command failure.

        Given:
        - Command args and a non-working google api integration.

        When:
        - Calling google-file-permission-list command with the parameters provided.

        Then:
        - Ensure command's error response is as expected.
        """
        mocker_http_request.side_effect = ValueError("SOME_ERROR")

        from GoogleDrive import file_permission_list_command

        args = {
            'use_domain_admin_access': True
        }

        with pytest.raises(ValueError, match="SOME_ERROR"):
            file_permission_list_command(gsuite_client, args)

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_create_command_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-file-permission-create command successful run.

        Given:
        - Command args.

        When:
        - Calling google-drive-file-permission-create command with the parameters provided.

        Then:
        - Ensure command's raw_response, outputs should be as expected.
        """
        from GoogleDrive import file_permission_create_command

        with open('test_data/file_permission_create_response.json', encoding='utf-8') as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {
            'use_domain_admin_access': True
        }
        result = file_permission_create_command(gsuite_client, args)

        assert 'GoogleDrive.FilePermission' in result.outputs
        assert result.outputs.get('GoogleDrive.FilePermission').get('FilePermission').get('id') == '17'

        assert result.raw_response == mock_response

        assert HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Permission(s)', 1) in result.readable_output
        assert '17' in result.readable_output

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_create_command_failure(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-file-permission-create command failure.

        Given:
        - Command args and a non-working google api integration.

        When:
        - Calling google-file-permission-create command with the parameters provided.

        Then:
        - Ensure command's error response is as expected.
        """
        mocker_http_request.side_effect = ValueError("SOME_ERROR")

        from GoogleDrive import file_permission_create_command

        args = {
            'use_domain_admin_access': True
        }

        with pytest.raises(ValueError, match="SOME_ERROR"):
            file_permission_create_command(gsuite_client, args)

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_update_command_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-file-permission-update command successful run.

        Given:
        - Command args.

        When:
        - Calling google-drive-file-permission-update command with the parameters provided.

        Then:
        - Ensure command's raw_response, outputs should be as expected.
        """
        from GoogleDrive import file_permission_update_command

        with open('test_data/file_permission_create_response.json', encoding='utf-8') as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {
            'use_domain_admin_access': True
        }
        result = file_permission_update_command(gsuite_client, args)

        assert 'GoogleDrive.FilePermission' in result.outputs
        assert result.outputs.get('GoogleDrive.FilePermission').get('FilePermission').get('id') == '17'

        assert result.raw_response == mock_response

        assert HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Permission(s)', 1) in result.readable_output
        assert '17' in result.readable_output

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_update_command_failure(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-file-permission-update command failure.

        Given:
        - Command args and a non-working google api integration.

        When:
        - Calling google-file-permission-update command with the parameters provided.

        Then:
        - Ensure command's error response is as expected.
        """
        mocker_http_request.side_effect = ValueError("SOME_ERROR")

        from GoogleDrive import file_permission_update_command

        args = {
            'use_domain_admin_access': True
        }

        with pytest.raises(ValueError, match="SOME_ERROR"):
            file_permission_update_command(gsuite_client, args)

    def test_upload_file_with_parent_command_success(self, mocker, gsuite_client):
        """
        Scenario: For google-drive-file-upload command with the 'parent' arg.

        Given:
        - Command args.

        When:
        - Calling google-drive-file-upload command with the parent arg.

        Then:
        - Ensure parent arg send as expected by Google API (in array).
        """
        import GoogleDrive
        from GoogleDrive import file_upload_command
        import demistomock as demisto

        mocker.patch('googleapiclient.http.HttpRequest.execute')
        mocker.patch('GoogleDrive.handle_response_file_single')
        mocker.patch('GoogleDrive.assign_params', return_value={})
        mocker.patch.object(demisto, 'getFilePath', return_value={'id': 'test_id',
                                                                  'path': 'test_data/drive_changes_hr.txt',
                                                                  'name': 'drive_changes_hr.txt'})

        args = {
            'parent': 'test_parent',
            'entry_id': 'test_entry_id',
            'file_name': 'test_file_name',
            'parent': 'test_parent'

        }
        file_upload_command(gsuite_client, args)
        assert GoogleDrive.assign_params.call_args[1]['parents'] == ['test_parent']
