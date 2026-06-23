from unittest.mock import patch

import pytest
from CommonServerPython import *
from GoogleDrive import HR_MESSAGES, MESSAGES, OUTPUT_PREFIX, GSuiteClient

with open("test_data/service_account_json.txt") as f:
    TEST_JSON = f.read()

MOCKER_HTTP_METHOD = "GSuiteApiModule.GSuiteClient.http_request"


@pytest.fixture
def gsuite_client():
    headers = {"Content-Type": "application/json"}
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
    from GoogleDrive import GSuiteClient, test_module

    mocker.patch.object(GSuiteClient, "set_authorized_http")
    mocker.patch.object(GSuiteClient, "http_request")
    assert test_module(gsuite_client, {}, {}) == "ok"


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

    with open("test_data/drive_create_response.json", encoding="utf-8") as data:
        response_data = json.load(data)
    mocker_http_request.return_value = response_data

    result = drive_create_command(gsuite_client, {})

    assert result.raw_response == response_data
    assert result.outputs == response_data
    assert result.readable_output.startswith("### " + HR_MESSAGES["DRIVE_CREATE_SUCCESS"])
    assert result.outputs_key_field == "id"
    assert result.outputs_prefix == OUTPUT_PREFIX["GOOGLE_DRIVE_HEADER"]


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

    with open("test_data/drive_changes_response.json", encoding="utf-8") as data:
        mock_response = json.load(data)
    with open("test_data/drive_changes_drive_context.json", encoding="utf-8") as data:
        expected_res = json.load(data)
    mocker_http_request.return_value = mock_response

    with open("test_data/drive_changes_hr.txt") as data:
        expected_hr = data.read()
    args = {"user_id": "user@test.com", "page_token": "1"}
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
    args = {"page_token": "1", "user_id": "user@test.comm", "fields": "advance"}
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

    fields = "fields"
    arguments = {
        "page_token": "1",
        "drive_id": "driveId",
        "include_corpus_removals": "false",
        "include_items_from_all_drives": "false",
        "include_removed": "false",
        "restrict_to_my_drive": "false",
        "supports_all_drives": "false",
        fields: "advance",
        "page_size": "1",
        "spaces": "drive,appDataFolder",
        "include_permissions_for_view": "published",
    }
    expected_arguments = {
        "pageToken": "1",
        "driveId": "driveId",
        "includeCorpusRemovals": False,
        "includeItemsFromAllDrives": False,
        "includeRemoved": False,
        "restrictToMyDrive": False,
        "supportsAllDrives": False,
        fields: "*",
        "pageSize": 1,
        "spaces": "drive,appDataFolder",
        "includePermissionsForView": "published",
    }
    assert prepare_params_for_drive_changes_list(arguments) == expected_arguments

    arguments = {fields: "some"}
    with pytest.raises(ValueError) as e:
        prepare_params_for_drive_changes_list(arguments)
    assert MESSAGES["DRIVE_CHANGES_FIELDS"].format(fields) == str(e.value)

    arguments = {"page_size": "-1"}
    with pytest.raises(ValueError) as e:
        prepare_params_for_drive_changes_list(arguments)
    assert MESSAGES["INTEGER_ERROR"].format("page_size") == str(e.value)


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
        "folder_name": "items/1",
        "item_name": "items/2",
        "filter": 'time >= "2020-09-17T13:19:10.197Z"',
        "time_range": "5 days",
        "action_detail_case_include": "RENAME",
        "action_detail_case_remove": "CREATE",
        "page_token": "token123",
    }

    expected_body = {
        "ancestorName": args.get("folder_name"),
        "itemName": args.get("item_name"),
        "pageToken": args.get("page_token"),
        "filter": args.get("filter"),
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

    with open("test_data/drive_activity_response.json", encoding="utf-8") as data:
        mock_response = json.load(data)
    with open("test_data/drive_activity_context.json", encoding="utf-8") as data:
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

    with open("test_data/drive_activity_primary_activities.json", encoding="utf-8") as data:
        mock_response = json.load(data)
    with open("test_data/drive_activity_list_hr.txt") as data:
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

    params = {"isFetch": True, "drive_item_search_value": "create", "max_fetch": "abc", "user_id": "helo"}
    with pytest.raises(ValueError, match=MESSAGES["FETCH_INCIDENT_REQUIRED_ARGS"]):
        validate_params_for_fetch_incidents(params)
        params.pop("drive_item_search_value")
        params["drive_item_search_field"] = "create"
        validate_params_for_fetch_incidents(params)

    with pytest.raises(ValueError, match=MESSAGES["MAX_INCIDENT_ERROR"]):
        params.pop("drive_item_search_value")
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
        "action_detail_case_include": ["create", "edit"],
    }
    assert prepare_args_for_fetch_incidents(0, params) == {
        "filter": "time > 0 AND detail.action_detail_case: (CREATE EDIT)",
        "pageSize": 100,
    }
    with pytest.raises(ValueError, match=MESSAGES["FETCH_INCIDENT_REQUIRED_ARGS"]):
        prepare_args_for_fetch_incidents(0, {"drive_item_search_value": "a"})


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
        "drive_item_search_field": "create",
        "drive_item_search_value": "create",
        "action_detail_case_include": ["create", "edit"],
        "user_id": "user@domain.io",
    }
    with open("test_data/fetch_incidents_response.json") as file:
        fetch_incidents_response = json.load(file)
    mocker.patch(MOCKER_HTTP_METHOD, return_value=fetch_incidents_response)
    with open("test_data/fetch_incidents_output.json") as file:
        fetch_incidents_output = json.load(file)
    mocker.patch(MOCKER_HTTP_METHOD, return_value=fetch_incidents_response)
    params["first_fetch"] = "10 day"
    params["max_incidents"] = 10
    fetch_incident = fetch_incidents(gsuite_client, {}, params)
    assert fetch_incident[0] == fetch_incidents_output["incidents"]


def test_main_fetch_incidents(mocker):
    """
    Given working service integration
    When fetch-incidents is called from main()
    Then demistomock.incidents and demistomock.setLastRun should be called with respected values.

    :param args: Mocker objects.
    :return: None
    """
    from GoogleDrive import demisto, main

    with open("test_data/fetch_incidents_output.json") as file:
        fetch_incidents_output = json.load(file)
    mocker.patch.object(demisto, "command", return_value="fetch-incidents")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "incidents")
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "user_service_account_json": TEST_JSON,
            "max_incidents": 1,
            "first_fetch": "10 minutes",
            "isFetch": True,
            "user_id": "hellod",
        },
    )
    mocker.patch(
        "GoogleDrive.fetch_incidents", return_value=(fetch_incidents_output["incidents"], fetch_incidents_output["last_fetch"])
    )
    main()

    demisto.incidents.assert_called_once_with(fetch_incidents_output["incidents"])
    demisto.setLastRun.assert_called_once_with(fetch_incidents_output["last_fetch"])


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

    name = "drive name"
    title = "drive title"
    output = {
        "driveitemname": name,
        "driveitemtitle": title,
        "driveitemisdrivefile": True,
        "driveitemfoldertype": "folder type",
        "drivename": name,
        "drivetitle": title,
    }
    move = {
        "addedParents": [
            {
                "driveItem": {"name": name, "title": title, "driveFile": {}, "driveFolder": {"type": "folder type"}},
                "drive": {"name": name, "title": title},
            }
        ]
    }
    move["removedParents"] = move["addedParents"]
    flatten_move_keys_for_fetch_incident(move)
    assert move == {"addedParents": [output], "removedParents": [output]}


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

    mentioned_users = {
        "mentionedUsers": [
            {"knownUser": {"personName": "person name", "isCurrentUser": True}, "deletedUser": {}, "unknownUser": {}}
        ]
    }
    output = {
        "mentionedUsers": [{"personName": "person name", "isCurrentUser": True, "isDeletedUser": True, "isUnknownUser": True}]
    }
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

        with open("test_data/drives_list_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {"use_domain_admin_access": True}
        result = drives_list_command(gsuite_client, args)

        assert "GoogleDrive.Drive" in result.outputs
        assert result.outputs.get("GoogleDrive.Drive").get("PageToken") == "myNextPageToken"
        assert len(result.outputs["GoogleDrive.Drive"].get("Drive")) == 4

        assert result.raw_response == mock_response

        assert result.readable_output.startswith("### Total Retrieved Drive(s): ")
        assert HR_MESSAGES["LIST_COMMAND_SUCCESS"].format("Drive(s)", 4) in result.readable_output

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

        args = {"use_domain_admin_access": True}

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

        with open("test_data/drive_get_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {"use_domain_admin_access": True}
        result = drive_get_command(gsuite_client, args)

        assert "GoogleDrive.Drive" in result.outputs
        assert result.outputs.get("GoogleDrive.Drive").get("Drive").get("id") == "17"

        assert result.raw_response == mock_response

        assert HR_MESSAGES["LIST_COMMAND_SUCCESS"].format("Drive(s)", 1) in result.readable_output
        assert "17" in result.readable_output

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

        args = {"use_domain_admin_access": True}

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

        with open("test_data/files_list_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {"use_domain_admin_access": True}
        result = files_list_command(gsuite_client, args)

        assert "GoogleDrive.File" in result.outputs
        assert result.outputs.get("GoogleDrive.File").get("PageToken") == "myNextPageToken"
        assert len(result.outputs["GoogleDrive.File"].get("File")) == 2

        assert result.raw_response == mock_response

        assert result.readable_output.startswith("### Total Retrieved File(s): ")
        assert HR_MESSAGES["LIST_COMMAND_SUCCESS"].format("File(s)", 2) in result.readable_output

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

        args = {"use_domain_admin_access": True}

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

        with open("test_data/file_get_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {"use_domain_admin_access": True}
        result = file_get_command(gsuite_client, args)

        assert "GoogleDrive.File" in result.outputs
        assert result.outputs.get("GoogleDrive.File").get("File").get("id") == "17"

        assert result.raw_response == mock_response

        assert HR_MESSAGES["LIST_COMMAND_SUCCESS"].format("File(s)", 1) in result.readable_output
        assert "17" in result.readable_output

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

        args = {"use_domain_admin_access": True}

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

        with open("test_data/file_permission_list_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {"use_domain_admin_access": True}
        result = file_permission_list_command(gsuite_client, args)

        assert "GoogleDrive.FilePermission" in result.outputs
        assert len(result.outputs["GoogleDrive.FilePermission"]) == 1

        assert result.raw_response == mock_response

        assert result.readable_output.startswith("### Total")
        assert HR_MESSAGES["LIST_COMMAND_SUCCESS"].format("Permission(s)", 1) in result.readable_output

    @patch(MOCKER_HTTP_METHOD)
    def test_list_labels(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-list-labels command successful run.

        Given:
        - Command args.

        When:
        - Calling google-drive-list-labels  command with the parameters provided.

        Then:
        - Ensure command's raw_response, outputs should be as expected.
        """
        from GoogleDrive import get_labels_command

        with open("test_data/list_labels_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        result = get_labels_command(gsuite_client, {})

        assert "GoogleDrive.Labels" in result.outputs
        assert len(result.outputs["GoogleDrive.Labels"]["labels"]) == 2

    @patch(MOCKER_HTTP_METHOD)
    def test_modify_labels_command(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-modify-label command successful run.

        Given:
        - Command args.

        When:
        - Calling google-drive-modify-label command with the parameters provided.

        Then:
        - Ensure command's raw_response, outputs should be as expected.
        """
        from GoogleDrive import modify_label_command

        with open("test_data/modify_label_command_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {"field_id": "test", "selection_label_id": "test", "label_id": "test", "file_id": "test"}
        result = modify_label_command(gsuite_client, args)

        assert "modifiedLabels" in result.outputs.get("GoogleDrive.Labels")
        assert (
            result.outputs.get("GoogleDrive.Labels").get("modifiedLabels")[0].get("id")
            == "vFmXsMA1fQMz1BdE59YSkisZV4DiKdpxxLQRNNEbbFcb"
        )

        assert result.raw_response == mock_response

        assert HR_MESSAGES["MODIFY_LABEL_SUCCESS"].format(args.get("file_id")) in result.readable_output

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

        args = {"use_domain_admin_access": True}

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

        with open("test_data/file_permission_create_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {"use_domain_admin_access": True}
        result = file_permission_create_command(gsuite_client, args)

        assert "GoogleDrive.FilePermission" in result.outputs
        assert result.outputs.get("GoogleDrive.FilePermission").get("FilePermission").get("id") == "17"

        assert result.raw_response == mock_response

        assert HR_MESSAGES["LIST_COMMAND_SUCCESS"].format("Permission(s)", 1) in result.readable_output
        assert "17" in result.readable_output

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

        args = {"use_domain_admin_access": True}

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

        with open("test_data/file_permission_create_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {"use_domain_admin_access": True}
        result = file_permission_update_command(gsuite_client, args)

        assert "GoogleDrive.FilePermission" in result.outputs
        assert result.outputs.get("GoogleDrive.FilePermission").get("FilePermission").get("id") == "17"

        assert result.raw_response == mock_response

        assert HR_MESSAGES["LIST_COMMAND_SUCCESS"].format("Permission(s)", 1) in result.readable_output
        assert "17" in result.readable_output

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

        args = {"use_domain_admin_access": True}

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
        import demistomock as demisto
        import GoogleDrive
        from GoogleDrive import file_upload_command

        mocker.patch("googleapiclient.http.HttpRequest.execute")
        mocker.patch("GoogleDrive.handle_response_file_single")
        mocker.patch("GoogleDrive.assign_params", return_value={})
        mocker.patch.object(
            demisto,
            "getFilePath",
            return_value={"id": "test_id", "path": "test_data/drive_changes_hr.txt", "name": "drive_changes_hr.txt"},
        )

        args = {"parent": "test_parent", "entry_id": "test_entry_id", "file_name": "test_file_name"}
        file_upload_command(gsuite_client, args)
        assert GoogleDrive.assign_params.call_args[1]["parents"] == ["test_parent"]

    def test_file_copy_command(self, mocker, gsuite_client):
        """
        Given:
        - A request to copy a Drive file.

        When:
        - Calling google-drive-file-copy.

        Then:
        - Copy the Drive file.
        """

        from GoogleDrive import file_copy_command

        mocker.patch(
            "GoogleDrive.copy_file_http_request",
            return_value={
                "id": "test_id",
                "kind": "drive#file",
                "mimeType": "application/octet-stream",
                "name": "TEST COPY",
            },
        )

        results = file_copy_command(
            gsuite_client,
            args={
                "file_id": "test_file_id",
                "copy_title": "test_copy_title",
                "supports_all_drives": "true",
                "user_id": "test_user_id",
            },
        )

        assert results.outputs == {
            "id": "test_id",
            "kind": "drive#file",
            "mimeType": "application/octet-stream",
            "name": "TEST COPY",
        }
        assert results.readable_output == (
            "### File copied successfully.\n"
            "|Id|Kind|Mimetype|Name|\n"
            "|---|---|---|---|\n"
            "| test_id | drive#file | application/octet-stream | TEST COPY |\n"
        )

    def test_file_copy_command_error(self, mocker, gsuite_client):
        """
        Given:
        - A request to copy a Drive file with an error.

        When:
        - Calling google-drive-file-copy.

        Then:
        - Return an error gracefully.
        """
        from GoogleDrive import errors, file_copy_command

        def raise_error():
            raise errors.HttpError(resp=type("MockRequest", (), {"status": 400, "reason": "Bad Request"}), content=b"Bad Request")

        mocker.patch("googleapiclient.http.HttpRequest.execute", side_effect=raise_error)

        with pytest.raises(DemistoException, match="Status Code: 400"):
            file_copy_command(
                gsuite_client,
                args={
                    "file_id": "test_file_id",
                    "copy_title": "test_copy_title",
                    "supports_all_drives": "true",
                    "user_id": "test_user_id",
                },
            )

    @patch(MOCKER_HTTP_METHOD)
    def test_drive_get_file_parents_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: For file_get_parents command successful run.

        Given:
        - Command args.

        When:
        - Calling google-drive-get-file-parents command with the parameters provided.

        Then:
        - Ensure command's raw_response, outputs should be as expected.
        """
        from GoogleDrive import file_get_parents

        with open("test_data/get_parents_list.txt", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {"use_domain_admin_access": True, "file_id": "test", "user_id": "test"}
        result: CommandResults = file_get_parents(gsuite_client, args)

        assert len(result.outputs.get("GoogleDrive.File.Parents", [])) == 1  # type: ignore
        assert result.raw_response == mock_response

    @patch(MOCKER_HTTP_METHOD)
    def test_file_move_command_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-file-move command successful run.

        Given:
        - Command args.

        When:
        - Calling google-drive-file-move command with the parameters provided.

        Then:
        - Ensure command's outputs and readable_output should be as expected.
        """
        from GoogleDrive import file_move_command

        with open("test_data/file_move_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {
            "file_id": "1234567890abcdef",
            "add_parent_id": "quarantine_folder_id_123",
            "remove_parent_id": "original_folder_id_789",
            "user_id": "admin@example.com",
        }
        result: CommandResults = file_move_command(gsuite_client, args)

        assert result.outputs_prefix == "GoogleDrive.File"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "1234567890abcdef"
        assert result.outputs["parents"] == ["quarantine_folder_id_123"]
        assert "moved successfully" in result.readable_output

    @patch(MOCKER_HTTP_METHOD)
    def test_file_create_command_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-file-create command successful run for folder creation.

        Given:
        - Command args.

        When:
        - Calling google-drive-file-create command with the parameters provided.

        Then:
        - Ensure command's outputs and readable_output should be as expected.
        """
        from GoogleDrive import file_create_command

        with open("test_data/file_create_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {
            "file_name": "Quarantine Folder",
            "mime_type": "application/vnd.google-apps.folder",
            "user_id": "admin@example.com",
            "parent": "root",
        }
        result: CommandResults = file_create_command(gsuite_client, args)

        assert result.outputs_prefix == "GoogleDrive.File"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "new_folder_id_456"
        assert result.outputs["mimeType"] == "application/vnd.google-apps.folder"
        assert "Created" in result.readable_output

        # Verify the request body and params
        _, call_kwargs = mocker_http_request.call_args
        assert call_kwargs["body"]["name"] == "Quarantine Folder"
        assert call_kwargs["body"]["parents"] == ["root"]
        # supports_all_drives defaults to False when not provided
        assert call_kwargs["params"]["supportsAllDrives"] is False

    @patch(MOCKER_HTTP_METHOD)
    def test_file_create_tombstone_command_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-file-create command successful run for tombstone placeholder creation.

        Given:
        - Command args for creating a tombstone placeholder file.

        When:
        - Calling google-drive-file-create command with the parameters provided.

        Then:
        - Ensure command's outputs should be as expected.
        """
        from GoogleDrive import file_create_command

        mock_response = {
            "kind": "drive#file",
            "id": "tombstone_id_789",
            "name": "This file has been quarantined",
            "mimeType": "application/vnd.google-apps.document",
            "parents": ["original_folder_id"],
            "description": "This file was quarantined by security policy. Contact admin for details.",
        }
        mocker_http_request.return_value = mock_response

        args = {
            "file_name": "This file has been quarantined",
            "mime_type": "application/vnd.google-apps.document",
            "user_id": "admin@example.com",
            "parent": "original_folder_id",
            "description": "This file was quarantined by security policy. Contact admin for details.",
        }
        result: CommandResults = file_create_command(gsuite_client, args)

        assert result.outputs["id"] == "tombstone_id_789"
        assert result.outputs["mimeType"] == "application/vnd.google-apps.document"

    @patch(MOCKER_HTTP_METHOD)
    def test_file_create_command_supports_all_drives(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-file-create command run with supports_all_drives="true".

        Given:
        - Command args including supports_all_drives="true".

        When:
        - Calling google-drive-file-create command with the parameters provided.

        Then:
        - Ensure supportsAllDrives is forwarded to the API as True.
        """
        from GoogleDrive import file_create_command

        mock_response = {
            "kind": "drive#file",
            "id": "shared_drive_folder_id",
            "name": "Shared Drive Folder",
            "mimeType": "application/vnd.google-apps.folder",
            "parents": ["shared_drive_root_id"],
        }
        mocker_http_request.return_value = mock_response

        args = {
            "file_name": "Shared Drive Folder",
            "mime_type": "application/vnd.google-apps.folder",
            "user_id": "admin@example.com",
            "parent": "shared_drive_root_id",
            "supports_all_drives": "true",
        }
        result: CommandResults = file_create_command(gsuite_client, args)

        assert result.outputs["id"] == "shared_drive_folder_id"
        _, call_kwargs = mocker_http_request.call_args
        assert call_kwargs["params"]["supportsAllDrives"] is True
        assert call_kwargs["body"]["name"] == "Shared Drive Folder"
        assert call_kwargs["body"]["parents"] == ["shared_drive_root_id"]

def test_mask_sensitive_values():
    """
    Scenario: Mask sensitive values in a params dictionary.

    Given:
    - A dictionary containing sensitive and non-sensitive keys, including nested dicts.

    When:
    - Calling mask_sensitive_values.

    Then:
    - Ensure sensitive values are redacted and non-sensitive values are preserved.
    """
    from GoogleDrive import mask_sensitive_values

    data = {
        "user_id": "admin@example.com",
        "insecure": False,
        "user_service_account_json": "super-secret-json",
        "user_creds": {"identifier": "id@example.com", "password": "p@ss"},
    }

    result = mask_sensitive_values(data)

    assert result["user_id"] == "admin@example.com"
    assert result["insecure"] is False
    assert result["user_service_account_json"] == "***"
    assert result["user_creds"]["identifier"] == "***"
    assert result["user_creds"]["password"] == "***"


def test_connectus_info_command_ucp_disabled(mocker, gsuite_client):
    """
    Scenario: Run connectus-info command when UCP is disabled.

    Given:
    - UCP is not enabled and integration params are configured.

    When:
    - Calling connectus_info_command.

    Then:
    - Ensure ucp_enabled is False and sensitive params are masked.
    """
    from GoogleDrive import connectus_info_command

    mocker.patch("GoogleDrive.should_use_ucp_auth", return_value=False)
    mocker.patch.object(
        demisto,
        "params",
        return_value={"user_id": "admin@example.com", "user_service_account_json": "secret"},
    )

    result: CommandResults = connectus_info_command(gsuite_client, {})

    assert result.outputs["ConnectUs"]["ucp_enabled"] is False
    assert result.outputs["Params"]["user_service_account_json"] == "***"
    assert result.outputs["Params"]["user_id"] == "admin@example.com"


def test_connectus_info_command_ucp_enabled(mocker, gsuite_client):
    """
    Scenario: Run connectus-info command when UCP is enabled.

    Given:
    - UCP is enabled and a capability/method id can be resolved.

    When:
    - Calling connectus_info_command.

    Then:
    - Ensure capability and method_unique_id are included in the output.
    """
    from GoogleDrive import connectus_info_command

    mocker.patch("GoogleDrive.should_use_ucp_auth", return_value=True)
    mocker.patch("GoogleDrive.resolve_ucp_capability", return_value="automation-and-remediation")
    mocker.patch("GoogleDrive.get_ucp_method_unique_id", return_value="method-123")
    mocker.patch.object(demisto, "params", return_value={"user_id": "admin@example.com"})

    result: CommandResults = connectus_info_command(gsuite_client, {})

    assert result.outputs["ConnectUs"]["ucp_enabled"] is True
    assert result.outputs["ConnectUs"]["capability"] == "automation-and-remediation"
    assert result.outputs["ConnectUs"]["method_unique_id"] == "method-123"

    @patch(MOCKER_HTTP_METHOD)
    def test_file_delete_command_soft_delete_true(self, mocker_http_request, gsuite_client):
        """
        Scenario: google-drive-file-delete invoked with soft_delete=true.

        Given:
        - file_id, user_id, and soft_delete=true.

        When:
        - Calling file_delete_command.

        Then:
        - The HTTP call is a PATCH (not DELETE) with body {"trashed": True}, and
          the response's trashed field is surfaced under GoogleDrive.File.File.
        """
        from GoogleDrive import file_delete_command

        mock_response = {
            "kind": "drive#file",
            "id": "file_id_123",
            "name": "Quarterly Report.docx",
            "mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "trashed": True,
            "trashedTime": "2026-05-29T12:00:00.000Z",
        }
        mocker_http_request.return_value = mock_response

        args = {"file_id": "file_id_123", "user_id": "owner@example.com", "soft_delete": "true"}
        result: CommandResults = file_delete_command(gsuite_client, args)

        _, call_kwargs = mocker_http_request.call_args
        assert call_kwargs["method"] == "PATCH"
        assert call_kwargs["body"] == {"trashed": True}
        assert "drive/v3/files/file_id_123" in call_kwargs["url_suffix"]

        file_ctx = result.outputs.get("GoogleDrive.File").get("File")
        assert file_ctx.get("trashed") is True
        assert file_ctx.get("trashedTime") == "2026-05-29T12:00:00.000Z"

    @patch(MOCKER_HTTP_METHOD)
    def test_file_delete_command_soft_delete_default_hard_delete(self, mocker_http_request, gsuite_client):
        """
        Scenario: google-drive-file-delete invoked without soft_delete.

        Given:
        - file_id, user_id, and no soft_delete argument (default behavior).

        When:
        - Calling file_delete_command.

        Then:
        - The HTTP call is a DELETE (existing behavior preserved bit-for-bit),
          no PATCH body is sent, and the legacy output shape is emitted.
        """
        from GoogleDrive import file_delete_command

        mocker_http_request.return_value = None

        args = {"file_id": "file_id_456", "user_id": "owner@example.com"}
        result: CommandResults = file_delete_command(gsuite_client, args)

        _, call_kwargs = mocker_http_request.call_args
        assert call_kwargs["method"] == "DELETE"
        # The legacy DELETE path must not send a body.
        assert "body" not in call_kwargs or call_kwargs.get("body") is None

        file_ctx = result.outputs.get("GoogleDrive.File").get("File")
        assert file_ctx.get("id") == "file_id_456"
        assert "trashed" not in file_ctx

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_create_command_transfer_ownership(self, mocker_http_request, gsuite_client):
        """
        Scenario: google-drive-file-permission-create invoked with transfer_ownership=true.

        Given:
        - role=owner, type=user, email_address set, and transfer_ownership=true.

        When:
        - Calling file_permission_create_command.

        Then:
        - The transferOwnership query parameter is forwarded to the vendor;
          when the argument is omitted on a second call, the parameter is absent.
        """
        from GoogleDrive import file_permission_create_command

        with open("test_data/file_permission_create_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args_with = {
            "file_id": "file_id_789",
            "user_id": "admin@example.com",
            "role": "owner",
            "type": "user",
            "email_address": "newowner@example.com",
            "transfer_ownership": "true",
        }
        file_permission_create_command(gsuite_client, args_with)
        _, call_kwargs_with = mocker_http_request.call_args
        assert call_kwargs_with["params"].get("transferOwnership") == "true"

        args_without = {
            "file_id": "file_id_789",
            "user_id": "admin@example.com",
            "role": "reader",
            "type": "user",
            "email_address": "viewer@example.com",
        }
        file_permission_create_command(gsuite_client, args_without)
        _, call_kwargs_without = mocker_http_request.call_args
        assert "transferOwnership" not in call_kwargs_without["params"]

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_create_command_move_to_new_owners_root(self, mocker_http_request, gsuite_client):
        """
        Scenario: google-drive-file-permission-create invoked with move_to_new_owners_root.

        Given:
        - role=owner, transfer_ownership=true, and move_to_new_owners_root=true.

        When:
        - Calling file_permission_create_command.

        Then:
        - The moveToNewOwnersRoot query parameter is forwarded to the vendor;
          when the argument is omitted on a second call, the parameter is absent.
        """
        from GoogleDrive import file_permission_create_command

        with open("test_data/file_permission_create_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args_with = {
            "file_id": "file_id_789",
            "user_id": "admin@example.com",
            "role": "owner",
            "type": "user",
            "email_address": "newowner@example.com",
            "transfer_ownership": "true",
            "move_to_new_owners_root": "true",
        }
        file_permission_create_command(gsuite_client, args_with)
        _, call_kwargs_with = mocker_http_request.call_args
        assert call_kwargs_with["params"].get("moveToNewOwnersRoot") == "true"

        args_without = {
            "file_id": "file_id_789",
            "user_id": "admin@example.com",
            "role": "owner",
            "type": "user",
            "email_address": "newowner@example.com",
            "transfer_ownership": "true",
        }
        file_permission_create_command(gsuite_client, args_without)
        _, call_kwargs_without = mocker_http_request.call_args
        assert "moveToNewOwnersRoot" not in call_kwargs_without["params"]

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_delete_command_ignore_not_found_404_treated_success(self, mocker_http_request, gsuite_client):
        """
        Scenario: google-drive-file-permission-delete with ignore_not_found=true on a permission Not Found.

        Given:
        - The shared GSuite client raises DemistoException carrying the
          documented "Permission not found" reason from Drive.
        - ignore_not_found=true.

        When:
        - Calling file_permission_delete_command.

        Then:
        - The exception is swallowed and the result surfaces alreadyRemoved=True.
        - With ignore_not_found omitted, the same Not Found still raises
          (default behavior preserved).
        """
        from GoogleDrive import file_permission_delete_command

        args = {
            "file_id": "file_id_999",
            "user_id": "admin@example.com",
            "permission_id": "perm_id_111",
            "ignore_not_found": "true",
        }

        # Real-world payload observed from production.
        mocker_http_request.side_effect = DemistoException("Not found. Reason: Permission not found: 12849315382336496719.")
        result: CommandResults = file_permission_delete_command(gsuite_client, args)
        perm_ctx = result.outputs.get("GoogleDrive.FilePermission").get("FilePermission")
        assert perm_ctx.get("alreadyRemoved") is True
        assert perm_ctx.get("id") == "perm_id_111"
        assert perm_ctx.get("fileId") == "file_id_999"

        # Default behavior preserved: with ignore_not_found omitted, the same
        # Not Found still raises.
        args_default = dict(args)
        args_default.pop("ignore_not_found")
        with pytest.raises(DemistoException, match=r"(?i)permission not found"):
            file_permission_delete_command(gsuite_client, args_default)

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_delete_command_ignore_not_found_file_not_found_still_raises(
        self, mocker_http_request, gsuite_client
    ):
        """
        Scenario: bogus file_id with ignore_not_found=true must still raise.

        Given:
        - The shared GSuite client raises DemistoException carrying "File not
          found" (the parent file does not exist, not the permission).
        - ignore_not_found=true.

        When:
        - Calling file_permission_delete_command.

        Then:
        - The exception still raises; only "permission not found" is swallowed
          so operator typos in file_id are not silently masked.
        """
        from GoogleDrive import file_permission_delete_command

        mocker_http_request.side_effect = DemistoException("Not found. Reason: File not found: bogus_file_id_123.")

        args = {
            "file_id": "bogus_file_id_123",
            "user_id": "admin@example.com",
            "permission_id": "perm_id_111",
            "ignore_not_found": "true",
        }
        with pytest.raises(DemistoException, match=r"(?i)file not found"):
            file_permission_delete_command(gsuite_client, args)

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_delete_command_ignore_not_found_other_error_still_raises(self, mocker_http_request, gsuite_client):
        """
        Scenario: google-drive-file-permission-delete with ignore_not_found=true on non-Not Found.

        Given:
        - The shared GSuite client raises a Forbidden DemistoException (not a 404).
        - ignore_not_found=true.

        When:
        - Calling file_permission_delete_command.

        Then:
        - The exception is still raised; only Not Found is swallowed.
        """
        from GoogleDrive import file_permission_delete_command

        mocker_http_request.side_effect = DemistoException("HTTP Connection error occurred. Status: 403. Reason: Forbidden")

        args = {
            "file_id": "file_id_999",
            "user_id": "admin@example.com",
            "permission_id": "perm_id_222",
            "ignore_not_found": "true",
        }
        with pytest.raises(DemistoException, match="Status: 403"):
            file_permission_delete_command(gsuite_client, args)

    @patch(MOCKER_HTTP_METHOD)
    def test_file_permission_list_command_inherited_output(self, mocker_http_request, gsuite_client):
        """
        Scenario: google-drive-file-permissions-list surfaces permissionDetails.

        Given:
        - A vendor response containing permissionDetails with inherited=true.

        When:
        - Calling file_permission_list_command.

        Then:
        - The permissionDetails field is surfaced under
          GoogleDrive.FilePermission.FilePermission so playbooks can filter on it.
        """
        from GoogleDrive import file_permission_list_command

        mock_response = {
            "kind": "drive#permissionList",
            "permissions": [
                {
                    "id": "perm_inherited",
                    "type": "user",
                    "role": "writer",
                    "emailAddress": "shared@example.com",
                    "permissionDetails": [
                        {
                            "permissionType": "file",
                            "role": "writer",
                            "inheritedFrom": "parent_folder_id",
                            "inherited": True,
                        }
                    ],
                }
            ],
        }
        mocker_http_request.return_value = mock_response

        args = {"file_id": "file_id_xyz", "user_id": "owner@example.com", "supports_all_drives": "true"}
        result: CommandResults = file_permission_list_command(gsuite_client, args)

        perm_ctx = result.outputs.get("GoogleDrive.FilePermission").get("FilePermission")
        # The list command surfaces an array; the helper may emit a single dict
        # when there is one permission. Normalize for the assertion.
        perms = perm_ctx if isinstance(perm_ctx, list) else [perm_ctx]
        assert perms[0].get("permissionDetails")[0].get("inherited") is True
        assert perms[0].get("permissionDetails")[0].get("inheritedFrom") == "parent_folder_id"
        assert perms[0].get("permissionDetails")[0].get("permissionType") == "file"
