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
        # When mime_type is provided, it must be forwarded as-is in the request body.
        assert call_kwargs["body"]["mimeType"] == "application/vnd.google-apps.folder"
        # supports_all_drives defaults to False when not provided
        assert call_kwargs["params"]["supportsAllDrives"] is False

    @patch(MOCKER_HTTP_METHOD)
    def test_file_create_command_with_mime_type(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-file-create command with an explicit mime_type.

        Given:
        - Command args including mime_type="application/vnd.google-apps.document".

        When:
        - Calling google-drive-file-create command with the parameters provided.

        Then:
        - Ensure the request body includes the provided mimeType value.
        """
        from GoogleDrive import file_create_command

        mock_response = {
            "kind": "drive#file",
            "id": "doc_id_001",
            "name": "My Document",
            "mimeType": "application/vnd.google-apps.document",
        }
        mocker_http_request.return_value = mock_response

        args = {
            "file_name": "My Document",
            "mime_type": "application/vnd.google-apps.document",
            "user_id": "admin@example.com",
        }
        file_create_command(gsuite_client, args)

        _, call_kwargs = mocker_http_request.call_args
        assert call_kwargs["body"]["name"] == "My Document"
        assert call_kwargs["body"]["mimeType"] == "application/vnd.google-apps.document"

    @patch(MOCKER_HTTP_METHOD)
    def test_file_create_command_without_mime_type(self, mocker_http_request, gsuite_client):
        """
        Scenario: For google-drive-file-create command without mime_type argument.

        Given:
        - Command args without mime_type.

        When:
        - Calling google-drive-file-create command with the parameters provided.

        Then:
        - Ensure the request body does NOT include a mimeType key
          (so Google Drive infers the type instead of receiving an empty value).
        """
        from GoogleDrive import file_create_command

        mock_response = {
            "kind": "drive#file",
            "id": "no_mime_id_001",
            "name": "Untyped File",
        }
        mocker_http_request.return_value = mock_response

        args = {
            "file_name": "Untyped File",
            "user_id": "admin@example.com",
        }
        file_create_command(gsuite_client, args)

        _, call_kwargs = mocker_http_request.call_args
        assert call_kwargs["body"]["name"] == "Untyped File"
        # mimeType key must be omitted entirely when the arg is not provided.
        assert "mimeType" not in call_kwargs["body"]

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

# ---------------------------------------------------------------------------
# Backward-compatible extensions on existing commands. Each new optional
# argument has at least one "default-behavior preserved" test that locks
# the existing wire-protocol shape, plus one "new behavior activated"
# test that asserts the new branch.
# ---------------------------------------------------------------------------


class TestFileDeleteSoftDelete:
    """!google-drive-file-delete + soft_delete arg."""

    @patch(MOCKER_HTTP_METHOD)
    def test_file_delete_default_is_permanent_purge(self, mocker_http_request, gsuite_client):
        """
        Scenario: soft_delete arg absent — must call DELETE
        (the existing permanent-purge behavior is preserved bit-for-bit).
        """
        from GoogleDrive import file_delete_command

        mocker_http_request.return_value = ""

        args = {"file_id": "FILE123", "user_id": "user@example.com"}
        result = file_delete_command(gsuite_client, args)

        assert mocker_http_request.call_count == 1
        call_kwargs = mocker_http_request.call_args.kwargs
        assert call_kwargs["method"] == "DELETE"
        assert call_kwargs["url_suffix"] == "drive/v3/files/FILE123"
        # No body for the legacy DELETE branch.
        assert "body" not in call_kwargs

        outputs_context = result.outputs["GoogleDrive.File"]["File"]
        assert outputs_context["id"] == "FILE123"
        assert "trashed" not in outputs_context  # legacy output shape preserved

    @patch(MOCKER_HTTP_METHOD)
    def test_file_delete_default_is_permanent_purge_when_false(self, mocker_http_request, gsuite_client):
        """soft_delete=false must behave identically to soft_delete absent."""
        from GoogleDrive import file_delete_command

        mocker_http_request.return_value = ""

        args = {"file_id": "FILE123", "user_id": "user@example.com", "soft_delete": "false"}
        file_delete_command(gsuite_client, args)

        call_kwargs = mocker_http_request.call_args.kwargs
        assert call_kwargs["method"] == "DELETE"
        assert "body" not in call_kwargs

    @patch(MOCKER_HTTP_METHOD)
    def test_file_delete_soft_delete_uses_patch_with_trashed_true(self, mocker_http_request, gsuite_client):
        """
        Scenario: soft_delete=true — must switch to PATCH
        /drive/v3/files/{id} with body {"trashed": true}.
        """
        from GoogleDrive import file_delete_command

        mocker_http_request.return_value = {"id": "FILE123", "trashed": True}

        args = {"file_id": "FILE123", "user_id": "user@example.com", "soft_delete": "true"}
        result = file_delete_command(gsuite_client, args)

        assert mocker_http_request.call_count == 1
        call_kwargs = mocker_http_request.call_args.kwargs
        assert call_kwargs["method"] == "PATCH"
        assert call_kwargs["url_suffix"] == "drive/v3/files/FILE123"
        assert call_kwargs["body"] == {"trashed": True}

        outputs_context = result.outputs["GoogleDrive.File"]["File"]
        assert outputs_context["id"] == "FILE123"
        assert outputs_context["trashed"] is True
        assert "Trash" in result.readable_output


class TestFilePermissionCreateTransferOwnership:
    """!google-drive-file-permission-create + transfer_ownership arg."""

    @patch(MOCKER_HTTP_METHOD)
    def test_permission_create_default_no_transfer_ownership(self, mocker_http_request, gsuite_client):
        """
        Scenario: transfer_ownership arg absent — the request URL must
        NOT include the transferOwnership query parameter (legacy shape).
        """
        from GoogleDrive import file_permission_create_command

        with open("test_data/file_permission_create_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {"file_id": "FILE123", "role": "reader", "type": "user", "email_address": "u@example.com"}
        file_permission_create_command(gsuite_client, args)

        call_kwargs = mocker_http_request.call_args.kwargs
        assert call_kwargs["method"] == "POST"
        params = call_kwargs.get("params", {})
        assert "transferOwnership" not in params  # legacy behavior preserved

    @patch(MOCKER_HTTP_METHOD)
    def test_permission_create_default_no_transfer_ownership_when_false(self, mocker_http_request, gsuite_client):
        """transfer_ownership=false must behave identically to transfer_ownership absent."""
        from GoogleDrive import file_permission_create_command

        with open("test_data/file_permission_create_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {
            "file_id": "FILE123",
            "role": "reader",
            "type": "user",
            "email_address": "u@example.com",
            "transfer_ownership": "false",
        }
        file_permission_create_command(gsuite_client, args)

        params = mocker_http_request.call_args.kwargs.get("params", {})
        assert "transferOwnership" not in params

    @patch(MOCKER_HTTP_METHOD)
    def test_permission_create_transfer_ownership_true_appends_query(self, mocker_http_request, gsuite_client):
        """
        Scenario: transfer_ownership=true — request must include
        transferOwnership=true query parameter.
        """
        from GoogleDrive import file_permission_create_command

        with open("test_data/file_permission_create_response.json", encoding="utf-8") as data:
            mock_response = json.load(data)
        mocker_http_request.return_value = mock_response

        args = {
            "file_id": "FILE123",
            "role": "owner",
            "type": "user",
            "email_address": "newowner@example.com",
            "transfer_ownership": "true",
        }
        file_permission_create_command(gsuite_client, args)

        params = mocker_http_request.call_args.kwargs.get("params", {})
        assert params.get("transferOwnership") == "true"


class TestFilePermissionDeleteIgnoreNotFound:
    """!google-drive-file-permission-delete + ignore_not_found arg."""

    @patch(MOCKER_HTTP_METHOD)
    def test_permission_delete_default_404_raises(self, mocker_http_request, gsuite_client):
        """
        Scenario: ignore_not_found arg absent — a DemistoException
        ("Not found.") from the underlying http_request must propagate
        (preserves the existing behavior bit-for-bit).
        """
        from GoogleDrive import file_permission_delete_command

        mocker_http_request.side_effect = DemistoException("Not found. Reason: File not found")

        args = {"file_id": "FILE123", "permission_id": "PERM456"}
        with pytest.raises(DemistoException, match="Not found"):
            file_permission_delete_command(gsuite_client, args)

    @patch(MOCKER_HTTP_METHOD)
    def test_permission_delete_default_404_raises_when_false(self, mocker_http_request, gsuite_client):
        """ignore_not_found=false must behave identically to ignore_not_found absent."""
        from GoogleDrive import file_permission_delete_command

        mocker_http_request.side_effect = DemistoException("Not found. Reason: gone")

        args = {"file_id": "FILE123", "permission_id": "PERM456", "ignore_not_found": "false"}
        with pytest.raises(DemistoException, match="Not found"):
            file_permission_delete_command(gsuite_client, args)

    @patch(MOCKER_HTTP_METHOD)
    def test_permission_delete_default_success_unchanged(self, mocker_http_request, gsuite_client):
        """A normal 200/204 success must produce the same output shape as before."""
        from GoogleDrive import file_permission_delete_command

        mocker_http_request.return_value = ""

        args = {"file_id": "FILE123", "permission_id": "PERM456"}
        result = file_permission_delete_command(gsuite_client, args)

        call_kwargs = mocker_http_request.call_args.kwargs
        assert call_kwargs["method"] == "DELETE"
        assert call_kwargs["url_suffix"] == "drive/v3/files/FILE123/permissions/PERM456"

        outputs_context = result.outputs["GoogleDrive.FilePermission"]["FilePermission"]
        assert outputs_context["fileId"] == "FILE123"
        assert outputs_context["id"] == "PERM456"

    @patch(MOCKER_HTTP_METHOD)
    def test_permission_delete_ignore_not_found_true_swallows_404(self, mocker_http_request, gsuite_client):
        """
        Scenario: ignore_not_found=true + 404 — must return a successful
        CommandResults with an idempotent-skip readable_output.
        """
        from GoogleDrive import file_permission_delete_command

        mocker_http_request.side_effect = DemistoException("Not found. Reason: already removed")

        args = {"file_id": "FILE123", "permission_id": "PERM456", "ignore_not_found": "true"}
        result = file_permission_delete_command(gsuite_client, args)

        outputs_context = result.outputs["GoogleDrive.FilePermission"]["FilePermission"]
        assert outputs_context["fileId"] == "FILE123"
        assert outputs_context["id"] == "PERM456"
        assert "idempotent skip" in result.readable_output

    @patch(MOCKER_HTTP_METHOD)
    def test_permission_delete_ignore_not_found_true_does_not_swallow_other_errors(self, mocker_http_request, gsuite_client):
        """
        ignore_not_found=true must only swallow 404s — other errors
        (e.g. 403 / 500) must still propagate.
        """
        from GoogleDrive import file_permission_delete_command

        mocker_http_request.side_effect = DemistoException("Authorization Error: forbidden")

        args = {"file_id": "FILE123", "permission_id": "PERM456", "ignore_not_found": "true"}
        with pytest.raises(DemistoException, match="Authorization"):
            file_permission_delete_command(gsuite_client, args)


class TestFilePermissionListInheritedOutput:
    """!google-drive-file-permissions-list — declare permissionDetails.inherited output.

    The Drive API already returns ``permissionDetails`` when
    ``fields=*`` (which the existing code requests). This test confirms
    the field flows through to the context output unchanged.
    """

    @patch(MOCKER_HTTP_METHOD)
    def test_permission_list_surfaces_permission_details_inherited(self, mocker_http_request, gsuite_client):
        from GoogleDrive import file_permission_list_command

        mock_response = {
            "kind": "drive#permissionList",
            "permissions": [
                {
                    "kind": "drive#permission",
                    "id": "perm-direct",
                    "type": "user",
                    "emailAddress": "direct@example.com",
                    "role": "writer",
                    "displayName": "Direct User",
                    "deleted": False,
                },
                {
                    "kind": "drive#permission",
                    "id": "perm-inherited",
                    "type": "user",
                    "emailAddress": "inherited@example.com",
                    "role": "reader",
                    "displayName": "Inherited User",
                    "deleted": False,
                    "permissionDetails": [
                        {
                            "permissionType": "member",
                            "role": "reader",
                            "inheritedFrom": "PARENT_FOLDER_ID",
                            "inherited": True,
                        }
                    ],
                },
            ],
        }
        mocker_http_request.return_value = mock_response

        result = file_permission_list_command(gsuite_client, {"file_id": "FILE123"})

        permissions = result.outputs["GoogleDrive.FilePermission"]["FilePermission"]
        assert len(permissions) == 2

        direct = next(p for p in permissions if p["id"] == "perm-direct")
        inherited = next(p for p in permissions if p["id"] == "perm-inherited")

        # Legacy fields preserved on every permission.
        for perm in (direct, inherited):
            assert "id" in perm
            assert "role" in perm
            assert "type" in perm

        # The new context path is populated when the API returns it.
        details = inherited["permissionDetails"]
        assert isinstance(details, list)
        assert details[0]["inherited"] is True
        assert details[0]["inheritedFrom"] == "PARENT_FOLDER_ID"
        assert details[0]["permissionType"] == "member"

        # And it is absent (or unchanged) on permissions that don't carry it —
        # i.e. nothing was injected into the legacy shape.
        assert "permissionDetails" not in direct
