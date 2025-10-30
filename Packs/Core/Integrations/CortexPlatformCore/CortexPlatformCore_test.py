import json

import pytest

import demistomock as demisto

MAX_GET_INCIDENTS_LIMIT = 100


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_get_asset_details_command_success(mocker):
    """
    GIVEN:
        A mocked client and valid arguments with an asset ID.
    WHEN:
        The get_asset_details_command function is called.
    THEN:
        The response is parsed, formatted, and returned correctly.
    """
    from CortexPlatformCore import Client, get_asset_details_command

    mock_client = Client(base_url="", headers={})
    mock_get_asset_details = mocker.patch.object(
        mock_client, "_http_request", return_value={"reply": {"id": "1234", "name": "Test Asset"}}
    )

    args = {"asset_id": "1234"}

    result = get_asset_details_command(mock_client, args)

    assert result.outputs == {"id": "1234", "name": "Test Asset"}
    assert "Test Asset" in result.readable_output
    assert mock_get_asset_details.call_count == 1


def test_replace_args_alert_with_issue():
    """
    GIVEN:
        Arguments dictionary with various key types - single issue key, multiple issue keys, and mixed keys.
    WHEN:
        The replace_args_alert_with_issue function is called.
    THEN:
        All 'issue' keys are replaced with 'alert' and values are preserved, while other keys remain unchanged.
    """
    from CortexPlatformCore import issue_to_alert

    # Test single issue key
    args = {"issue_id": "12345"}
    result = issue_to_alert(args)

    assert result == {"alert_id": "12345"}
    assert "issue_id" not in result
    assert "alert_id" in result

    # Test multiple issue keys
    args = {"issue_id": "12345", "issue_status": "open", "issue_priority": "high"}
    result = issue_to_alert(args)

    expected = {"alert_id": "12345", "alert_status": "open", "alert_priority": "high"}
    assert result == expected
    assert "issue_id" not in result
    assert "issue_status" not in result
    assert "issue_priority" not in result

    # Test mixed keys
    args = {"issue_id": "12345", "user_name": "john", "issue_type": "bug", "timestamp": "2023-01-01"}
    result = issue_to_alert(args)

    expected = {"alert_id": "12345", "user_name": "john", "alert_type": "bug", "timestamp": "2023-01-01"}
    assert result == expected
    assert "issue_id" not in result
    assert "issue_type" not in result
    assert result["user_name"] == "john"
    assert result["timestamp"] == "2023-01-01"


def test_alert_to_issue():
    """
    GIVEN:
        A dictionary with alert keys that need to be converted to issue keys.
    WHEN:
        The alert_to_issue function is called.
    THEN:
        All 'alert' keys are replaced with 'issue' keys and values are preserved.
    """
    from CortexPlatformCore import alert_to_issue

    # Test single alert key
    outputs = {"alert_id": "12345"}
    result = alert_to_issue(outputs)

    assert result == {"issue_id": "12345"}
    assert "alert_id" not in result
    assert "issue_id" in result

    # Test multiple alert keys
    outputs = {"alert_id": "12345", "alert_status": "open", "alert_priority": "high"}
    result = alert_to_issue(outputs)

    expected = {"issue_id": "12345", "issue_status": "open", "issue_priority": "high"}
    assert result == expected
    assert "alert_id" not in result
    assert "alert_status" not in result
    assert "alert_priority" not in result

    # Test mixed keys
    outputs = {"alert_id": "12345", "user_name": "john", "alert_type": "bug", "timestamp": "2023-01-01"}
    result = alert_to_issue(outputs)

    expected = {"issue_id": "12345", "user_name": "john", "issue_type": "bug", "timestamp": "2023-01-01"}
    assert result == expected
    assert "alert_id" not in result
    assert "alert_type" not in result
    assert result["user_name"] == "john"
    assert result["timestamp"] == "2023-01-01"


def test_core_get_issues_command(mocker):
    """
    GIVEN:
        A mocked get_alerts_by_filter_command that returns a CommandResults object with alert data.
    WHEN:
        The core-get-issues command is executed through the main function.
    THEN:
        Arguments are transformed from issue to alert format, get_alerts_by_filter_command is called,
        outputs are transformed back from alert to issue format, and results are returned.
    """
    from CortexPlatformCore import main
    from CommonServerPython import CommandResults

    # Mock demisto functions
    mocker.patch.object(demisto, "command", return_value="core-get-issues")
    mocker.patch.object(demisto, "args", return_value={"issue_id": "12345", "issue_status": "open", "issue_priority": "high"})
    mocker.patch.object(demisto, "params", return_value={"proxy": False, "insecure": False, "timeout": "120"})

    # Create mock CommandResults with alert data that should be converted to issue data
    mock_command_results = CommandResults(
        outputs_prefix="Core.Alert",
        outputs=[
            {
                "alert_id": "12345",
                "alert_status": "open",
                "alert_priority": "high",
                "alert_description": "Test alert",
                "user_name": "john",
            }
        ],
        readable_output="Test alert output",
        raw_response={"alert_id": "12345"},
    )

    # Mock get_alerts_by_filter_command to return our mock CommandResults
    mock_get_alerts = mocker.patch("CortexPlatformCore.get_alerts_by_filter_command", return_value=mock_command_results)
    mock_return_results = mocker.patch("CortexPlatformCore.return_results")
    # Execute the main function
    main()

    # Verify that get_alerts_by_filter_command was called with transformed arguments
    mock_get_alerts.assert_called_once()
    called_args = mock_get_alerts.call_args[0][1]  # Get the args parameter

    # Verify the arguments were transformed from issue to alert format
    assert "alert_id" in called_args
    assert "alert_status" in called_args
    assert "alert_priority" in called_args
    assert called_args["alert_id"] == "12345"
    assert called_args["alert_status"] == "open"
    assert called_args["alert_priority"] == "high"

    # Verify issue keys are not present in the transformed args
    assert "issue_id" not in called_args
    assert "issue_status" not in called_args
    assert "issue_priority" not in called_args

    # Get the CommandResults object that was passed to return_results
    returned_command_results = mock_return_results.call_args[0][0]

    # Verify the outputs were transformed back from alert to issue format
    assert "issue_id" in returned_command_results.outputs[0]
    assert "issue_status" in returned_command_results.outputs[0]
    assert "issue_priority" in returned_command_results.outputs[0]
    assert "issue_description" in returned_command_results.outputs[0]
    assert returned_command_results.outputs[0]["issue_id"] == "12345"
    assert returned_command_results.outputs[0]["issue_status"] == "open"
    assert returned_command_results.outputs[0]["issue_priority"] == "high"
    assert returned_command_results.outputs[0]["issue_description"] == "Test alert"

    # Verify alert keys are not present in the final outputs
    assert "alert_id" not in returned_command_results.outputs[0]
    assert "alert_priority" not in returned_command_results.outputs[0]
    assert "alert_description" not in returned_command_results.outputs[0]

    # Verify non-alert/issue keys are preserved
    assert returned_command_results.outputs[0]["user_name"] == "john"


def test_filter_context_fields():
    from CortexPlatformCore import filter_context_fields

    context_data = [
        {
            "id": "alert_1",
            "name": "Critical Alert",
            "status": "active",
            "severity": "high",
            "timestamp": "2023-10-01T10:00:00Z",
            "internal_field": "should_be_removed",
            "private_data": "confidential",
        },
        {
            "id": "alert_2",
            "name": "Warning Alert",
            "status": "resolved",
            "severity": "medium",
            "timestamp": "2023-10-01T11:00:00Z",
            "internal_field": "should_be_removed",
            "debug_info": "debug_data",
        },
    ]

    output_keys_to_keep = ["id", "name", "status", "severity", "timestamp"]
    filtered_data = filter_context_fields(output_keys_to_keep, context_data)

    expected_result = [
        {"id": "alert_1", "name": "Critical Alert", "status": "active", "severity": "high", "timestamp": "2023-10-01T10:00:00Z"},
        {
            "id": "alert_2",
            "name": "Warning Alert",
            "status": "resolved",
            "severity": "medium",
            "timestamp": "2023-10-01T11:00:00Z",
        },
    ]

    assert expected_result == filtered_data


def test_core_get_issues_command_with_output_keys(mocker):
    """
    GIVEN:
        A mocked get_alerts_by_filter_command that returns a CommandResults object with alert data
        and output_keys argument is provided to filter specific fields.
    WHEN:
        The core-get-issues command is executed with output_keys parameter.
    THEN:
        Arguments are transformed from issue to alert format, get_alerts_by_filter_command is called,
        outputs are transformed back from alert to issue format, filtered by output_keys, and results are returned.
    """
    from CortexPlatformCore import main
    from CommonServerPython import CommandResults

    # Mock demisto functions with output_keys parameter
    mocker.patch.object(demisto, "command", return_value="core-get-issues")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "issue_id": "12345",
            "issue_status": "open",
            "issue_priority": "high",
            "output_keys": "issue_id,issue_status,issue_description",
        },
    )
    mocker.patch.object(demisto, "params", return_value={"proxy": False, "insecure": False, "timeout": "120"})

    # Create mock CommandResults with alert data that should be converted to issue data
    mock_command_results = CommandResults(
        outputs_prefix="Core.Issue",
        outputs=[
            {
                "alert_id": "12345",
                "alert_status": "open",
                "alert_priority": "high",
                "alert_description": "Test alert",
                "alert_severity": "critical",
                "alert_timestamp": "2023-10-01T10:00:00Z",
                "user_name": "john",
                "internal_field": "should_be_filtered_out",
            },
            {
                "alert_id": "67890",
                "alert_status": "closed",
                "alert_priority": "medium",
                "alert_description": "Another test alert",
                "alert_severity": "low",
                "alert_timestamp": "2023-10-01T11:00:00Z",
                "user_name": "jane",
                "internal_field": "should_be_filtered_out",
            },
        ],
        readable_output="Test alert output",
        raw_response={"alert_id": "12345"},
    )

    # Mock get_alerts_by_filter_command to return our mock CommandResults
    mock_get_alerts = mocker.patch("CortexPlatformCore.get_alerts_by_filter_command", return_value=mock_command_results)
    mock_return_results = mocker.patch("CortexPlatformCore.return_results")

    # Execute the main function
    main()

    # Verify that get_alerts_by_filter_command was called with transformed arguments
    mock_get_alerts.assert_called_once()
    called_args = mock_get_alerts.call_args[0][1]  # Get the args parameter

    # Verify the arguments were transformed from issue to alert format and output_keys was removed
    assert "alert_id" in called_args
    assert "alert_status" in called_args
    assert "alert_priority" in called_args
    assert "output_keys" not in called_args  # Should be removed from args passed to get_alerts_by_filter_command
    assert called_args["alert_id"] == "12345"
    assert called_args["alert_status"] == "open"
    assert called_args["alert_priority"] == "high"

    # Get the CommandResults object that was passed to return_results
    returned_command_results = mock_return_results.call_args[0][0]

    # Verify the outputs were transformed back from alert to issue format
    assert len(returned_command_results.outputs) == 2

    # Check first alert/issue
    first_issue = returned_command_results.outputs[0]
    assert "issue_id" in first_issue
    assert "issue_status" in first_issue
    assert "issue_description" in first_issue
    assert first_issue["issue_id"] == "12345"
    assert first_issue["issue_status"] == "open"
    assert first_issue["issue_description"] == "Test alert"

    # Verify that only the specified output_keys are present (after transformation to issue format)
    expected_keys = {"issue_id", "issue_status", "issue_description"}
    assert set(first_issue.keys()) == expected_keys

    # Verify fields that should be filtered out are not present
    assert "issue_priority" not in first_issue
    assert "issue_severity" not in first_issue
    assert "issue_timestamp" not in first_issue
    assert "user_name" not in first_issue
    assert "internal_field" not in first_issue

    # Check second alert/issue
    second_issue = returned_command_results.outputs[1]
    assert "issue_id" in second_issue
    assert "issue_status" in second_issue
    assert "issue_description" in second_issue
    assert second_issue["issue_id"] == "67890"
    assert second_issue["issue_status"] == "closed"
    assert second_issue["issue_description"] == "Another test alert"

    # Verify that only the specified output_keys are present
    assert set(second_issue.keys()) == expected_keys

    # Verify alert keys are not present in the final outputs
    assert "alert_id" not in first_issue
    assert "alert_status" not in first_issue
    assert "alert_description" not in first_issue


def test_get_cases_command_case_id_as_int(mocker):
    """
    Given:
        - case_id_list as an integer
    When:
        - Calling get_cases_command
    Then:
        - client.get_incidents is called with incident_id_list as a list of string
    """
    from CortexPlatformCore import get_cases_command

    client = mocker.Mock()
    client.get_incidents.return_value = [{"case_id": "1"}]
    mocker.patch("CortexPlatformCore.tableToMarkdown", return_value="table")
    args = {"case_id_list": 1}
    result = get_cases_command(client, args)
    assert result.outputs == [{"case_id": "1"}]
    client.get_incidents.assert_called_once()
    assert result.readable_output.startswith("table")


def test_get_cases_command_limit_enforced(mocker):
    """
    Given:
        - limit greater than MAX_GET_INCIDENTS_LIMIT
    When:
        - Calling get_cases_command
    Then:
        - Limit is set to MAX_GET_INCIDENTS_LIMIT
        - client.get_incidents is called with limit=MAX_GET_INCIDENTS_LIMIT
    """
    from CortexPlatformCore import get_cases_command

    client = mocker.Mock()
    client.get_incidents.return_value = [{"case_id": str(i)} for i in range(MAX_GET_INCIDENTS_LIMIT + 1)]
    mocker.patch("CortexPlatformCore.tableToMarkdown", return_value="table")
    args = {"limit": MAX_GET_INCIDENTS_LIMIT + 10, "case_id_list": "1"}
    result = get_cases_command(client, args)
    assert len(result.outputs) == MAX_GET_INCIDENTS_LIMIT + 1
    client.get_incidents.assert_called_with(
        incident_id_list=["1"],
        lte_modification_time=None,
        gte_modification_time=None,
        lte_creation_time=None,
        gte_creation_time=None,
        sort_by_creation_time=None,
        sort_by_modification_time=None,
        page_number=0,
        limit=MAX_GET_INCIDENTS_LIMIT,
        starred=None,
        starred_incidents_fetch_window=mocker.ANY,
    )


def test_get_cases_command_no_filters_error(mocker):
    """
    Given:
        - No filters provided
    When:
        - Calling get_cases_command
    Then:
        - ValueError is raised
    """
    from CortexPlatformCore import get_cases_command

    client = mocker.Mock()
    args = {}
    with pytest.raises(ValueError, match="Specify a query for the incidents"):
        get_cases_command(client, args)


def test_get_cases_command_conflicting_time_filters(mocker):
    """
    Given:
        - since_modification_time and gte_modification_time both set
    When:
        - Calling get_cases_command
    Then:
        - ValueError is raised
    """
    from CortexPlatformCore import get_cases_command

    client = mocker.Mock()
    args = {"since_modification_time": "1 day", "gte_modification_time": "2022-01-01"}
    with pytest.raises(ValueError):
        get_cases_command(client, args)


def test_replace_substring_string():
    """
    GIVEN a string containing or not containing the substring 'issue'.
    WHEN replace_substring is called with 'issue' and 'alert'.
    THEN it replaces all occurrences of 'issue' with 'alert' in the string, or leaves unchanged if not present.
    """
    from CortexPlatformCore import replace_substring

    assert replace_substring("foo_issue_bar", "issue", "alert") == "foo_alert_bar"
    assert replace_substring("nochange", "issue", "alert") == "nochange"


def test_replace_substring_dict():
    """
    GIVEN a dict with keys containing 'issue' and other keys.
    WHEN replace_substring is called with 'issue' and 'alert'.
    THEN it replaces all occurrences of 'issue' in keys with 'alert', values are preserved, and other keys unchanged.
    """
    from CortexPlatformCore import replace_substring

    d = {"issue_id": 1, "other": 2}
    out = replace_substring(d.copy(), "issue", "alert")
    assert out["alert_id"] == 1
    assert "issue_id" not in out
    assert out["other"] == 2


def test_preprocess_get_cases_outputs_list_and_single():
    """
    GIVEN a dict or list of dicts with 'incident_id' and/or 'alert_field'.
    WHEN preprocess_get_cases_outputs is called.
    THEN it returns dict(s) with 'incident' replaced by 'case' and 'alert' replaced by 'issue'.
    """
    from CortexPlatformCore import preprocess_get_cases_outputs

    # Single dict
    data = {"incident_id": 1, "alert_field": "foo"}
    out = preprocess_get_cases_outputs(data.copy())
    assert out["case_id"] == 1
    # List
    data_list = [{"incident_id": 2}, {"incident_id": 3}]
    out_list = preprocess_get_cases_outputs(data_list.copy())
    assert out_list[0]["case_id"] == 2
    assert out_list[1]["case_id"] == 3


def test_preprocess_get_case_extra_data_outputs_basic():
    """
    GIVEN a dict with 'incident' or 'alerts' keys containing dicts with 'incident_id'.
    WHEN preprocess_get_case_extra_data_outputs is called.
    THEN it returns dict(s) with 'incident' replaced by 'case' and 'alert' replaced by 'issue' in all nested dicts.
    """
    from CortexPlatformCore import preprocess_get_case_extra_data_outputs

    # Only incident
    data = {"incident": {"incident_id": 1}}
    out = preprocess_get_case_extra_data_outputs(data.copy())
    assert out["case"]["case_id"] == 1
    # With alerts
    data = {"incident": {"incident_id": 1}, "alerts": {"data": [{"incident_id": 2}, {"incident_id": 3}]}}
    out = preprocess_get_case_extra_data_outputs(data.copy())
    assert out["issues"]["data"][0]["case_id"] == 2
    assert out["issues"]["data"][1]["case_id"] == 3


def test_preprocess_get_case_extra_data_outputs_list():
    """
    GIVEN a list of dicts with 'incident' key.
    WHEN preprocess_get_case_extra_data_outputs is called.
    THEN it returns a list with 'incident' replaced by 'case' in each dict.
    """
    from CortexPlatformCore import preprocess_get_case_extra_data_outputs

    data = [{"incident": {"incident_id": 1}}, {"incident": {"incident_id": 2}}]
    out = preprocess_get_case_extra_data_outputs(data.copy())
    assert out[0]["case"]["case_id"] == 1
    assert out[1]["case"]["case_id"] == 2


def test_preprocess_get_case_extra_data_outputs_edge_cases():
    """
    GIVEN a non-dict/list input, or a dict without 'incident'/'alerts' keys.
    WHEN preprocess_get_case_extra_data_outputs is called.
    THEN it returns the input unchanged or with only top-level keys transformed if possible.
    """
    from CortexPlatformCore import preprocess_get_case_extra_data_outputs

    # Not a dict/list
    assert preprocess_get_case_extra_data_outputs("foo") == "foo"
    # Dict without incident/alerts
    d = {"other": 1}
    out = preprocess_get_case_extra_data_outputs(d.copy())
    assert out["other"] == 1


def test_preprocess_get_cases_args_limit_enforced():
    """
    GIVEN an args dict with 'limit' above and below MAX_GET_INCIDENTS_LIMIT.
    WHEN preprocess_get_cases_args is called.
    THEN it enforces the limit not to exceed MAX_GET_INCIDENTS_LIMIT.
    """
    from CortexPlatformCore import preprocess_get_cases_args

    args = {"limit": 500}
    out = preprocess_get_cases_args(args.copy())
    assert out["limit"] == 100
    args = {"limit": 50}
    out = preprocess_get_cases_args(args.copy())
    assert out["limit"] == 50


def test_get_issue_id_from_args():
    """
    GIVEN:
        Arguments dictionary with issue_id provided.
    WHEN:
        The get_issue_id function is called.
    THEN:
        The issue_id from args is returned.
    """
    from CortexPlatformCore import get_issue_id

    args = {"issue_id": "12345"}
    result = get_issue_id(args)

    assert result == "12345"


def test_get_issue_id_empty_string_in_args(mocker):
    """
    GIVEN:
        Arguments dictionary with empty issue_id and demisto calling context with incident.
    WHEN:
        The get_issue_id function is called.
    THEN:
        The issue_id from calling context is returned.
    """
    from CortexPlatformCore import get_issue_id

    args = {"issue_id": ""}
    mock_calling_context = {"context": {"Incidents": [{"id": "67890"}]}}
    mocker.patch.object(demisto, "callingContext", mock_calling_context)

    result = get_issue_id(args)

    assert result == "67890"


def test_get_issue_id_missing_from_args(mocker):
    """
    GIVEN:
        Arguments dictionary without issue_id and demisto calling context with incident.
    WHEN:
        The get_issue_id function is called.
    THEN:
        The issue_id from calling context is returned.
    """
    from CortexPlatformCore import get_issue_id

    args = {}
    mock_calling_context = {"context": {"Incidents": [{"id": "99999"}]}}
    mocker.patch.object(demisto, "callingContext", mock_calling_context)

    result = get_issue_id(args)

    assert result == "99999"


def test_get_issue_id_from_context_multiple_incidents(mocker):
    """
    GIVEN:
        Arguments dictionary without issue_id and calling context with multiple incidents.
    WHEN:
        The get_issue_id function is called.
    THEN:
        The issue_id from the first incident in calling context is returned.
    """
    from CortexPlatformCore import get_issue_id

    args = {}
    mock_calling_context = {"context": {"Incidents": [{"id": "first_incident"}, {"id": "second_incident"}]}}
    mocker.patch.object(demisto, "callingContext", mock_calling_context)

    result = get_issue_id(args)

    assert result == "first_incident"


def test_create_filter_data_basic():
    """
    GIVEN:
        Issue ID and basic update arguments.
    WHEN:
        The create_filter_data function is called.
    THEN:
        Correct filter data structure is returned with proper formatting.
    """
    from CortexPlatformCore import create_filter_data

    issue_id = "12345"
    update_args = {"name": "Test Issue", "severity": "HIGH"}

    result = create_filter_data(issue_id, update_args)

    expected = {
        "filter_data": {"filter": {"OR": [{"SEARCH_FIELD": "internal_id", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "12345"}]}},
        "filter_type": "static",
        "update_data": {"name": "Test Issue", "severity": "HIGH"},
    }

    assert result == expected


def test_create_filter_data_empty_update_args():
    """
    GIVEN:
        Issue ID and empty update arguments.
    WHEN:
        The create_filter_data function is called.
    THEN:
        Filter data structure is returned with empty update_data.
    """
    from CortexPlatformCore import create_filter_data

    issue_id = "54321"
    update_args = {}

    result = create_filter_data(issue_id, update_args)

    assert result["filter_data"]["filter"]["OR"][0]["SEARCH_VALUE"] == "54321"
    assert result["filter_type"] == "static"
    assert result["update_data"] == {}


def test_create_filter_data_complex_update_args():
    """
    GIVEN:
        Issue ID and complex update arguments with multiple fields.
    WHEN:
        The create_filter_data function is called.
    THEN:
        Filter data structure contains all update arguments in update_data.
    """
    from CortexPlatformCore import create_filter_data

    issue_id = "98765"
    update_args = {
        "name": "Complex Issue",
        "severity": "CRITICAL",
        "assigned_user": "user@example.com",
        "type": "security",
        "phase": "investigation",
    }

    result = create_filter_data(issue_id, update_args)

    assert result["filter_data"]["filter"]["OR"][0]["SEARCH_VALUE"] == "98765"
    assert result["update_data"] == update_args
    assert result["filter_type"] == "static"


def test_update_issue_command_success(mocker):
    """
    GIVEN:
        Client instance and arguments with all required fields.
    WHEN:
        The update_issue_command function is called.
    THEN:
        Issue is updated successfully with correct filter data and severity mapping.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mock_debug = mocker.patch.object(demisto, "debug")

    args = {
        "issue_id": "12345",
        "assigned_user_mail": "user@example.com",
        "severity": "3",
        "name": "Updated Issue",
        "occurred": "2023-01-01",
        "type": "incident",
        "phase": "response",
    }

    update_issue_command(client, args)

    # Verify debug was called
    mock_debug.assert_called_once()

    # Verify update_issue was called
    mock_update_issue.assert_called_once()

    # Check the filter data structure passed to update_issue
    call_args = mock_update_issue.call_args[0][0]
    assert call_args["filter_data"]["filter"]["OR"][0]["SEARCH_VALUE"] == "12345"
    assert call_args["update_data"]["assigned_user"] == "user@example.com"
    assert call_args["update_data"]["severity"] == "SEV_040_HIGH"
    assert call_args["update_data"]["name"] == "Updated Issue"


def test_update_issue_command_no_issue_id(mocker):
    """
    GIVEN:
        Client instance and arguments without issue_id or calling context.
    WHEN:
        The update_issue_command function is called.
    THEN:
        return_error is called with appropriate error message.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_return_error = mocker.patch("CortexPlatformCore.return_error")
    mock_calling_context = {"context": {"Incidents": [{"id": ""}]}}
    mocker.patch.object(demisto, "callingContext", mock_calling_context)

    args = {}

    update_issue_command(client, args)

    mock_return_error.assert_called_once_with("Issue ID is required for updating an issue.")


def test_update_issue_command_filters_none_values(mocker):
    """
    GIVEN:
        Client instance and arguments with some None values.
    WHEN:
        The update_issue_command function is called.
    THEN:
        None values are filtered out from the update data.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")

    args = {
        "issue_id": "12345",
        "assigned_user_mail": "user@example.com",
        "severity": None,
        "name": None,
    }

    update_issue_command(client, args)

    # Check that only non-None values are in update_data
    call_args = mock_update_issue.call_args[0][0]
    update_data = call_args["update_data"]

    assert "assigned_user" in update_data
    assert update_data["assigned_user"] == "user@example.com"
    assert "severity" not in update_data
    assert "name" not in update_data


def test_update_issue_command_severity_mapping(mocker):
    """
    GIVEN:
        Client instance and arguments with different severity values.
    WHEN:
        The update_issue_command function is called.
    THEN:
        Severity numbers are correctly mapped to severity strings.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")

    severity_tests = [(1, "SEV_020_LOW"), (2, "SEV_030_MEDIUM"), (3, "SEV_040_HIGH"), (4, "SEV_050_CRITICAL")]

    for severity_num, expected_severity in severity_tests:
        args = {"issue_id": "12345", "severity": str(severity_num)}

        update_issue_command(client, args)

        # Check severity mapping in update_data
        call_args = mock_update_issue.call_args[0][0]
        update_data = call_args["update_data"]

        assert update_data["severity"] == expected_severity


def test_update_issue_command_from_context(mocker):
    """
    GIVEN:
        Client instance, arguments without issue_id, and calling context with incident.
    WHEN:
        The update_issue_command function is called.
    THEN:
        Issue ID is retrieved from calling context and update proceeds successfully.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")

    mock_calling_context = {"context": {"Incidents": [{"id": "context_issue_id"}]}}
    mocker.patch.object(demisto, "callingContext", mock_calling_context)

    args = {"assigned_user_mail": "user@example.com", "severity": "2", "name": "Context Issue"}

    update_issue_command(client, args)

    # Verify the issue ID from context was used
    call_args = mock_update_issue.call_args[0][0]
    assert call_args["filter_data"]["filter"]["OR"][0]["SEARCH_VALUE"] == "context_issue_id"
    assert call_args["update_data"]["assigned_user"] == "user@example.com"
    assert call_args["update_data"]["severity"] == "SEV_030_MEDIUM"
    assert call_args["update_data"]["name"] == "Context Issue"


def test_update_issue_command_empty_args(mocker):
    """
    GIVEN:
        Client instance and minimal arguments with only issue_id.
    WHEN:
        The update_issue_command function is called.
    THEN:
        Update proceeds with empty update_data.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")

    args = {"issue_id": "12345"}

    update_issue_command(client, args)

    # Check that update_data is empty
    call_args = mock_update_issue.call_args[0][0]
    update_data = call_args["update_data"]

    assert update_data == {}
    assert call_args["filter_data"]["filter"]["OR"][0]["SEARCH_VALUE"] == "12345"


def test_update_issue_command_invalid_severity_mapping(mocker):
    """
    GIVEN:
        Client instance and arguments with invalid severity value.
    WHEN:
        The update_issue_command function is called.
    THEN:
        Severity is not included in update_data when mapping returns None.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")

    args = {"issue_id": "12345", "severity": "99", "name": "Test Issue"}

    update_issue_command(client, args)

    # Check that invalid severity is not in update_data
    call_args = mock_update_issue.call_args[0][0]
    update_data = call_args["update_data"]

    assert "severity" not in update_data
    assert update_data["name"] == "Test Issue"
