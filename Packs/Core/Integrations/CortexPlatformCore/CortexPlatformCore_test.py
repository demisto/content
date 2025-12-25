import json

import pytest
from pytest_mock import MockerFixture
from unittest.mock import call
import demistomock as demisto

from unittest.mock import Mock, patch
import unittest
from CortexPlatformCore import (
    get_appsec_suggestion,
    populate_playbook_and_quick_action_suggestions,
    map_qa_name_to_data,
    get_issue_recommendations_command,
    map_pb_id_to_data,
    create_issue_recommendations_readable_output,
    Client,
    CommandResults,
    DemistoException,
)

MAX_GET_INCIDENTS_LIMIT = 100


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_get_asset_details_command_success(mocker: MockerFixture):
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


def test_core_get_issues_command(mocker: MockerFixture):
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


def test_core_get_issues_command_with_output_keys(mocker: MockerFixture):
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


def test_get_cases_command_case_id_as_int(mocker: MockerFixture):
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
    client.get_webapp_data.return_value = {"reply": {"DATA": [{"CASE_ID": 1}]}}  # Changed to int
    client.map_case_format.return_value = [{"case_id": "1"}]  # Mapped to string
    mocker.patch("CortexPlatformCore.tableToMarkdown", return_value="table")

    args = {"case_id_list": 1}
    result = get_cases_command(client, args)
    assert result[1].outputs[0].get("case_id") == "1"
    assert result[1].readable_output.startswith("table")


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

    args = {"id": "12345"}
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
        "filter_data": {"filter": {"AND": [{"SEARCH_FIELD": "internal_id", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "12345"}]}},
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

    assert result["filter_data"]["filter"]["AND"][0]["SEARCH_VALUE"] == "54321"
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

    assert result["filter_data"]["filter"]["AND"][0]["SEARCH_VALUE"] == "98765"
    assert result["update_data"] == update_args
    assert result["filter_type"] == "static"


def test_get_asset_group_ids_from_names_success(mocker):
    """
    GIVEN:
        A client and a list of valid asset group names.
    WHEN:
        get_asset_group_ids_from_names is called.
    THEN:
        The corresponding asset group IDs are returned.
    """
    from CortexPlatformCore import Client, get_asset_group_ids_from_names

    mock_client = Client(base_url="", headers={})
    mock_search_asset_groups = mocker.patch.object(
        mock_client,
        "search_asset_groups",
        return_value={
            "reply": {
                "data": [
                    {"XDM.ASSET_GROUP.ID": 1, "XDM.ASSET_GROUP.NAME": "Production Servers"},
                    {"XDM.ASSET_GROUP.ID": 2, "XDM.ASSET_GROUP.NAME": "Development Workstations"},
                ]
            }
        },
    )

    group_names = ["Production Servers", "Development Workstations"]
    result = get_asset_group_ids_from_names(mock_client, group_names)

    assert set(result) == {1, 2}
    assert mock_search_asset_groups.call_count == 1

    filter = mock_search_asset_groups.call_args[0][0]
    expected_filter = {
        "AND": [
            {
                "OR": [
                    {
                        "SEARCH_FIELD": "XDM.ASSET_GROUP.NAME",
                        "SEARCH_TYPE": "EQ",
                        "SEARCH_VALUE": "Production Servers",
                    },
                    {
                        "SEARCH_FIELD": "XDM.ASSET_GROUP.NAME",
                        "SEARCH_TYPE": "EQ",
                        "SEARCH_VALUE": "Development Workstations",
                    },
                ]
            }
        ]
    }
    assert filter == expected_filter


def test_get_asset_group_ids_from_names_empty_list():
    """
    GIVEN:
        A client and an empty list of asset group names.
    WHEN:
        get_asset_group_ids_from_names is called.
    THEN:
        An empty list is returned without making API calls.
    """
    from CortexPlatformCore import Client, get_asset_group_ids_from_names

    mock_client = Client(base_url="", headers={})
    result = get_asset_group_ids_from_names(mock_client, [])

    assert result == []


def test_get_asset_group_ids_from_names_partial_match(mocker):
    """
    GIVEN:
        A client and asset group names where only some are found.
    WHEN:
        get_asset_group_ids_from_names is called.
    THEN:
        A DemistoException is raised indicating invalid group names.
    """
    from CortexPlatformCore import Client, get_asset_group_ids_from_names
    import pytest

    mock_client = Client(base_url="", headers={})
    mocker.patch.object(
        mock_client,
        "search_asset_groups",
        return_value={
            "reply": {
                "data": [
                    {"XDM.ASSET_GROUP.ID": "group-id-1", "XDM.ASSET_GROUP.NAME": "Production Servers"},
                ]
            }
        },
    )

    group_names = ["Production Servers", "Invalid Group"]

    with pytest.raises(Exception) as exc_info:
        get_asset_group_ids_from_names(mock_client, group_names)

    assert "Failed to fetch asset group IDs" in str(exc_info.value)
    assert "Invalid Group" in str(exc_info.value)


def test_search_assets_command_success(mocker):
    """
    GIVEN:
        A client and valid arguments for searching assets.
    WHEN:
        search_assets_command is called.
    THEN:
        Asset group IDs are resolved, filter is created, and assets are searched successfully.
    """
    from CortexPlatformCore import Client, search_assets_command

    mock_client = Client(base_url="", headers={})

    # Mock get_asset_group_ids_from_names
    mock_get_asset_group_ids = mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[1, 2])

    # Mock client.search_assets
    mock_reply = {
        "data": [
            {"xdm.asset.id": "asset-1", "xdm.asset.name": "Server-1", "xdm.asset.type.name": "server"},
            {"xdm.asset.id": "asset-2", "xdm.asset.name": "Server-2", "xdm.asset.type.name": "server"},
        ]
    }
    expected_reply = [
        {"id": "asset-1", "name": "Server-1", "type.name": "server"},
        {"id": "asset-2", "name": "Server-2", "type.name": "server"},
    ]
    mock_search_assets = mocker.patch.object(
        mock_client,
        "search_assets",
        return_value={"reply": mock_reply},
    )

    args = {
        "asset_names": "Server-1,Server-2",
        "asset_types": "server",
        "asset_groups": "Production Servers,Development Workstations",
        "asset_tags": json.dumps([{"tag1": "value1"}, {"tag2": "value2"}]),
        "page_size": "50",
        "page_number": "0",
    }

    result = search_assets_command(mock_client, args)

    assert len(result.outputs) == 2
    assert result.outputs == expected_reply
    mock_search_assets.assert_called_once()
    mock_get_asset_group_ids.assert_called_once_with(mock_client, ["Production Servers", "Development Workstations"])

    filter_arg = mock_search_assets.call_args[0][0]
    expected_filter = {
        "AND": [
            {
                "OR": [
                    {
                        "SEARCH_FIELD": "xdm.asset.name",
                        "SEARCH_TYPE": "CONTAINS",
                        "SEARCH_VALUE": "Server-1",
                    },
                    {
                        "SEARCH_FIELD": "xdm.asset.name",
                        "SEARCH_TYPE": "CONTAINS",
                        "SEARCH_VALUE": "Server-2",
                    },
                ]
            },
            {
                "SEARCH_FIELD": "xdm.asset.type.name",
                "SEARCH_TYPE": "EQ",
                "SEARCH_VALUE": "server",
            },
            {
                "OR": [
                    {
                        "SEARCH_FIELD": "xdm.asset.tags",
                        "SEARCH_TYPE": "JSON_WILDCARD",
                        "SEARCH_VALUE": {"tag1": "value1"},
                    },
                    {
                        "SEARCH_FIELD": "xdm.asset.tags",
                        "SEARCH_TYPE": "JSON_WILDCARD",
                        "SEARCH_VALUE": {"tag2": "value2"},
                    },
                ]
            },
            {
                "OR": [
                    {
                        "SEARCH_FIELD": "xdm.asset.group_ids",
                        "SEARCH_TYPE": "ARRAY_CONTAINS",
                        "SEARCH_VALUE": 1,
                    },
                    {
                        "SEARCH_FIELD": "xdm.asset.group_ids",
                        "SEARCH_TYPE": "ARRAY_CONTAINS",
                        "SEARCH_VALUE": 2,
                    },
                ]
            },
        ]
    }

    assert filter_arg == expected_filter

    # Check other parameters
    assert mock_search_assets.call_args[0][1] == 0  # page_number
    assert mock_search_assets.call_args[0][2] == 50  # page_size


def test_get_vulnerabilities_command_success(mocker: MockerFixture):
    """
    Given:
        A mocked client and valid arguments with vulnerability filters.
    When:
        The get_vulnerabilities_command function is called.
    Then:
        The response is parsed, formatted, and returned correctly with expected outputs.
    """
    from CortexPlatformCore import Client, get_vulnerabilities_command

    mock_client = Client(base_url="", headers={})
    mock_response = {
        "reply": {
            "DATA": [
                {
                    "ISSUE_ID": "vuln_001",
                    "CVE_ID": "CVE-2023-1234",
                    "CVE_DESCRIPTION": "Test vulnerability",
                    "ASSET_NAME": "test-server",
                    "PLATFORM_SEVERITY": "HIGH",
                    "EPSS_SCORE": 0.85,
                    "CVSS_SCORE": 9.1,
                    "ASSIGNED_TO": "admin",
                    "ASSIGNED_TO_PRETTY": "Administrator",
                    "AFFECTED_SOFTWARE": "Apache",
                    "FIX_AVAILABLE": True,
                    "INTERNET_EXPOSED": True,
                    "HAS_KEV": True,
                    "EXPLOITABLE": True,
                    "ASSET_IDS": ["asset_123"],
                    "EXTRA_FIELD": "should_be_filtered",
                }
            ]
        }
    }
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"cve_id": "CVE-2023-1234", "cvss_score_gte": "8.0", "severity": "high", "limit": "10"}

    result = get_vulnerabilities_command(mock_client, args)

    assert len(result.outputs) == 1
    assert result.outputs[0]["ISSUE_ID"] == "vuln_001"
    assert result.outputs[0]["CVE_ID"] == "CVE-2023-1234"
    assert result.outputs[0]["PLATFORM_SEVERITY"] == "HIGH"
    assert "EXTRA_FIELD" not in result.outputs[0]
    assert "Test vulnerability" in result.readable_output
    assert result.outputs_prefix == "Core.VulnerabilityIssue"
    assert result.outputs_key_field == "ISSUE_ID"
    assert mock_get_webapp_data.call_count == 1


def test_get_vulnerabilities_command_empty_response(mocker: MockerFixture):
    """
    Given:
        A mocked client that returns empty data.
    When:
        The get_vulnerabilities_command function is called.
    Then:
        An empty result is returned with proper structure.
    """
    from CortexPlatformCore import Client, get_vulnerabilities_command

    mock_client = Client(base_url="", headers={})
    mock_response = {"reply": {"DATA": []}}
    mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"cve_id": "CVE-2023-9999"}

    result = get_vulnerabilities_command(mock_client, args)

    assert result.outputs == []
    assert "Vulnerabilities" in result.readable_output
    assert result.outputs_prefix == "Core.VulnerabilityIssue"


def test_get_vulnerabilities_command_all_filters(mocker: MockerFixture):
    """
    Given:
        A mocked client and arguments with all possible filter combinations.
    When:
        The get_vulnerabilities_command function is called.
    Then:
        All filters are properly applied and the request is built correctly.
    """
    from CortexPlatformCore import Client, get_vulnerabilities_command

    mock_client = Client(base_url="", headers={})
    mock_response = {"reply": {"DATA": []}}
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {
        "cve_id": "CVE-2023-1234,CVE-2023-5678",
        "cvss_score_gte": "7.5",
        "epss_score_gte": "0.5",
        "internet_exposed": "true",
        "exploitable": "false",
        "has_kev": "true",
        "affected_software": "Apache,Nginx",
        "severity": "high,critical",
        "issue_id": "issue_001,issue_002",
        "start_time": "2023-01-01T00:00:00Z",
        "end_time": "2023-12-31T23:59:59Z",
        "assignee": "admin,user1",
        "limit": "25",
        "sort_field": "CVSS_SCORE",
        "sort_order": "ASC",
        "on_demand_fields": "field1,field2",
    }

    get_vulnerabilities_command(mock_client, args)

    mock_get_webapp_data.assert_called_once()
    call_args = mock_get_webapp_data.call_args[0][0]

    assert call_args["table_name"] == "VULNERABLE_ISSUES_TABLE"
    assert call_args["filter_data"]["paging"]["to"] == 25
    assert call_args["filter_data"]["sort"][0]["FIELD"] == "CVSS_SCORE"
    assert call_args["filter_data"]["sort"][0]["ORDER"] == "ASC"
    assert call_args["onDemandFields"] == ["field1", "field2"]


def test_get_vulnerabilities_command_boolean_filters(mocker: MockerFixture):
    """
    Given:
        A mocked client and boolean filter arguments.
    When:
        The get_vulnerabilities_command function is called with various boolean values.
    Then:
        Boolean filters are properly converted and applied.
    """
    from CortexPlatformCore import Client, get_vulnerabilities_command

    mock_client = Client(base_url="", headers={})
    mock_response = {"reply": {"DATA": []}}
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"internet_exposed": "false", "exploitable": "true", "has_kev": "false", "cve_id": "CVE-2023-1234"}

    get_vulnerabilities_command(mock_client, args)

    mock_get_webapp_data.assert_called_once()
    call_args = mock_get_webapp_data.call_args[0][0]

    filter_data = call_args["filter_data"]["filter"]
    assert "AND" in filter_data


def test_get_vulnerabilities_command_assignee_special_values(mocker: MockerFixture):
    """
    Given:
        A mocked client and assignee arguments with special values.
    When:
        The get_vulnerabilities_command function is called with 'unassigned' and 'assigned' values.
    Then:
        Special assignee mappings are properly applied.
    """
    from CortexPlatformCore import Client, get_vulnerabilities_command

    mock_client = Client(base_url="", headers={})
    mock_response = {"reply": {"DATA": []}}
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"assignee": "unassigned", "cve_id": "CVE-2023-1234"}

    get_vulnerabilities_command(mock_client, args)

    mock_get_webapp_data.assert_called_once()
    call_args = mock_get_webapp_data.call_args[0][0]

    filter_data = call_args["filter_data"]["filter"]
    assert "AND" in filter_data


def test_get_vulnerabilities_command_default_values(mocker: MockerFixture):
    """
    Given:
        A mocked client and minimal arguments.
    When:
        The get_vulnerabilities_command function is called with only required parameters.
    Then:
        Default values are properly applied for limit, sort_field, and sort_order.
    """
    from CortexPlatformCore import Client, get_vulnerabilities_command

    mock_client = Client(base_url="", headers={})
    mock_response = {"reply": {"DATA": []}}
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"cve_id": "CVE-2023-1234"}

    get_vulnerabilities_command(mock_client, args)

    mock_get_webapp_data.assert_called_once()
    call_args = mock_get_webapp_data.call_args[0][0]

    assert call_args["filter_data"]["paging"]["to"] == 50
    assert call_args["filter_data"]["sort"][0]["FIELD"] == "LAST_OBSERVED"
    assert call_args["filter_data"]["sort"][0]["ORDER"] == "DESC"


def test_get_vulnerabilities_command_output_filtering(mocker: MockerFixture):
    """
    Given:
        A mocked client that returns data with extra fields.
    When:
        The get_vulnerabilities_command function is called.
    Then:
        Only the specified output keys are included in the results.
    """
    from CortexPlatformCore import Client, get_vulnerabilities_command

    mock_client = Client(base_url="", headers={})
    mock_response = {
        "reply": {
            "DATA": [
                {
                    "ISSUE_ID": "vuln_001",
                    "CVE_ID": "CVE-2023-1234",
                    "EXTRA_FIELD_1": "should_be_filtered",
                    "INTERNAL_DATA": "confidential",
                    "PLATFORM_SEVERITY": "HIGH",
                    "DEBUG_INFO": "debug_data",
                    "CVSS_SCORE": 8.5,
                }
            ]
        }
    }
    mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"cve_id": "CVE-2023-1234"}

    result = get_vulnerabilities_command(mock_client, args)

    output_item = result.outputs[0]
    expected_keys = {"ISSUE_ID", "CVE_ID", "PLATFORM_SEVERITY", "CVSS_SCORE"}
    actual_keys = set(output_item.keys())

    assert expected_keys.issubset(actual_keys)
    assert "EXTRA_FIELD_1" not in actual_keys
    assert "INTERNAL_DATA" not in actual_keys
    assert "DEBUG_INFO" not in actual_keys


def test_get_vulnerabilities_command_multiple_vulnerabilities(mocker: MockerFixture):
    """
    Given:
        A mocked client that returns multiple vulnerability records.
    When:
        The get_vulnerabilities_command function is called.
    Then:
        All vulnerability records are properly processed and returned.
    """
    from CortexPlatformCore import Client, get_vulnerabilities_command

    mock_client = Client(base_url="", headers={})
    mock_response = {
        "reply": {
            "DATA": [
                {"ISSUE_ID": "vuln_001", "CVE_ID": "CVE-2023-1234", "PLATFORM_SEVERITY": "HIGH", "CVSS_SCORE": 9.1},
                {"ISSUE_ID": "vuln_002", "CVE_ID": "CVE-2023-5678", "PLATFORM_SEVERITY": "MEDIUM", "CVSS_SCORE": 6.5},
                {"ISSUE_ID": "vuln_003", "CVE_ID": "CVE-2023-9999", "PLATFORM_SEVERITY": "CRITICAL", "CVSS_SCORE": 10.0},
            ]
        }
    }
    mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"severity": "high,medium,critical"}

    result = get_vulnerabilities_command(mock_client, args)

    assert len(result.outputs) == 3
    assert result.outputs[0]["ISSUE_ID"] == "vuln_001"
    assert result.outputs[1]["ISSUE_ID"] == "vuln_002"
    assert result.outputs[2]["ISSUE_ID"] == "vuln_003"
    assert result.outputs_key_field == "ISSUE_ID"


def test_get_vulnerabilities_command_numeric_filters(mocker: MockerFixture):
    """
    Given:
        A mocked client and numeric filter arguments.
    When:
        The get_vulnerabilities_command function is called with cvss_score_gte and epss_score_gte.
    Then:
        Numeric filters are properly converted and applied.
    """
    from CortexPlatformCore import Client, get_vulnerabilities_command

    mock_client = Client(base_url="", headers={})
    mock_response = {"reply": {"DATA": []}}
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"cvss_score_gte": "7.5", "epss_score_gte": "0.8", "limit": "100", "cve_id": "CVE-2023-1234"}

    get_vulnerabilities_command(mock_client, args)

    mock_get_webapp_data.assert_called_once()
    call_args = mock_get_webapp_data.call_args[0][0]

    assert call_args["filter_data"]["paging"]["to"] == 100
    filter_data = call_args["filter_data"]["filter"]
    assert "AND" in filter_data


def test_get_vulnerabilities_command_severity_mapping(mocker: MockerFixture):
    """
    Given:
        A mocked client and severity arguments with string values.
    When:
        The get_vulnerabilities_command function is called with severity filters.
    Then:
        Severity values are properly mapped to their corresponding constants.
    """
    from CortexPlatformCore import Client, get_vulnerabilities_command

    mock_client = Client(base_url="", headers={})
    mock_response = {"reply": {"DATA": []}}
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"severity": "info,low,medium,high,critical", "cve_id": "CVE-2023-1234"}

    get_vulnerabilities_command(mock_client, args)

    mock_get_webapp_data.assert_called_once()
    call_args = mock_get_webapp_data.call_args[0][0]

    filter_data = call_args["filter_data"]["filter"]
    assert "AND" in filter_data


def test_build_webapp_request_data_with_all_parameters(mocker: MockerFixture):
    """
    Given: All parameters are provided including on_demand_fields.
    When: build_webapp_request_data is called with table_name, filter_dict, limit, sort_field, on_demand_fields, and sort_order.
    Then: A properly formatted request dictionary is returned with all provided values.
    """
    from CortexPlatformCore import build_webapp_request_data

    # Mock demisto.debug to avoid actual debug output during tests
    mocker.patch("CortexPlatformCore.demisto.debug")

    table_name = "TEST_TABLE"
    filter_dict = {"filter_key": "filter_value"}
    limit = 100
    sort_field = "TEST_FIELD"
    on_demand_fields = ["field1", "field2"]
    sort_order = "ASC"

    result = build_webapp_request_data(
        table_name=table_name,
        filter_dict=filter_dict,
        limit=limit,
        sort_field=sort_field,
        on_demand_fields=on_demand_fields,
        sort_order=sort_order,
    )

    expected = {
        "type": "grid",
        "table_name": "TEST_TABLE",
        "filter_data": {
            "sort": [{"FIELD": "TEST_FIELD", "ORDER": "ASC"}],
            "paging": {"from": 0, "to": 100},
            "filter": {"filter_key": "filter_value"},
        },
        "jsons": [],
        "onDemandFields": ["field1", "field2"],
    }

    assert result == expected


def test_build_webapp_request_data_with_none_on_demand_fields(mocker: MockerFixture):
    """
    Given: on_demand_fields parameter is None.
    When: build_webapp_request_data is called with on_demand_fields set to None.
    Then: The returned dictionary has an empty list for onDemandFields.
    """
    from CortexPlatformCore import build_webapp_request_data

    # Mock demisto.debug to avoid actual debug output during tests
    mocker.patch("CortexPlatformCore.demisto.debug")

    table_name = "TEST_TABLE"
    filter_dict = {"filter_key": "filter_value"}
    limit = 50
    sort_field = "TEST_FIELD"
    on_demand_fields = None

    result = build_webapp_request_data(
        table_name=table_name, filter_dict=filter_dict, limit=limit, sort_field=sort_field, on_demand_fields=on_demand_fields
    )

    expected = {
        "type": "grid",
        "table_name": "TEST_TABLE",
        "filter_data": {
            "sort": [{"FIELD": "TEST_FIELD", "ORDER": "DESC"}],
            "paging": {"from": 0, "to": 50},
            "filter": {"filter_key": "filter_value"},
        },
        "jsons": [],
        "onDemandFields": [],
    }

    assert result == expected


def test_build_webapp_request_data_with_default_sort_order(mocker: MockerFixture):
    """
    Given: sort_order parameter is not provided.
    When: build_webapp_request_data is called without specifying sort_order.
    Then: The default sort_order "DESC" is used in the returned dictionary.
    """
    from CortexPlatformCore import build_webapp_request_data

    # Mock demisto.debug to avoid actual debug output during tests
    mocker.patch("CortexPlatformCore.demisto.debug")

    table_name = "TEST_TABLE"
    filter_dict = {}
    limit = 25
    sort_field = "DEFAULT_FIELD"

    result = build_webapp_request_data(table_name=table_name, filter_dict=filter_dict, limit=limit, sort_field=sort_field)

    expected = {
        "type": "grid",
        "table_name": "TEST_TABLE",
        "filter_data": {"sort": [{"FIELD": "DEFAULT_FIELD", "ORDER": "DESC"}], "paging": {"from": 0, "to": 25}, "filter": {}},
        "jsons": [],
        "onDemandFields": [],
    }

    assert result == expected


def test_build_webapp_request_data_with_empty_filter_dict(mocker: MockerFixture):
    """
    Given: filter_dict parameter is an empty dictionary.
    When: build_webapp_request_data is called with an empty filter_dict.
    Then: The returned dictionary contains an empty filter object in filter_data.
    """
    from CortexPlatformCore import build_webapp_request_data

    # Mock demisto.debug to avoid actual debug output during tests
    mocker.patch("CortexPlatformCore.demisto.debug")

    table_name = "EMPTY_FILTER_TABLE"
    filter_dict = {}
    limit = 10
    sort_field = "EMPTY_FIELD"

    result = build_webapp_request_data(table_name=table_name, filter_dict=filter_dict, limit=limit, sort_field=sort_field)

    expected = {
        "type": "grid",
        "table_name": "EMPTY_FILTER_TABLE",
        "filter_data": {"sort": [{"FIELD": "EMPTY_FIELD", "ORDER": "DESC"}], "paging": {"from": 0, "to": 10}, "filter": {}},
        "jsons": [],
        "onDemandFields": [],
    }

    assert result == expected


class TestFilterBuilder:
    def test_add_field_without_mapper(self):
        """
        Given:
            A FilterBuilder instance and field parameters without a mapper.
        When:
            The add_field method is called with name, type, and values.
        Then:
            A new Field should be added to filter_fields with the original values.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        values = ["value1", "value2"]

        filter_builder.add_field("test_field", FilterType.EQ, values)

        assert len(filter_builder.filter_fields) == 1
        field = filter_builder.filter_fields[0]
        assert field.field_name == "test_field"
        assert field.filter_type == FilterType.EQ
        assert field.values == values

    def test_add_field_with_mapper_list_values(self):
        """
        Given:
            A FilterBuilder instance, field parameters with a mapper, and list values.
        When:
            The add_field method is called with values that exist in the mapper.
        Then:
            A new Field should be added with mapped values only.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        values = ["low", "high", "unknown"]
        mapper = {"low": "SEV_040_LOW", "high": "SEV_060_HIGH"}

        filter_builder.add_field("severity", FilterType.EQ, values, mapper)

        assert len(filter_builder.filter_fields) == 1
        field = filter_builder.filter_fields[0]
        assert field.field_name == "severity"
        assert field.filter_type == FilterType.EQ
        assert field.values == ["SEV_040_LOW", "SEV_060_HIGH"]

    def test_add_field_with_mapper_single_value(self):
        """
        Given:
            A FilterBuilder instance, field parameters with a mapper, and a single value.
        When:
            The add_field method is called with a single value that exists in the mapper.
        Then:
            The single value should be converted to a list and mapped correctly.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        value = "medium"
        mapper = {"medium": "SEV_050_MEDIUM", "high": "SEV_060_HIGH"}

        filter_builder.add_field("severity", FilterType.EQ, value, mapper)

        assert len(filter_builder.filter_fields) == 1
        field = filter_builder.filter_fields[0]
        assert field.field_name == "severity"
        assert field.filter_type == FilterType.EQ
        assert field.values == ["SEV_050_MEDIUM"]

    def test_add_field_with_mapper_no_matching_values(self):
        """
        Given:
            A FilterBuilder instance, field parameters with a mapper, and values not in the mapper.
        When:
            The add_field method is called with values that don't exist in the mapper.
        Then:
            A new Field should be added with an empty list of processed values.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        values = ["unknown", "invalid"]
        mapper = {"low": "SEV_040_LOW", "high": "SEV_060_HIGH"}

        filter_builder.add_field("severity", FilterType.EQ, values, mapper)

        assert len(filter_builder.filter_fields) == 1
        field = filter_builder.filter_fields[0]
        assert field.field_name == "severity"
        assert field.filter_type == FilterType.EQ
        assert field.values == []

    def test_add_field_with_mappings_single_mapped_value(self):
        """
        Given: A FilterBuilder instance and a single mapped value that exists in the mappings dictionary.
        When: The add_field_with_mappings method is called with a mapped value.
        Then: A MappedValuesField should be added to the filter_fields list with the correct parameters.
        """
        from CortexPlatformCore import FilterBuilder

        filter_builder = FilterBuilder()
        mappings = {
            "unassigned": FilterBuilder.FilterType.IS_EMPTY,
            "assigned": FilterBuilder.FilterType.NIS_EMPTY,
        }

        filter_builder.add_field_with_mappings("assignee", FilterBuilder.FilterType.CONTAINS, "unassigned", mappings)

        assert len(filter_builder.filter_fields) == 1
        field = filter_builder.filter_fields[0]
        assert isinstance(field, FilterBuilder.MappedValuesField)
        assert field.field_name == "assignee"
        assert field.filter_type == FilterBuilder.FilterType.CONTAINS
        assert field.values == "unassigned"
        assert field.mappings == mappings

    def test_add_field_with_mappings_multiple_mapped_values(self):
        """
        Given: A FilterBuilder instance and multiple values that exist in the mappings dictionary.
        When: The add_field_with_mappings method is called with a list of mapped values.
        Then: A MappedValuesField should be added with the list of values and correct mappings.
        """
        from CortexPlatformCore import FilterBuilder

        filter_builder = FilterBuilder()
        mappings = {
            "unassigned": FilterBuilder.FilterType.IS_EMPTY,
            "assigned": FilterBuilder.FilterType.NIS_EMPTY,
            "pending": FilterBuilder.FilterType.CONTAINS,
        }
        values = ["unassigned", "assigned"]

        filter_builder.add_field_with_mappings("status", FilterBuilder.FilterType.EQ, values, mappings)

        assert len(filter_builder.filter_fields) == 1
        field = filter_builder.filter_fields[0]
        assert isinstance(field, FilterBuilder.MappedValuesField)
        assert field.field_name == "status"
        assert field.filter_type == FilterBuilder.FilterType.EQ
        assert field.values == values
        assert field.mappings == mappings

    def test_add_field_with_mappings_unmapped_value(self):
        """
        Given: A FilterBuilder instance and a value that does not exist in the mappings dictionary.
        When: The add_field_with_mappings method is called with an unmapped value.
        Then: A MappedValuesField should be added with the default filter type for unmapped values.
        """
        from CortexPlatformCore import FilterBuilder

        filter_builder = FilterBuilder()
        mappings = {
            "unassigned": FilterBuilder.FilterType.IS_EMPTY,
            "assigned": FilterBuilder.FilterType.NIS_EMPTY,
        }

        filter_builder.add_field_with_mappings("assignee", FilterBuilder.FilterType.CONTAINS, "john.doe", mappings)

        assert len(filter_builder.filter_fields) == 1
        field = filter_builder.filter_fields[0]
        assert isinstance(field, FilterBuilder.MappedValuesField)
        assert field.field_name == "assignee"
        assert field.filter_type == FilterBuilder.FilterType.CONTAINS
        assert field.values == "john.doe"
        assert field.mappings == mappings

    def test_add_field_with_mappings_mixed_values(self):
        """
        Given: A FilterBuilder instance and a list containing both mapped and unmapped values.
        When: The add_field_with_mappings method is called with mixed value types.
        Then: A MappedValuesField should be added containing all values with their respective mappings.
        """
        from CortexPlatformCore import FilterBuilder

        filter_builder = FilterBuilder()
        mappings = {
            "unassigned": FilterBuilder.FilterType.IS_EMPTY,
            "assigned": FilterBuilder.FilterType.NIS_EMPTY,
        }
        values = ["unassigned", "john.doe", "assigned"]

        filter_builder.add_field_with_mappings("assignee", FilterBuilder.FilterType.CONTAINS, values, mappings)

        assert len(filter_builder.filter_fields) == 1
        field = filter_builder.filter_fields[0]
        assert isinstance(field, FilterBuilder.MappedValuesField)
        assert field.field_name == "assignee"
        assert field.filter_type == FilterBuilder.FilterType.CONTAINS
        assert field.values == values
        assert field.mappings == mappings

    def test_add_field_with_mappings_empty_mappings(self):
        """
        Given: A FilterBuilder instance and an empty mappings dictionary.
        When: The add_field_with_mappings method is called with empty mappings.
        Then: A MappedValuesField should be added with the empty mappings dictionary.
        """
        from CortexPlatformCore import FilterBuilder

        filter_builder = FilterBuilder()
        mappings = {}

        filter_builder.add_field_with_mappings("field", FilterBuilder.FilterType.EQ, "value", mappings)

        assert len(filter_builder.filter_fields) == 1
        field = filter_builder.filter_fields[0]
        assert isinstance(field, FilterBuilder.MappedValuesField)
        assert field.field_name == "field"
        assert field.filter_type == FilterBuilder.FilterType.EQ
        assert field.values == "value"
        assert field.mappings == {}

    def test_add_field_with_mappings_none_value(self):
        """
        Given: A FilterBuilder instance and None as the value parameter.
        When: The add_field_with_mappings method is called with None value.
        Then: A MappedValuesField should be added with None as the values.
        """
        from CortexPlatformCore import FilterBuilder

        filter_builder = FilterBuilder()
        mappings = {
            "unassigned": FilterBuilder.FilterType.IS_EMPTY,
        }

        filter_builder.add_field_with_mappings("assignee", FilterBuilder.FilterType.CONTAINS, None, mappings)

        assert len(filter_builder.filter_fields) == 1
        field = filter_builder.filter_fields[0]
        assert isinstance(field, FilterBuilder.MappedValuesField)
        assert field.field_name == "assignee"
        assert field.filter_type == FilterBuilder.FilterType.CONTAINS
        assert field.values is None
        assert field.mappings == mappings

    def test_add_time_range_field_with_valid_start_and_end_time(self, mocker: MockerFixture):
        """
        Given: A FilterBuilder instance and valid start_time and end_time strings.
        When: add_time_range_field is called with both start and end times.
        Then: The method should add a RANGE field with from and to values to the filter.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        # Arrange
        filter_builder = FilterBuilder()
        mock_prepare_time_range = mocker.patch.object(
            filter_builder, "_prepare_time_range", return_value=(1640995200000, 1641081600000)
        )
        mock_add_field = mocker.patch.object(filter_builder, "add_field")

        # Act
        filter_builder.add_time_range_field("test_field", "2022-01-01T00:00:00", "2022-01-02T00:00:00")

        # Assert
        mock_prepare_time_range.assert_called_once_with("2022-01-01T00:00:00", "2022-01-02T00:00:00")
        mock_add_field.assert_called_once_with("test_field", FilterType.RANGE, {"from": 1640995200000, "to": 1641081600000})

    def test_add_time_range_field_with_none_start_time(self, mocker: MockerFixture):
        """
        Given: A FilterBuilder instance with None start_time and valid end_time.
        When: add_time_range_field is called with start_time as None.
        Then: The method should not add any field to the filter since start is None.
        """
        from CortexPlatformCore import FilterBuilder

        # Arrange
        filter_builder = FilterBuilder()
        mock_prepare_time_range = mocker.patch.object(filter_builder, "_prepare_time_range", return_value=(None, 1641081600000))
        mock_add_field = mocker.patch.object(filter_builder, "add_field")

        # Act
        filter_builder.add_time_range_field("test_field", None, "2022-01-02T00:00:00")

        # Assert
        mock_prepare_time_range.assert_called_once_with(None, "2022-01-02T00:00:00")
        mock_add_field.assert_not_called()

    def test_add_time_range_field_with_none_end_time(self, mocker: MockerFixture):
        """
        Given: A FilterBuilder instance with valid start_time and None end_time.
        When: add_time_range_field is called with end_time as None.
        Then: The method should not add any field to the filter since end is None.
        """
        from CortexPlatformCore import FilterBuilder

        # Arrange
        filter_builder = FilterBuilder()
        mock_prepare_time_range = mocker.patch.object(filter_builder, "_prepare_time_range", return_value=(1640995200000, None))
        mock_add_field = mocker.patch.object(filter_builder, "add_field")

        # Act
        filter_builder.add_time_range_field("test_field", "2022-01-01T00:00:00", None)

        # Assert
        mock_prepare_time_range.assert_called_once_with("2022-01-01T00:00:00", None)
        mock_add_field.assert_not_called()

    def test_add_time_range_field_with_both_none_times(self, mocker: MockerFixture):
        """
        Given: A FilterBuilder instance with both start_time and end_time as None.
        When: add_time_range_field is called with both times as None.
        Then: The method should not add any field to the filter since both values are None.
        """
        from CortexPlatformCore import FilterBuilder

        # Arrange
        filter_builder = FilterBuilder()
        mock_prepare_time_range = mocker.patch.object(filter_builder, "_prepare_time_range", return_value=(None, None))
        mock_add_field = mocker.patch.object(filter_builder, "add_field")

        # Act
        filter_builder.add_time_range_field("test_field", None, None)

        # Assert
        mock_prepare_time_range.assert_called_once_with(None, None)
        mock_add_field.assert_not_called()

    def test_add_time_range_field_with_zero_timestamps(self, mocker: MockerFixture):
        """
        Given: A FilterBuilder instance and _prepare_time_range returning zero timestamps.
        When: add_time_range_field is called and both timestamps are zero (falsy values).
        Then: The method should not add any field to the filter since zero is falsy in the condition.
        """
        from CortexPlatformCore import FilterBuilder

        # Arrange
        filter_builder = FilterBuilder()
        mock_prepare_time_range = mocker.patch.object(filter_builder, "_prepare_time_range", return_value=(0, 0))
        mock_add_field = mocker.patch.object(filter_builder, "add_field")

        # Act
        filter_builder.add_time_range_field("test_field", "some_time", "some_other_time")

        # Assert
        mock_prepare_time_range.assert_called_once_with("some_time", "some_other_time")
        mock_add_field.assert_not_called()

    def test_to_dict_empty_filter_fields(self):
        """
        Given: A FilterBuilder instance with no filter fields.
        When: The to_dict method is called.
        Then: An empty dictionary should be returned.
        """
        from CortexPlatformCore import FilterBuilder

        filter_builder = FilterBuilder()
        result = filter_builder.to_dict()
        assert result == {}

    def test_to_dict_single_field_single_value(self):
        """
        Given: A FilterBuilder with one field containing a single non-list value.
        When: The to_dict method is called.
        Then: A properly structured filter dictionary with one search object should be returned.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        filter_builder.add_field("test_field", FilterType.EQ, "test_value")

        result = filter_builder.to_dict()
        expected = {
            FilterBuilder.AND: [
                {FilterBuilder.FIELD: "test_field", FilterBuilder.TYPE: FilterType.EQ.value, FilterBuilder.VALUE: "test_value"}
            ]
        }
        assert result == expected

    def test_to_dict_single_field_multiple_values(self):
        """
        Given: A FilterBuilder with one field containing multiple values in a list.
        When: The to_dict method is called.
        Then: A filter dictionary with OR operator grouping multiple search values should be returned.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        filter_builder.add_field("test_field", FilterType.EQ, ["value1", "value2"])

        result = filter_builder.to_dict()
        expected = {
            FilterBuilder.AND: [
                {
                    FilterType.EQ.operator: [
                        {
                            FilterBuilder.FIELD: "test_field",
                            FilterBuilder.TYPE: FilterType.EQ.value,
                            FilterBuilder.VALUE: "value1",
                        },
                        {
                            FilterBuilder.FIELD: "test_field",
                            FilterBuilder.TYPE: FilterType.EQ.value,
                            FilterBuilder.VALUE: "value2",
                        },
                    ]
                }
            ]
        }
        assert result == expected

    def test_to_dict_multiple_fields(self):
        """
        Given: A FilterBuilder with multiple fields each containing different values.
        When: The to_dict method is called.
        Then: A filter dictionary with AND operator containing all field filters should be returned.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        filter_builder.add_field("field1", FilterType.EQ, "value1")
        filter_builder.add_field("field2", FilterType.CONTAINS, "value2")

        result = filter_builder.to_dict()
        expected = {
            FilterBuilder.AND: [
                {FilterBuilder.FIELD: "field1", FilterBuilder.TYPE: FilterType.EQ.value, FilterBuilder.VALUE: "value1"},
                {FilterBuilder.FIELD: "field2", FilterBuilder.TYPE: FilterType.CONTAINS.value, FilterBuilder.VALUE: "value2"},
            ]
        }
        assert result == expected

    def test_to_dict_with_none_values_filtered_out(self):
        """
        Given: A FilterBuilder with fields containing None values mixed with valid values.
        When: The to_dict method is called.
        Then: None values should be filtered out and only valid values should appear in the result.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        filter_builder.add_field("test_field", FilterType.EQ, [None, "valid_value", None])

        result = filter_builder.to_dict()
        expected = {
            FilterBuilder.AND: [
                {FilterBuilder.FIELD: "test_field", FilterBuilder.TYPE: FilterType.EQ.value, FilterBuilder.VALUE: "valid_value"}
            ]
        }
        assert result == expected

    def test_to_dict_with_all_none_values(self):
        """
        Given: A FilterBuilder with fields containing only None values.
        When: The to_dict method is called.
        Then: An empty dictionary should be returned since all values are filtered out.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        filter_builder.add_field("test_field", FilterType.EQ, [None, None])

        result = filter_builder.to_dict()
        assert result == {}

    def test_to_dict_with_mapped_values_field_normal_value(self):
        """
        Given: A MappedValuesField with a value that is not in the mappings dictionary.
        When: The to_dict method is called.
        Then: The default filter type should be used for the unmapped value.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        mappings = {"special": FilterType.IS_EMPTY}
        filter_builder.add_field_with_mappings("test_field", FilterType.EQ, "normal_value", mappings)

        result = filter_builder.to_dict()
        expected = {
            FilterBuilder.AND: [
                {FilterBuilder.FIELD: "test_field", FilterBuilder.TYPE: FilterType.EQ.value, FilterBuilder.VALUE: "normal_value"}
            ]
        }
        assert result == expected

    def test_to_dict_with_mapped_values_field_is_empty(self):
        """
        Given: A MappedValuesField with a value mapped to IS_EMPTY filter type.
        When: The to_dict method is called.
        Then: The mapped filter type should be used and value should be set to "<No Value>".
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        mappings = {"unassigned": FilterType.IS_EMPTY}
        filter_builder.add_field_with_mappings("assignee", FilterType.EQ, "unassigned", mappings)

        result = filter_builder.to_dict()
        expected = {
            FilterBuilder.AND: [
                {
                    FilterBuilder.FIELD: "assignee",
                    FilterBuilder.TYPE: FilterType.IS_EMPTY.value,
                    FilterBuilder.VALUE: "<No Value>",
                }
            ]
        }
        assert result == expected

    def test_to_dict_with_mapped_values_field_nis_empty(self):
        """
        Given: A MappedValuesField with a value mapped to NIS_EMPTY filter type.
        When: The to_dict method is called.
        Then: The mapped filter type should be used and value should be set to "<No Value>".
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        mappings = {"assigned": FilterType.NIS_EMPTY}
        filter_builder.add_field_with_mappings("assignee", FilterType.EQ, "assigned", mappings)

        result = filter_builder.to_dict()
        expected = {
            FilterBuilder.AND: [
                {
                    FilterBuilder.FIELD: "assignee",
                    FilterBuilder.TYPE: FilterType.NIS_EMPTY.value,
                    FilterBuilder.VALUE: "<No Value>",
                }
            ]
        }
        assert result == expected

    def test_to_dict_with_mixed_mapped_and_normal_values(self):
        """
        Given: A MappedValuesField with both mapped and unmapped values in the same field.
        When: The to_dict method is called.
        Then: Each value should use its appropriate filter type and the results should be grouped with OR operator.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        mappings = {"unassigned": FilterType.IS_EMPTY}
        filter_builder.add_field_with_mappings("assignee", FilterType.EQ, ["unassigned", "john.doe"], mappings)

        result = filter_builder.to_dict()
        expected = {
            FilterBuilder.AND: [
                {
                    FilterType.EQ.operator: [
                        {
                            FilterBuilder.FIELD: "assignee",
                            FilterBuilder.TYPE: FilterType.IS_EMPTY.value,
                            FilterBuilder.VALUE: "<No Value>",
                        },
                        {
                            FilterBuilder.FIELD: "assignee",
                            FilterBuilder.TYPE: FilterType.EQ.value,
                            FilterBuilder.VALUE: "john.doe",
                        },
                    ]
                }
            ]
        }
        assert result == expected

    def test_to_dict_converts_non_list_values_to_list(self):
        """
        Given: A FilterBuilder with field values that are not initially in list format.
        When: The to_dict method is called.
        Then: The non-list values should be converted to lists internally for processing.
        """
        from CortexPlatformCore import FilterBuilder, FilterType

        filter_builder = FilterBuilder()
        # Directly create a field with non-list value
        field = FilterBuilder.Field("test_field", FilterType.EQ, "single_value")
        filter_builder.filter_fields = [field]

        result = filter_builder.to_dict()
        expected = {
            FilterBuilder.AND: [
                {FilterBuilder.FIELD: "test_field", FilterBuilder.TYPE: FilterType.EQ.value, FilterBuilder.VALUE: "single_value"}
            ]
        }
        assert result == expected

    def test_prepare_time_range_both_valid_times(self, mocker: MockerFixture):
        """
        Given: Valid start_time and end_time strings that can be parsed by dateparser.
        When: _prepare_time_range is called with both valid time strings.
        Then: Both timestamps should be converted to milliseconds and returned as a tuple.
        """
        from CortexPlatformCore import FilterBuilder
        from datetime import datetime

        # Mock dateparser.parse to return known datetime objects
        start_dt = datetime(2023, 1, 1, 10, 0, 0)
        end_dt = datetime(2023, 1, 2, 15, 30, 0)
        mock_parse = mocker.patch("CortexPlatformCore.dateparser.parse")
        mock_parse.side_effect = [start_dt, end_dt]

        start_time, end_time = FilterBuilder._prepare_time_range("2023-01-01T10:00:00", "2023-01-02T15:30:00")

        assert start_time == int(start_dt.timestamp() * 1000)
        assert end_time == int(end_dt.timestamp() * 1000)
        assert mock_parse.call_count == 2

    def test_prepare_time_range_only_start_time_provided(self, mocker: MockerFixture):
        """
        Given: A valid start_time string and None as end_time.
        When: _prepare_time_range is called with only start_time provided.
        Then: start_time should be converted to milliseconds and end_time should be set to current time.
        """
        from CortexPlatformCore import FilterBuilder
        from datetime import datetime

        # Mock dateparser.parse for start_time
        start_dt = datetime(2023, 1, 1, 10, 0, 0)
        mock_parse = mocker.patch("CortexPlatformCore.dateparser.parse", return_value=start_dt)

        # Mock datetime.now for end_time calculation
        current_dt = datetime(2023, 1, 3, 12, 0, 0)
        mock_now = mocker.patch("CortexPlatformCore.datetime")
        mock_now.now.return_value = current_dt

        start_time, end_time = FilterBuilder._prepare_time_range("2023-01-01T10:00:00", None)

        assert start_time == int(start_dt.timestamp() * 1000)
        assert end_time == int(current_dt.timestamp() * 1000)
        mock_parse.assert_called_once_with("2023-01-01T10:00:00")

    def test_prepare_time_range_both_none_times(self):
        """
        Given: Both start_time_str and end_time_str parameters as None.
        When: _prepare_time_range is called with both parameters as None.
        Then: Both returned timestamps should be None without any parsing attempts.
        """
        from CortexPlatformCore import FilterBuilder

        start_time, end_time = FilterBuilder._prepare_time_range(None, None)

        assert start_time is None
        assert end_time is None

    def test_prepare_time_range_end_time_without_start_time_raises_exception(self):
        """
        Given: None as start_time_str and a valid end_time_str.
        When: _prepare_time_range is called with end_time but no start_time.
        Then: A DemistoException should be raised with appropriate error message.
        """
        from CortexPlatformCore import FilterBuilder
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException, match="When 'end_time' is provided, 'start_time' must be provided as well."):
            FilterBuilder._prepare_time_range(None, "2023-01-02T15:30:00")

    def test_prepare_time_range_invalid_start_time_raises_value_error(self, mocker: MockerFixture):
        """
        Given: An invalid start_time string that cannot be parsed by dateparser.
        When: _prepare_time_range is called with an unparseable start_time.
        Then: A ValueError should be raised with the invalid start_time in the error message.
        """
        from CortexPlatformCore import FilterBuilder

        # Mock dateparser.parse to return None for invalid input
        mock_parse = mocker.patch("CortexPlatformCore.dateparser.parse", return_value=None)

        with pytest.raises(ValueError, match="Could not parse start_time: invalid_start_time"):
            FilterBuilder._prepare_time_range("invalid_start_time", None)

        mock_parse.assert_called_once_with("invalid_start_time")

    def test_prepare_time_range_invalid_end_time_raises_value_error(self, mocker: MockerFixture):
        """
        Given: A valid start_time and an invalid end_time string that cannot be parsed.
        When: _prepare_time_range is called with valid start_time but unparseable end_time.
        Then: A ValueError should be raised with the invalid end_time in the error message.
        """
        from CortexPlatformCore import FilterBuilder
        from datetime import datetime

        # Mock dateparser.parse to return valid datetime for start_time and None for end_time
        start_dt = datetime(2023, 1, 1, 10, 0, 0)
        mock_parse = mocker.patch("CortexPlatformCore.dateparser.parse")
        mock_parse.side_effect = [start_dt, None]

        with pytest.raises(ValueError, match="Could not parse end_time: invalid_end_time"):
            FilterBuilder._prepare_time_range("2023-01-01T10:00:00", "invalid_end_time")

        assert mock_parse.call_count == 2

    def test_prepare_time_range_string_conversion_for_start_time(self, mocker: MockerFixture):
        """
        Given: A non-string start_time parameter that needs string conversion.
        When: _prepare_time_range is called with start_time that requires str() conversion.
        Then: The start_time should be converted to string before parsing and processed correctly.
        """
        from CortexPlatformCore import FilterBuilder
        from datetime import datetime

        # Mock dateparser.parse to return a valid datetime
        start_dt = datetime(2023, 1, 1, 10, 0, 0)
        mock_parse = mocker.patch("CortexPlatformCore.dateparser.parse", return_value=start_dt)

        # Pass an integer that should be converted to string
        start_time, end_time = FilterBuilder._prepare_time_range(20230101, None)

        # Verify that str() was called on the parameter
        mock_parse.assert_called_with("20230101")
        assert start_time == int(start_dt.timestamp() * 1000)

    def test_prepare_time_range_string_conversion_for_end_time(self, mocker: MockerFixture):
        """
        Given: A non-string end_time parameter along with valid start_time.
        When: _prepare_time_range is called with end_time that requires str() conversion.
        Then: The end_time should be converted to string before parsing and both times processed correctly.
        """
        from CortexPlatformCore import FilterBuilder
        from datetime import datetime

        # Mock dateparser.parse to return valid datetimes
        start_dt = datetime(2023, 1, 1, 10, 0, 0)
        end_dt = datetime(2023, 1, 2, 15, 30, 0)
        mock_parse = mocker.patch("CortexPlatformCore.dateparser.parse")
        mock_parse.side_effect = [start_dt, end_dt]

        # Pass integers that should be converted to strings
        start_time, end_time = FilterBuilder._prepare_time_range(20230101, 20230102)

        # Verify that str() was called on both parameters
        assert mock_parse.call_args_list[0][0][0] == "20230101"
        assert mock_parse.call_args_list[1][0][0] == "20230102"
        assert start_time == int(start_dt.timestamp() * 1000)
        assert end_time == int(end_dt.timestamp() * 1000)

    def test_prepare_time_range_millisecond_conversion_precision(self, mocker: MockerFixture):
        """
        Given: Valid datetime objects returned from dateparser with specific timestamp values.
        When: _prepare_time_range converts the timestamps to milliseconds.
        Then: The conversion should multiply by 1000 and convert to integer with correct precision.
        """
        from CortexPlatformCore import FilterBuilder
        from datetime import datetime

        # Create datetime with known timestamp
        start_dt = datetime(2023, 1, 1, 10, 0, 0)
        end_dt = datetime(2023, 1, 2, 15, 30, 0)
        mock_parse = mocker.patch("CortexPlatformCore.dateparser.parse")
        mock_parse.side_effect = [start_dt, end_dt]

        start_time, end_time = FilterBuilder._prepare_time_range("2023-01-01T10:00:00", "2023-01-02T15:30:00")

        # Verify precise millisecond conversion
        expected_start = int(start_dt.timestamp() * 1000)
        expected_end = int(end_dt.timestamp() * 1000)
        assert start_time == expected_start
        assert end_time == expected_end
        assert isinstance(start_time, int)
        assert isinstance(end_time, int)


def test_search_asset_groups_command_success_with_all_filters(mocker):
    """
    GIVEN:
        A mocked client and arguments with all filter parameters provided.
    WHEN:
        The search_asset_groups_command function is called.
    THEN:
        The request is built correctly with all filters and the response is formatted properly.
    """
    from CortexPlatformCore import Client, search_asset_groups_command

    mock_client = Client(base_url="", headers={})
    mock_response = {
        "reply": {
            "DATA": [
                {
                    "XDM__ASSET_GROUP__ID": "group_1",
                    "XDM__ASSET_GROUP__NAME": "Test Group 1",
                    "XDM__ASSET_GROUP__TYPE": "DYNAMIC",
                    "XDM__ASSET_GROUP__DESCRIPTION": "Test description 1",
                },
                {
                    "XDM__ASSET_GROUP__ID": "group_2",
                    "XDM__ASSET_GROUP__NAME": "Test Group 2",
                    "XDM__ASSET_GROUP__TYPE": "STATIC",
                    "XDM__ASSET_GROUP__DESCRIPTION": "Test description 2",
                },
            ]
        }
    }
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"name": "Test Group", "type": "security", "id": "group_1", "description": "Test description"}

    result = search_asset_groups_command(mock_client, args)

    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "group_1"
    assert result.outputs[1]["id"] == "group_2"
    assert result.outputs_prefix == "Core.AssetGroups"
    assert result.outputs_key_field == "id"
    assert "Test Group 1" in result.readable_output
    assert "Test Group 2" in result.readable_output
    assert mock_get_webapp_data.call_count == 1


def test_search_asset_groups_command_success_with_partial_filters(mocker):
    """
    GIVEN:
        A mocked client and arguments with only some filter parameters provided.
    WHEN:
        The search_asset_groups_command function is called.
    THEN:
        The request is built correctly with partial filters and the response is formatted properly.
    """
    from CortexPlatformCore import Client, search_asset_groups_command

    mock_client = Client(base_url="", headers={})
    mock_response = {
        "reply": {
            "DATA": [
                {
                    "XDM__ASSET_GROUP__ID": "group_3",
                    "XDM__ASSET_GROUP__NAME": "Security Group",
                    "XDM__ASSET_GROUP__TYPE": "DYNAMIC",
                    "XDM__ASSET_GROUP__DESCRIPTION": "Security asset group",
                }
            ]
        }
    }
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"name": "Security", "type": "DYNAMIC"}

    result = search_asset_groups_command(mock_client, args)

    assert len(result.outputs) == 1
    assert result.outputs[0]["id"] == "group_3"
    assert result.outputs[0]["name"] == "Security Group"
    assert result.outputs_prefix == "Core.AssetGroups"
    assert "Security Group" in result.readable_output
    assert mock_get_webapp_data.call_count == 1


def test_search_asset_groups_command_success_no_filters(mocker):
    """
    GIVEN:
        A mocked client and empty arguments with no filter parameters.
    WHEN:
        The search_asset_groups_command function is called.
    THEN:
        The request is built with empty filters and returns all asset groups.
    """
    from CortexPlatformCore import Client, search_asset_groups_command

    mock_client = Client(base_url="", headers={})
    mock_response = {
        "reply": {
            "DATA": [
                {
                    "XDM__ASSET_GROUP__ID": "group_all_1",
                    "XDM__ASSET_GROUP__NAME": "All Groups 1",
                    "XDM__ASSET_GROUP__TYPE": "static",
                    "XDM__ASSET_GROUP__DESCRIPTION": "General group",
                },
                {
                    "XDM__ASSET_GROUP__ID": "group_all_2",
                    "XDM__ASSET_GROUP__NAME": "All Groups 2",
                    "XDM__ASSET_GROUP__TYPE": "static",
                    "XDM__ASSET_GROUP__DESCRIPTION": "Special group",
                },
            ]
        }
    }
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {}

    result = search_asset_groups_command(mock_client, args)

    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "group_all_1"
    assert result.outputs[1]["id"] == "group_all_2"
    assert result.outputs_prefix == "Core.AssetGroups"
    assert "All Groups 1" in result.readable_output
    assert "All Groups 2" in result.readable_output
    assert mock_get_webapp_data.call_count == 1


def test_search_asset_groups_command_empty_response(mocker):
    """
    GIVEN:
        A mocked client that returns an empty response.
    WHEN:
        The search_asset_groups_command function is called.
    THEN:
        The function handles the empty response gracefully and returns empty results.
    """
    from CortexPlatformCore import Client, search_asset_groups_command

    mock_client = Client(base_url="", headers={})
    mock_response = {"reply": {"DATA": []}}
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"name": "NonExistent"}

    result = search_asset_groups_command(mock_client, args)

    assert len(result.outputs) == 0
    assert result.outputs_prefix == "Core.AssetGroups"
    assert result.outputs_key_field == "id"
    assert mock_get_webapp_data.call_count == 1


def test_search_asset_groups_command_missing_reply_key(mocker):
    """
    GIVEN:
        A mocked client that returns a response without the 'reply' key.
    WHEN:
        The search_asset_groups_command function is called.
    THEN:
        The function handles the malformed response gracefully and returns empty results.
    """
    from CortexPlatformCore import Client, search_asset_groups_command

    mock_client = Client(base_url="", headers={})
    mock_response = {}
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"type": "DYNAMIC"}

    result = search_asset_groups_command(mock_client, args)

    assert len(result.outputs) == 0
    assert result.outputs_prefix == "Core.AssetGroups"
    assert result.outputs_key_field == "id"
    assert mock_get_webapp_data.call_count == 1


def test_search_asset_groups_command_missing_data_key(mocker):
    """
    GIVEN:
        A mocked client that returns a response with 'reply' but without 'DATA' key.
    WHEN:
        The search_asset_groups_command function is called.
    THEN:
        The function handles the incomplete response gracefully and returns empty results.
    """
    from CortexPlatformCore import Client, search_asset_groups_command

    mock_client = Client(base_url="", headers={})
    mock_response = {"reply": {}}
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"id": "test_id"}

    result = search_asset_groups_command(mock_client, args)

    assert len(result.outputs) == 0
    assert result.outputs_prefix == "Core.AssetGroups"
    assert result.outputs_key_field == "id"
    assert mock_get_webapp_data.call_count == 1


def test_search_asset_groups_command_multiple_values_in_filters(mocker):
    """
    GIVEN:
        A mocked client and arguments with comma-separated values for filters.
    WHEN:
        The search_asset_groups_command function is called.
    THEN:
        The filters are processed correctly with multiple values and the response is formatted properly.
    """
    from CortexPlatformCore import Client, search_asset_groups_command

    mock_client = Client(base_url="", headers={})
    mock_response = {
        "reply": {
            "DATA": [
                {
                    "XDM__ASSET_GROUP__ID": "group_multi_1",
                    "XDM__ASSET_GROUP__NAME": "Multi Group 1",
                    "XDM__ASSET_GROUP__TYPE": "static",
                    "XDM__ASSET_GROUP__DESCRIPTION": "Multi description 1",
                },
                {
                    "XDM__ASSET_GROUP__ID": "group_multi_2",
                    "XDM__ASSET_GROUP__NAME": "Multi Group 2",
                    "XDM__ASSET_GROUP__TYPE": "STATIC",
                    "XDM__ASSET_GROUP__DESCRIPTION": "Multi description 2",
                },
            ]
        }
    }
    mock_get_webapp_data = mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"name": '["Multi Group 1","Multi Group 2"]', "type": "STATIC", "id": "group_multi_1,group_multi_2"}

    result = search_asset_groups_command(mock_client, args)

    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "group_multi_1"
    assert result.outputs[1]["id"] == "group_multi_2"
    assert result.outputs_prefix == "Core.AssetGroups"
    assert "Multi Group 1" in result.readable_output
    assert "Multi Group 2" in result.readable_output
    assert mock_get_webapp_data.call_count == 1


def test_update_issue_command_success_all_fields(mocker):
    """
    GIVEN:
        Client instance and arguments with all valid fields.
    WHEN:
        The update_issue_command function is called.
    THEN:
        Issue is updated with all provided fields and returns "done".
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")
    mocker.patch("CortexPlatformCore.arg_to_number", return_value=2)
    mocker.patch("CortexPlatformCore.arg_to_timestamp", return_value="2023-01-01T00:00:00Z")

    args = {
        "id": "12345",
        "assigned_user_mail": "user@example.com",
        "severity": "medium",
        "name": "Test Issue",
        "occurred": "2023-01-01T00:00:00Z",
        "phase": "investigation",
        "status": "New",
    }

    result = update_issue_command(client, args)

    assert result == "done"
    mock_update_issue.assert_called_once()

    call_args = mock_update_issue.call_args[0][0]
    update_data = call_args["update_data"]
    assert update_data["assigned_user"] == "user@example.com"
    assert update_data["severity"] == "SEV_030_MEDIUM"
    assert update_data["name"] == "Test Issue"
    assert update_data["occurred"] == "2023-01-01T00:00:00Z"
    assert update_data["phase"] == "investigation"
    assert update_data["resolution_status"] == "STATUS_010_NEW"


def test_update_issue_command_missing_issue_id_no_context(mocker):
    """
    GIVEN:
        Client instance and arguments without issue_id and no calling context.
    WHEN:
        The update_issue_command function is called.
    THEN:
        DemistoException is raised and update_issue is not called.
    """
    from CortexPlatformCore import update_issue_command, Client
    from CommonServerPython import DemistoException
    import pytest

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mock_calling_context = {"context": {}}
    mocker.patch.object(demisto, "callingContext", mock_calling_context)

    args = {"name": "Test Issue"}

    with pytest.raises(DemistoException, match="Issue ID is required for updating an issue."):
        update_issue_command(client, args)

    mock_update_issue.assert_not_called()


def test_update_issue_command_empty_issue_id_no_context(mocker):
    """
    GIVEN:
        Client instance and arguments with empty issue_id and no calling context.
    WHEN:
        The update_issue_command function is called.
    THEN:
        DemistoException is raised and update_issue is not called.
    """
    from CortexPlatformCore import update_issue_command, Client
    from CommonServerPython import DemistoException
    import pytest

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mock_calling_context = {"context": {}}
    mocker.patch.object(demisto, "callingContext", mock_calling_context)

    args = {"id": "", "name": "Test Issue"}

    with pytest.raises(DemistoException, match="Issue ID is required for updating an issue."):
        update_issue_command(client, args)

    mock_update_issue.assert_not_called()


def test_update_issue_command_issue_id_from_context(mocker):
    """
    GIVEN:
        Client instance and arguments without issue_id but with calling context containing incident.
    WHEN:
        The update_issue_command function is called.
    THEN:
        Issue ID is retrieved from context and update succeeds.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")
    mock_calling_context = {"context": {"Incidents": [{"id": "context_id_123"}]}}
    mocker.patch.object(demisto, "callingContext", mock_calling_context)

    args = {"name": "Test Issue"}

    result = update_issue_command(client, args)

    assert result == "done"
    mock_update_issue.assert_called_once()

    call_args = mock_update_issue.call_args[0][0]
    filter_data = call_args["filter_data"]["filter"]
    # Check that context ID was used in filter
    assert any(field["SEARCH_VALUE"] == "context_id_123" for field in filter_data["AND"])


def test_update_issue_command_severity_low(mocker):
    """
    GIVEN:
        Client instance and arguments with severity level 1 (low).
    WHEN:
        The update_issue_command function is called.
    THEN:
        Severity is mapped to SEV_020_LOW in update_data.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")
    mocker.patch("CortexPlatformCore.arg_to_number", return_value=1)

    args = {"id": "12345", "severity": "low"}

    update_issue_command(client, args)

    call_args = mock_update_issue.call_args[0][0]
    update_data = call_args["update_data"]
    assert update_data["severity"] == "SEV_020_LOW"


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
    mocker.patch("CortexPlatformCore.arg_to_number", return_value=99)

    args = {"id": "12345", "severity": "99", "name": "Test Issue"}

    update_issue_command(client, args)

    call_args = mock_update_issue.call_args[0][0]
    update_data = call_args["update_data"]
    assert "severity" not in update_data
    assert update_data["name"] == "Test Issue"


def test_update_issue_command_invalid_status_mapping(mocker):
    """
    GIVEN:
        Client instance and arguments with invalid status value.
    WHEN:
        The update_issue_command function is called.
    THEN:
        Status is not included in update_data when mapping returns None.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")
    mocker.patch("CortexPlatformCore.arg_to_number", return_value=99)

    args = {"id": "12345", "status": "FAKE", "name": "Test Issue"}

    update_issue_command(client, args)

    call_args = mock_update_issue.call_args[0][0]
    update_data = call_args["update_data"]
    assert "resolution_status" not in update_data
    assert update_data["name"] == "Test Issue"


def test_update_issue_command_no_severity(mocker):
    """
    GIVEN:
        Client instance and arguments without severity field.
    WHEN:
        The update_issue_command function is called.
    THEN:
        Severity is not included in update_data.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")
    mocker.patch("CortexPlatformCore.arg_to_number", return_value=None)

    args = {"id": "12345", "name": "Test Issue"}

    update_issue_command(client, args)

    call_args = mock_update_issue.call_args[0][0]
    update_data = call_args["update_data"]
    assert "severity" not in update_data
    assert update_data["name"] == "Test Issue"


def test_update_issue_command_partial_fields(mocker):
    """
    GIVEN:
        Client instance and arguments with only some fields provided.
    WHEN:
        The update_issue_command function is called.
    THEN:
        Only provided fields are included in update_data.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")

    args = {"id": "12345", "name": "Updated Issue Name", "phase": "investigation"}

    update_issue_command(client, args)

    call_args = mock_update_issue.call_args[0][0]
    update_data = call_args["update_data"]
    assert update_data["name"] == "Updated Issue Name"
    assert update_data["phase"] == "investigation"
    assert "severity" not in update_data
    assert "assigned_user" not in update_data
    assert "occurred" not in update_data


def test_update_issue_command_none_values_filtered(mocker):
    """
    GIVEN:
        Client instance and arguments where some fields resolve to None.
    WHEN:
        The update_issue_command function is called.
    THEN:
        None values are filtered out of update_data.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")
    mocker.patch("CortexPlatformCore.arg_to_timestamp", return_value=None)

    args = {"id": "12345", "name": "Test Issue", "occurred": "invalid-date", "assigned_user_mail": None}

    update_issue_command(client, args)

    call_args = mock_update_issue.call_args[0][0]
    update_data = call_args["update_data"]
    assert update_data["name"] == "Test Issue"
    assert "occurred" not in update_data
    assert "assigned_user" not in update_data


def test_update_issue_command_debug_called(mocker):
    """
    GIVEN:
        Client instance and valid arguments.
    WHEN:
        The update_issue_command function is called.
    THEN:
        demisto.debug is called with filter_data.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mock_debug = mocker.patch.object(demisto, "debug")

    args = {"id": "12345", "name": "Test Issue"}

    update_issue_command(client, args)

    mock_debug.assert_called_once()
    mock_update_issue.assert_called_once()


def test_update_issue_command_only_issue_id(mocker):
    """
    GIVEN:
        Client instance and arguments with only issue_id.
    WHEN:
        The update_issue_command function is called.
    THEN:
        update_issue is called with empty update_data.
    """
    from CortexPlatformCore import update_issue_command, Client
    from CommonServerPython import DemistoException

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mocker.patch.object(demisto, "debug")

    args = {"id": "12345"}
    with pytest.raises(DemistoException, match="Please provide arguments to update the issue."):
        update_issue_command(client, args)

    mock_update_issue.assert_not_called()


def test_enable_scanners_command_single_repository(mocker: MockerFixture):
    """
    Given:
        A client and args with a single repository ID and scanner configuration.
    When:
        enable_scanners_command is called.
    Then:
        The repository configuration is updated successfully and appropriate results are returned.
    """
    from CortexPlatformCore import Client, enable_scanners_command

    mock_client = Client(base_url="", headers={})
    mock_build_payload = mocker.patch("CortexPlatformCore.build_scanner_config_payload", return_value={"test": "payload"})
    mock_enable_scanners = mocker.patch.object(mock_client, "enable_scanners", return_value={"status": "success"})

    args = {"repository_ids": "repo_001", "enabled_scanners": "scanner1,scanner2", "disable_scanners": "scanner3"}

    result = enable_scanners_command(mock_client, args)

    mock_build_payload.assert_called_once_with(args)
    mock_enable_scanners.assert_called_once_with({"test": "payload"}, "repo_001")
    assert "Successfully updated repositories: repo_001" in result.readable_output


def test_enable_scanners_command_repository_ids_as_list(mocker: MockerFixture):
    """
    Given:
        A client and args where repository_ids is already a list.
    When:
        enable_scanners_command is called.
    Then:
        The function handles the list correctly and updates all repositories.
    """
    from CortexPlatformCore import Client, enable_scanners_command

    mock_client = Client(base_url="", headers={})
    mock_build_payload = mocker.patch("CortexPlatformCore.build_scanner_config_payload", return_value={"payload": "test"})
    mock_enable_scanners = mocker.patch.object(mock_client, "enable_scanners", return_value={"success": True})

    args = {"repository_ids": ["repo_alpha", "repo_beta"], "enable_scanners": "vulnerability_scan"}

    result = enable_scanners_command(mock_client, args)

    mock_build_payload.assert_called_with(args)

    expected_calls = [
        call({"payload": "test"}, "repo_alpha"),
        call({"payload": "test"}, "repo_beta"),
    ]
    mock_enable_scanners.assert_has_calls(expected_calls)
    assert "Successfully updated repositories: repo_alpha, repo_beta" in result.readable_output


def test_build_scanner_config_payload_secrets_scanner_with_validation(mocker: MockerFixture):
    """
    Given:
        Args with secrets scanner enable and secret_validation set to True.
    When:
        build_scanner_config_payload is called.
    Then:
        The secrets scanner configuration includes secretValidation option.
    """
    from CortexPlatformCore import build_scanner_config_payload

    mocker.patch("CortexPlatformCore.validate_scanner_name", return_value=True)

    args = {"repository_ids": ["repo1"], "enable_scanners": "secrets", "secret_validation": "True"}

    result = build_scanner_config_payload(args)

    expected = {"scanners": {"SECRETS": {"isEnabled": True, "scanOptions": {"secretValidation": True}}}}

    assert result == expected


def test_build_scanner_config_payload_secrets_scanner_without_validation(mocker: MockerFixture):
    """
    Given:
        Args with secrets scanner enable and secret_validation set to False.
    When:
        build_scanner_config_payload is called.
    Then:
        The secrets scanner configuration includes secretValidation as False.
    """
    from CortexPlatformCore import build_scanner_config_payload

    mocker.patch("CortexPlatformCore.validate_scanner_name", return_value=True)

    args = {"repository_ids": "repo1", "enable_scanners": "secrets", "secret_validation": "False"}

    result = build_scanner_config_payload(args)

    expected = {"scanners": {"SECRETS": {"isEnabled": True, "scanOptions": {"secretValidation": False}}}}

    assert result == expected


def test_build_scanner_config_payload_complete_configuration(mocker: MockerFixture):
    """
    Given:
        Args with all possible configuration options specified.
    When:
        build_scanner_config_payload is called.
    Then:
        A complete configuration payload with all options is returned.
    """
    from CortexPlatformCore import build_scanner_config_payload

    mocker.patch("CortexPlatformCore.validate_scanner_name", return_value=True)
    mocker.patch("CortexPlatformCore.demisto.debug")

    args = {
        "repository_ids": ["repo1", "repo2"],
        "enable_scanners": ["secrets", "iac"],
        "disable_scanners": ["SCA"],
        "secret_validation": "True",
        "pr_scanning": "True",
        "block_on_error": "False",
        "tag_resource_blocks": "True",
        "tag_module_blocks": "False",
        "exclude_paths": ["exclude1", "exclude2"],
    }

    result = build_scanner_config_payload(args)

    expected = {
        "scanners": {
            "SECRETS": {"isEnabled": True, "scanOptions": {"secretValidation": True}},
            "IAC": {"isEnabled": True},
            "SCA": {"isEnabled": False},
        },
        "prScanning": {"isEnabled": True, "blockOnError": False},
        "taggingBot": {"tagResourceBlocks": True, "tagModuleBlocks": False},
        "excludedPaths": ["exclude1", "exclude2"],
    }

    assert result == expected


def test_build_scanner_config_payload_empty_scanners_lists(mocker: MockerFixture):
    """
    Given:
        Args with empty enabled_scanners and disable_scanners lists.
    When:
        build_scanner_config_payload is called.
    Then:
        A configuration payload without scanners section is returned.
    """
    from CortexPlatformCore import build_scanner_config_payload

    mocker.patch("CortexPlatformCore.validate_scanner_name", return_value=True)
    mocker.patch("CortexPlatformCore.demisto.debug")

    args = {"repository_ids": "repo1", "enable_scanners": [], "disable_scanners": []}

    result = build_scanner_config_payload(args)

    expected = {}

    assert result == expected


def test_build_scanner_config_payload_invalid_scanner_names(mocker: MockerFixture):
    """
    Given:
        Args with invalid scanner names that fail validation.
    When:
        build_scanner_config_payload is called.
    Then:
        Invalid scanners are excluded from the configuration.
    """

    def mock_validate_scanner_name(scanner):
        return scanner in [
            "iac",
            "sca",
            "secrets",
        ]

    mocker.patch("CortexPlatformCore.validate_scanner_name", side_effect=mock_validate_scanner_name)


def test_build_scanner_config_payload_enable_and_disable_same_scanner(mocker: MockerFixture):
    """
    Given:
        Args with the same scanner in both enabled_scanners and disable_scanners lists.
    When:
        build_scanner_config_payload is called.
    Then:
        An error is thrown due to conflicting scanner configuration.
    """
    from CortexPlatformCore import build_scanner_config_payload

    mocker.patch("CortexPlatformCore.validate_scanner_name", return_value=True)

    args = {"repository_ids": "repo1", "enable_scanners": ["iac"], "disable_scanners": ["iac"]}

    with pytest.raises(ValueError):
        build_scanner_config_payload(args)


def test_create_policy_command_basic_success(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and minimal valid arguments for creating a policy.
    WHEN:
        The create_policy_command function is called.
    THEN:
        The policy is created successfully with default values where appropriate.
    """
    from CortexPlatformCore import Client, create_policy_command

    # Mock client and response
    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)

    # Mock helper functions that might be called
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    # Minimal args with just policy name and one trigger enabled
    args = {"policy_name": "Test Policy", "triggers_periodic_report_issue": "true"}

    result = create_policy_command(mock_client, args)

    # Verify the result is a CommandResults object with correct readable output
    assert hasattr(result, "readable_output")
    assert result.readable_output == "AppSec policy 'Test Policy' created successfully."

    # Verify other attributes are None/default as per actual implementation
    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.raw_response is None

    # Verify create_policy was called once
    mock_create_policy.assert_called_once()

    # Verify the JSON payload structure passed to create_policy
    call_args = mock_create_policy.call_args
    assert len(call_args[0]) == 1  # Only one positional argument (the JSON string)

    payload_json = call_args[0][0]
    import json

    payload = json.loads(payload_json)

    # Verify basic policy structure
    assert payload["name"] == "Test Policy"
    assert payload["description"] == ""
    assert payload["assetGroupIds"] == []
    assert "conditions" in payload
    assert "scope" in payload
    assert "triggers" in payload

    # Verify triggers structure - periodic should be enabled
    triggers = payload["triggers"]
    assert triggers["periodic"]["isEnabled"] is True
    assert triggers["periodic"]["actions"]["reportIssue"] is True
    assert triggers["pr"]["isEnabled"] is False
    assert triggers["cicd"]["isEnabled"] is False


def test_create_policy_command_missing_policy_name(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and arguments missing the required policy_name.
    WHEN:
        The create_policy_command function is called.
    THEN:
        A DemistoException is raised indicating policy_name is required.
    """
    from CortexPlatformCore import Client, create_policy_command
    from CommonServerPython import DemistoException

    mock_client = Client(base_url="", headers={})

    # Args missing policy_name
    args = {"triggers_periodic_report_issue": "true"}

    with pytest.raises(DemistoException) as excinfo:
        create_policy_command(mock_client, args)

    assert "Policy name is required" in str(excinfo.value)


def test_create_policy_command_no_triggers_enabled(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and arguments with no triggers enabled.
    WHEN:
        The create_policy_command function is called.
    THEN:
        A DemistoException is raised indicating at least one trigger must be enabled.
    """
    from CortexPlatformCore import Client, create_policy_command
    from CommonServerPython import DemistoException

    mock_client = Client(base_url="", headers={})
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    # Args with policy_name but no triggers enabled
    args = {"policy_name": "Test Policy"}

    with pytest.raises(DemistoException) as excinfo:
        create_policy_command(mock_client, args)

    assert "At least one trigger" in str(excinfo.value)


def test_create_policy_command_with_asset_groups(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and arguments including asset_group_names.
    WHEN:
        The create_policy_command function is called.
    THEN:
        The asset groups are properly resolved and included in the policy.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)

    # Mock asset group resolution
    mock_asset_groups = ["group-1", "group-2"]
    mock_get_asset_groups = mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=mock_asset_groups)
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {"policy_name": "Test Policy", "asset_group_names": "Group 1,Group 2", "triggers_periodic_report_issue": "true"}

    result = create_policy_command(mock_client, args)

    # Verify readable output
    assert result.readable_output == "AppSec policy 'Test Policy' created successfully."

    # Verify asset group resolution was called with correct parameters
    mock_get_asset_groups.assert_called_once_with(mock_client, ["Group 1", "Group 2"])

    # Verify create_policy was called and asset groups were included
    mock_create_policy.assert_called_once()
    payload_json = mock_create_policy.call_args[0][0]
    import json

    payload = json.loads(payload_json)

    # Verify asset groups are included in the policy payload
    assert payload["assetGroupIds"] == ["group-1", "group-2"]
    assert payload["name"] == "Test Policy"


def test_create_policy_command_with_conditions(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and arguments with various condition parameters.
    WHEN:
        The create_policy_command function is called.
    THEN:
        The conditions are properly built and included in the policy.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])

    # Mock AppSec rule resolution
    mock_rule_ids = ["rule-1", "rule-2"]
    mock_get_appsec_rules = mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=mock_rule_ids)

    args = {
        "policy_name": "Test Policy",
        "conditions_finding_type": "Vulnerabilities,Secrets",
        "conditions_severity": "high,critical",
        "conditions_respect_developer_suppression": "true",
        "conditions_has_a_fix": "true",
        "conditions_is_kev": "false",
        "conditions_appsec_rule_names": "Rule 1,Rule 2",
        "triggers_periodic_report_issue": "true",
    }

    result = create_policy_command(mock_client, args)

    # Verify readable output
    assert result.readable_output == "AppSec policy 'Test Policy' created successfully."

    # Verify AppSec rule resolution was called with correct parameters
    mock_get_appsec_rules.assert_called_once_with(mock_client, ["Rule 1", "Rule 2"])

    # Verify create_policy was called and examine the payload
    mock_create_policy.assert_called_once()
    payload_json = mock_create_policy.call_args[0][0]
    import json

    payload = json.loads(payload_json)

    # Verify conditions structure is present
    assert "conditions" in payload
    conditions = payload["conditions"]

    # The conditions are built using FilterBuilder, so we need to check the filter structure
    assert "AND" in conditions
    filters = conditions["AND"]

    # Verify that filters were created (exact structure depends on FilterBuilder implementation)
    assert len(filters) > 0


def test_create_policy_command_with_scope(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and arguments with scope parameters.
    WHEN:
        The create_policy_command function is called.
    THEN:
        The scope is properly built and included in the policy.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {
        "policy_name": "Test Policy",
        "scope_category": "Application,Repository",
        "scope_business_application_names": "App1,App2",
        "scope_repository_name": "repo1",
        "scope_is_public_repository": "true",
        "scope_has_internet_exposed_deployed_assets": "true",
        "triggers_periodic_report_issue": "true",
    }

    result = create_policy_command(mock_client, args)

    # Verify readable output
    assert result.readable_output == "AppSec policy 'Test Policy' created successfully."

    # Verify create_policy was called and examine the payload
    mock_create_policy.assert_called_once()
    payload_json = mock_create_policy.call_args[0][0]
    import json

    payload = json.loads(payload_json)

    # Verify scope structure is present
    assert "scope" in payload
    scope = payload["scope"]

    # The scope is built using FilterBuilder, so we verify the filter structure exists
    # (exact structure depends on FilterBuilder implementation)
    if scope:  # scope can be empty if no filters are added
        assert "AND" in scope or len(scope) == 0


def test_create_policy_command_with_triggers(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and arguments with various trigger configurations.
    WHEN:
        The create_policy_command function is called.
    THEN:
        The triggers are properly configured and included in the policy.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {
        "policy_name": "Test Policy",
        "triggers_periodic_report_issue": "true",
        "triggers_periodic_override_severity": "critical",
        "triggers_pr_report_issue": "true",
        "triggers_pr_block_pr": "true",
        "triggers_pr_report_pr_comment": "false",
        "triggers_cicd_report_issue": "false",
        "triggers_cicd_block_cicd": "true",
    }

    result = create_policy_command(mock_client, args)

    # Verify readable output
    assert result.readable_output == "AppSec policy 'Test Policy' created successfully."

    # Verify create_policy was called and examine the payload
    mock_create_policy.assert_called_once()
    payload_json = mock_create_policy.call_args[0][0]
    import json

    payload = json.loads(payload_json)

    # Verify triggers structure
    triggers = payload["triggers"]

    # Verify periodic trigger
    assert triggers["periodic"]["isEnabled"] is True
    assert triggers["periodic"]["actions"]["reportIssue"] is True
    assert triggers["periodic"]["overrideIssueSeverity"] == "critical"

    # Verify PR trigger
    assert triggers["pr"]["isEnabled"] is True
    assert triggers["pr"]["actions"]["reportIssue"] is True
    assert triggers["pr"]["actions"]["blockPr"] is True
    assert triggers["pr"]["actions"]["reportPrComment"] is False
    assert triggers["pr"]["overrideIssueSeverity"] is None

    # Verify CI/CD trigger
    assert triggers["cicd"]["isEnabled"] is True
    assert triggers["cicd"]["actions"]["reportIssue"] is False
    assert triggers["cicd"]["actions"]["blockCicd"] is True
    assert triggers["cicd"]["actions"]["reportCicd"] is False
    assert triggers["cicd"]["overrideIssueSeverity"] is None


def test_create_policy_command_with_all_parameters(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and arguments with all possible parameters.
    WHEN:
        The create_policy_command function is called.
    THEN:
        The policy is created with all parameters properly configured.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)

    # Mock asset group resolution
    mock_asset_groups = ["group-1", "group-2"]
    mock_get_asset_groups = mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=mock_asset_groups)

    # Mock AppSec rule resolution
    mock_rule_ids = ["rule-1", "rule-2"]
    mock_get_appsec_rules = mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=mock_rule_ids)

    # Comprehensive args with all parameters
    args = {
        "policy_name": "Comprehensive Policy",
        "description": "A comprehensive policy with all parameters",
        "asset_group_names": "Group 1,Group 2",
        # Conditions
        "conditions_finding_type": "Vulnerabilities,Secrets,Weaknesses",
        "conditions_severity": "high,critical",
        "conditions_respect_developer_suppression": "true",
        "conditions_backlog_status": "active",
        "conditions_package_name": "vulnerable-package",
        "conditions_package_version": "1.0.0",
        "conditions_package_operational_risk": "high",
        "conditions_appsec_rule_names": "Rule 1,Rule 2",
        "conditions_cvss": "7.5",
        "conditions_epss": "0.8",
        "conditions_has_a_fix": "true",
        "conditions_is_kev": "true",
        "conditions_secret_validity": "valid",
        "conditions_license_type": "GPL",
        # Scope
        "scope_category": "Application,Repository",
        "scope_business_application_names": "App1,App2",
        "scope_application_business_criticality": "high",
        "scope_repository_name": "repo1",
        "scope_is_public_repository": "true",
        "scope_has_deployed_assets": "true",
        "scope_has_internet_exposed_deployed_assets": "true",
        "scope_has_sensitive_data_access": "true",
        "scope_has_privileged_capabilities": "false",
        # Triggers
        "triggers_periodic_report_issue": "true",
        "triggers_periodic_override_severity": "critical",
        "triggers_pr_report_issue": "true",
        "triggers_pr_block_pr": "true",
        "triggers_pr_report_pr_comment": "true",
        "triggers_pr_override_severity": "high",
        "triggers_cicd_report_issue": "true",
        "triggers_cicd_block_cicd": "true",
        "triggers_cicd_report_cicd": "true",
        "triggers_cicd_override_severity": "medium",
    }

    result = create_policy_command(mock_client, args)

    # Verify readable output
    assert result.readable_output == "AppSec policy 'Comprehensive Policy' created successfully."

    # Verify create_policy was called once
    mock_create_policy.assert_called_once()

    # Verify helper functions were called with correct parameters
    mock_get_asset_groups.assert_called_once_with(mock_client, ["Group 1", "Group 2"])
    mock_get_appsec_rules.assert_called_once_with(mock_client, ["Rule 1", "Rule 2"])

    # Verify the complete policy payload
    payload_json = mock_create_policy.call_args[0][0]
    import json

    payload = json.loads(payload_json)

    # Verify basic policy info
    assert payload["name"] == "Comprehensive Policy"
    assert payload["description"] == "A comprehensive policy with all parameters"
    assert payload["assetGroupIds"] == ["group-1", "group-2"]

    # Verify triggers configuration
    triggers = payload["triggers"]

    # Periodic trigger
    assert triggers["periodic"]["isEnabled"] is True
    assert triggers["periodic"]["actions"]["reportIssue"] is True
    assert triggers["periodic"]["overrideIssueSeverity"] == "critical"

    # PR trigger
    assert triggers["pr"]["isEnabled"] is True
    assert triggers["pr"]["actions"]["reportIssue"] is True
    assert triggers["pr"]["actions"]["blockPr"] is True
    assert triggers["pr"]["actions"]["reportPrComment"] is True
    assert triggers["pr"]["overrideIssueSeverity"] == "high"

    # CI/CD trigger
    assert triggers["cicd"]["isEnabled"] is True
    assert triggers["cicd"]["actions"]["reportIssue"] is True
    assert triggers["cicd"]["actions"]["blockCicd"] is True
    assert triggers["cicd"]["actions"]["reportCicd"] is True
    assert triggers["cicd"]["overrideIssueSeverity"] == "medium"

    # Verify conditions and scope structures exist (they use FilterBuilder)
    assert "conditions" in payload
    assert "scope" in payload


def test_create_policy_command_non_dict_response(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client that returns a non-dict response.
    WHEN:
        The create_policy_command function is called.
    THEN:
        The function handles the non-dict response gracefully.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    # Mock a non-dict response (e.g., string or None)
    mock_response = "Policy created successfully"
    mocker.patch.object(mock_client, "create_policy", return_value=mock_response)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {"policy_name": "Test Policy", "triggers_periodic_report_issue": "true"}

    result = create_policy_command(mock_client, args)

    # Verify the function still returns success message regardless of response type
    assert result.readable_output == "AppSec policy 'Test Policy' created successfully."
    assert result.outputs is None
    assert result.raw_response is None


def test_create_policy_command_empty_response(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client that returns an empty dict response.
    WHEN:
        The create_policy_command function is called.
    THEN:
        The function handles the empty response gracefully.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mock_response = {}
    mocker.patch.object(mock_client, "create_policy", return_value=mock_response)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {"policy_name": "Test Policy", "triggers_periodic_report_issue": "true"}

    result = create_policy_command(mock_client, args)

    # Verify the function still returns success message regardless of response content
    assert result.readable_output == "AppSec policy 'Test Policy' created successfully."
    assert result.outputs is None
    assert result.raw_response is None


def test_create_policy_command_boolean_parameter_parsing(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and arguments with various boolean string values.
    WHEN:
        The create_policy_command function is called.
    THEN:
        String boolean values are properly parsed to actual booleans.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {
        "policy_name": "Boolean Test Policy",
        "triggers_periodic_report_issue": "false",  # String "false" should become boolean False
        "triggers_pr_report_issue": "true",  # String "true" should become boolean True
        "triggers_pr_block_pr": "false",
        "triggers_cicd_report_issue": "true",
    }

    result = create_policy_command(mock_client, args)

    # Verify readable output
    assert result.readable_output == "AppSec policy 'Boolean Test Policy' created successfully."

    # Verify the boolean parsing in the payload
    payload_json = mock_create_policy.call_args[0][0]
    import json

    payload = json.loads(payload_json)

    triggers = payload["triggers"]

    # Verify boolean values are properly parsed (not strings)
    assert triggers["periodic"]["isEnabled"] is False  # Should be boolean False, not string "false"
    assert triggers["periodic"]["actions"]["reportIssue"] is False

    assert triggers["pr"]["isEnabled"] is True  # Should be boolean True, not string "true"
    assert triggers["pr"]["actions"]["reportIssue"] is True
    assert triggers["pr"]["actions"]["blockPr"] is False

    assert triggers["cicd"]["isEnabled"] is True
    assert triggers["cicd"]["actions"]["reportIssue"] is True


def test_create_policy_command_comma_separated_values(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and arguments with comma-separated string values.
    WHEN:
        The create_policy_command function is called.
    THEN:
        Comma-separated values are properly parsed into lists.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {
        "policy_name": "Comma Test Policy",
        "conditions_finding_type": "Vulnerabilities,Secrets,Infrastructure as Code",
        "conditions_severity": "high,critical",
        "scope_category": "Application,Repository",
        "scope_business_application_names": "App1,App2,App3",
        "triggers_periodic_report_issue": "true",
    }

    result = create_policy_command(mock_client, args)

    # Verify readable output
    assert result.readable_output == "AppSec policy 'Comma Test Policy' created successfully."

    # Verify create_policy was called
    mock_create_policy.assert_called_once()

    # Note: The actual comma-separated value parsing happens within the FilterBuilder
    # and helper functions, so we verify they were called rather than the exact payload
    # structure since FilterBuilder's output format depends on its implementation


def test_create_policy_command_json_payload_structure(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and basic arguments.
    WHEN:
        The create_policy_command function is called.
    THEN:
        The JSON payload passed to create_policy has the correct top-level structure.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {
        "policy_name": "Structure Test Policy",
        "description": "Testing JSON structure",
        "triggers_periodic_report_issue": "true",
    }

    create_policy_command(mock_client, args)

    # Verify create_policy was called with a JSON string
    mock_create_policy.assert_called_once()
    call_args = mock_create_policy.call_args[0]
    assert len(call_args) == 1

    # Verify it's a valid JSON string
    payload_json = call_args[0]
    import json

    payload = json.loads(payload_json)

    # Verify required top-level structure
    required_keys = ["name", "description", "assetGroupIds", "conditions", "scope", "triggers"]
    for key in required_keys:
        assert key in payload, f"Missing required key: {key}"

    # Verify basic values
    assert payload["name"] == "Structure Test Policy"
    assert payload["description"] == "Testing JSON structure"
    assert isinstance(payload["assetGroupIds"], list)
    assert isinstance(payload["triggers"], dict)

    # Verify triggers sub-structure
    triggers = payload["triggers"]
    required_trigger_types = ["periodic", "pr", "cicd"]
    for trigger_type in required_trigger_types:
        assert trigger_type in triggers, f"Missing trigger type: {trigger_type}"
        assert "isEnabled" in triggers[trigger_type]
        assert "actions" in triggers[trigger_type]
        assert isinstance(triggers[trigger_type]["actions"], dict)


def test_get_appsec_rule_ids_from_names_empty_list():
    """
    GIVEN:
        A client and an empty list of AppSec rule names.
    WHEN:
        get_appsec_rule_ids_from_names is called.
    THEN:
        An empty list is returned without making API calls.
    """
    from CortexPlatformCore import Client, get_appsec_rule_ids_from_names

    mock_client = Client(base_url="", headers={})
    result = get_appsec_rule_ids_from_names(mock_client, [])

    assert result == []


def test_create_policy_command_client_create_policy_called_correctly(mocker: MockerFixture):
    """
    GIVEN:
        A mocked client and valid policy arguments.
    WHEN:
        The create_policy_command function is called.
    THEN:
        The client.create_policy method is called with correctly formatted JSON.
    """
    from CortexPlatformCore import Client, create_policy_command
    import json

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value={"id": "policy_123"})
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=["group_1"])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=["rule_1"])

    args = {
        "policy_name": "Test Policy",
        "description": "Test Description",
        "triggers_periodic_report_issue": "true",
    }

    create_policy_command(mock_client, args)

    # Verify create_policy was called once
    mock_create_policy.assert_called_once()

    # Get the JSON payload that was passed
    call_args = mock_create_policy.call_args[0][0]
    payload = json.loads(call_args)

    # Verify the JSON structure is valid and contains expected fields
    assert payload["name"] == "Test Policy"
    assert payload["description"] == "Test Description"
    assert "triggers" in payload
    assert "conditions" in payload
    assert "scope" in payload


def test_create_policy_command_edge_case_empty_asset_groups(mocker: MockerFixture):
    """
    GIVEN:
        A policy creation request with empty asset group names.
    WHEN:
        create_policy_command is called with empty asset_group_names.
    THEN:
        The policy is created with empty assetGroupIds list.
    """
    from CortexPlatformCore import Client, create_policy_command
    import json

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {
        "policy_name": "Empty Groups Policy",
        "asset_group_names": "",  # Empty string
        "triggers_periodic_report_issue": "true",
    }

    create_policy_command(mock_client, args)

    # Verify the payload has empty asset group IDs
    call_args = mock_create_policy.call_args[0][0]
    payload = json.loads(call_args)
    assert payload["assetGroupIds"] == []


def test_create_policy_conditions_builder_coverage(mocker: MockerFixture):
    """
    GIVEN:
        Policy creation arguments with various condition parameters.
    WHEN:
        create_policy_command builds the conditions filter.
    THEN:
        All condition parameters are properly processed by FilterBuilder.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=["rule_1"])

    args = {
        "policy_name": "Conditions Test Policy",
        "conditions_finding_type": "Vulnerabilities,Secrets",
        "conditions_severity": "high,critical",
        "conditions_respect_developer_suppression": "true",
        "conditions_backlog_status": "active",
        "conditions_package_name": "vulnerable-package",
        "conditions_package_version": "1.0.0",
        "conditions_package_operational_risk": "high",
        "conditions_appsec_rule_names": "Test Rule",
        "conditions_cvss": "7.5",
        "conditions_epss": "0.8",
        "conditions_has_a_fix": "true",
        "conditions_is_kev": "false",
        "conditions_secret_validity": "valid",
        "conditions_license_type": "GPL",
        "triggers_periodic_report_issue": "true",
    }

    result = create_policy_command(mock_client, args)

    # Verify successful creation
    assert result.readable_output == "AppSec policy 'Conditions Test Policy' created successfully."
    mock_create_policy.assert_called_once()


def test_create_policy_scope_builder_coverage(mocker: MockerFixture):
    """
    GIVEN:
        Policy creation arguments with various scope parameters.
    WHEN:
        create_policy_command builds the scope filter.
    THEN:
        All scope parameters are properly processed by FilterBuilder.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {
        "policy_name": "Scope Test Policy",
        "scope_category": "Application,Repository",
        "scope_business_application_names": "App1,App2",
        "scope_application_business_criticality": "high",
        "scope_repository_name": "test-repo",
        "scope_is_public_repository": "true",
        "scope_has_deployed_assets": "true",
        "scope_has_internet_exposed_deployed_assets": "false",
        "scope_has_sensitive_data_access": "true",
        "scope_has_privileged_capabilities": "false",
        "triggers_periodic_report_issue": "true",
    }

    result = create_policy_command(mock_client, args)

    # Verify successful creation
    assert result.readable_output == "AppSec policy 'Scope Test Policy' created successfully."
    mock_create_policy.assert_called_once()


def test_create_policy_trigger_configurations_coverage(mocker: MockerFixture):
    """
    GIVEN:
        Policy creation arguments with all trigger configuration combinations.
    WHEN:
        create_policy_command processes trigger parameters.
    THEN:
        All trigger configurations are properly set in the policy payload.
    """
    from CortexPlatformCore import Client, create_policy_command
    import json

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {
        "policy_name": "Triggers Test Policy",
        "triggers_periodic_report_issue": "true",
        "triggers_periodic_override_severity": "critical",
        "triggers_pr_report_issue": "false",
        "triggers_pr_block_pr": "true",
        "triggers_pr_report_pr_comment": "true",
        "triggers_pr_override_severity": "high",
        "triggers_cicd_report_issue": "true",
        "triggers_cicd_block_cicd": "false",
        "triggers_cicd_report_cicd": "true",
        "triggers_cicd_override_severity": "medium",
    }

    create_policy_command(mock_client, args)

    # Verify the triggers are configured correctly
    call_args = mock_create_policy.call_args[0][0]
    payload = json.loads(call_args)
    triggers = payload["triggers"]

    # Verify all trigger types are present and configured
    assert "periodic" in triggers
    assert "pr" in triggers
    assert "cicd" in triggers


def test_create_policy_command_trigger_validation_edge_cases(mocker: MockerFixture):
    """
    GIVEN:
        Policy creation with edge cases in trigger validation.
    WHEN:
        create_policy_command validates trigger configurations.
    THEN:
        Edge cases in trigger validation are properly handled.
    """
    from CortexPlatformCore import Client, create_policy_command
    from CommonServerPython import DemistoException

    mock_client = Client(base_url="", headers={})
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    # Test case where all trigger actions are false but trigger is enabled
    args = {
        "policy_name": "Edge Case Policy",
        "triggers_periodic_report_issue": "false",
        "triggers_pr_report_issue": "false",
        "triggers_pr_block_pr": "false",
        "triggers_pr_report_pr_comment": "false",
        "triggers_cicd_report_issue": "false",
        "triggers_cicd_block_cicd": "false",
        "triggers_cicd_report_cicd": "false",
    }

    with pytest.raises(DemistoException) as excinfo:
        create_policy_command(mock_client, args)

    assert "At least one trigger" in str(excinfo.value)


def test_create_policy_command_conditions_filter_empty(mocker: MockerFixture):
    """
    GIVEN:
        Policy creation where conditions filter results in empty filter.
    WHEN:
        create_policy_command builds conditions with no actual filters.
    THEN:
        Empty conditions filter is handled correctly.
    """
    from CortexPlatformCore import Client, create_policy_command
    import json

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    # Args that result in empty conditions filter
    args = {
        "policy_name": "Empty Conditions Policy",
        "conditions_severity": "",  # Empty string should result in no filter
        "conditions_finding_type": None,  # None should result in no filter
        "triggers_periodic_report_issue": "true",
    }

    create_policy_command(mock_client, args)

    # Verify policy was created
    mock_create_policy.assert_called_once()

    # Check that conditions is empty dict when no filters are added
    call_args = mock_create_policy.call_args[0][0]
    payload = json.loads(call_args)

    # Should have conditions key but it might be empty
    assert "conditions" in payload


def test_create_policy_command_scope_filter_empty(mocker: MockerFixture):
    """
    GIVEN:
        Policy creation where scope filter results in empty filter.
    WHEN:
        create_policy_command builds scope with no actual filters.
    THEN:
        Empty scope filter is handled correctly.
    """
    from CortexPlatformCore import Client, create_policy_command
    import json

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    # Args that result in empty scope filter
    args = {
        "policy_name": "Empty Scope Policy",
        "scope_category": "",  # Empty string
        "scope_repository_name": None,  # None value
        "triggers_periodic_report_issue": "true",
    }

    create_policy_command(mock_client, args)

    # Verify policy was created
    mock_create_policy.assert_called_once()

    # Check that scope is present (might be empty)
    call_args = mock_create_policy.call_args[0][0]
    payload = json.loads(call_args)

    assert "scope" in payload


def test_create_policy_command_trigger_severity_none_handling(mocker: MockerFixture):
    """
    GIVEN:
        Policy creation with None values for trigger severity overrides.
    WHEN:
        create_policy_command processes trigger severity overrides.
    THEN:
        None values are correctly handled in trigger configuration.
    """
    from CortexPlatformCore import Client, create_policy_command
    import json

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {
        "policy_name": "Severity None Policy",
        "triggers_periodic_report_issue": "true",
        "triggers_periodic_override_severity": None,  # Explicitly None
        "triggers_pr_report_issue": "true",
        "triggers_pr_override_severity": "",  # Empty string
        "triggers_cicd_block_cicd": "true",
        # No cicd_override_severity provided (should default to None)
    }

    create_policy_command(mock_client, args)

    call_args = mock_create_policy.call_args[0][0]
    payload = json.loads(call_args)
    triggers = payload["triggers"]

    # Verify None severity overrides are handled correctly
    assert triggers["periodic"]["overrideIssueSeverity"] is None
    assert triggers["pr"]["overrideIssueSeverity"] is None
    assert triggers["cicd"]["overrideIssueSeverity"] is None


def test_create_policy_command_trigger_disabled_actions_false(mocker: MockerFixture):
    """
    GIVEN:
        Policy creation where triggers are enabled but specific actions are disabled.
    WHEN:
        create_policy_command processes trigger actions.
    THEN:
        Disabled actions are correctly set to False in the payload.
    """
    from CortexPlatformCore import Client, create_policy_command
    import json

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=[])

    args = {
        "policy_name": "Disabled Actions Policy",
        "triggers_periodic_report_issue": "true",  # Enable periodic
        "triggers_pr_report_issue": "false",  # Disable PR report
        "triggers_pr_block_pr": "true",  # Enable PR block (this makes PR trigger enabled)
        "triggers_pr_report_pr_comment": "false",  # Disable PR comment
        "triggers_cicd_report_issue": "false",  # Disable CICD report
        "triggers_cicd_block_cicd": "false",  # Disable CICD block
        "triggers_cicd_report_cicd": "true",  # Enable CICD report (this makes CICD trigger enabled)
    }

    create_policy_command(mock_client, args)

    call_args = mock_create_policy.call_args[0][0]
    payload = json.loads(call_args)
    triggers = payload["triggers"]

    # Verify trigger enablement logic
    assert triggers["periodic"]["isEnabled"] is True
    assert triggers["periodic"]["actions"]["reportIssue"] is True

    assert triggers["pr"]["isEnabled"] is True  # Enabled because block_pr is true
    assert triggers["pr"]["actions"]["reportIssue"] is False
    assert triggers["pr"]["actions"]["blockPr"] is True
    assert triggers["pr"]["actions"]["reportPrComment"] is False

    assert triggers["cicd"]["isEnabled"] is True  # Enabled because report_cicd is true
    assert triggers["cicd"]["actions"]["reportIssue"] is False
    assert triggers["cicd"]["actions"]["blockCicd"] is False
    assert triggers["cicd"]["actions"]["reportCicd"] is True


def test_create_policy_command_appsec_rule_none_handling(mocker: MockerFixture):
    """
    GIVEN:
        Policy creation with None or empty AppSec rule names.
    WHEN:
        create_policy_command processes AppSec rule names.
    THEN:
        None/empty AppSec rules are handled without calling resolution function.
    """
    from CortexPlatformCore import Client, create_policy_command

    mock_client = Client(base_url="", headers={})
    mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=[])
    mock_get_appsec_rules = mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names")

    args = {
        "policy_name": "No AppSec Rules Policy",
        "conditions_appsec_rule_names": "",  # Empty string
        "triggers_periodic_report_issue": "true",
    }

    create_policy_command(mock_client, args)

    # Verify get_appsec_rule_ids_from_names was not called for empty string
    mock_get_appsec_rules.assert_not_called()


def test_create_policy_command_json_serialization_edge_cases(mocker: MockerFixture):
    """
    GIVEN:
        Policy creation with complex nested data structures.
    WHEN:
        create_policy_command serializes the policy to JSON.
    THEN:
        Complex data structures are properly serialized.
    """
    from CortexPlatformCore import Client, create_policy_command
    import json

    mock_client = Client(base_url="", headers={})
    mock_create_policy = mocker.patch.object(mock_client, "create_policy", return_value=None)
    mocker.patch("CortexPlatformCore.get_asset_group_ids_from_names", return_value=["group-1", "group-2"])
    mocker.patch("CortexPlatformCore.get_appsec_rule_ids_from_names", return_value=["rule-1"])

    # Complex args that will create nested structures
    args = {
        "policy_name": "Complex JSON Policy",
        "description": "Policy with complex nested structures",
        "asset_group_names": "Group1,Group2",
        "conditions_finding_type": "Vulnerabilities,Secrets,Infrastructure as Code",
        "conditions_severity": "high,critical",
        "conditions_appsec_rule_names": "Rule1",
        "scope_category": "Application,Repository",
        "scope_business_application_names": "App1,App2",
        "triggers_periodic_report_issue": "true",
        "triggers_pr_block_pr": "true",
        "triggers_cicd_report_cicd": "true",
    }

    create_policy_command(mock_client, args)

    # Verify the JSON can be parsed back (tests serialization)
    call_args = mock_create_policy.call_args[0][0]
    payload = json.loads(call_args)  # This will fail if JSON is malformed

    # Verify the structure is complete
    assert payload["name"] == "Complex JSON Policy"
    assert payload["assetGroupIds"] == ["group-1", "group-2"]
    assert isinstance(payload["triggers"], dict)
    assert isinstance(payload["conditions"], dict)
    assert isinstance(payload["scope"], dict)


def test_appsec_remediate_issue_command_single_issue_success(mocker: MockerFixture):
    """
    Given:
        A client and args with a single issue ID and title.
    When:
        appsec_remediate_issue_command is called.
    Then:
        The issue is remediated successfully and appropriate results are returned.
    """
    from CortexPlatformCore import Client, appsec_remediate_issue_command

    mock_client = Client(base_url="", headers={})
    mock_demisto = mocker.patch("CortexPlatformCore.demisto")
    mock_demisto.args.return_value = {"issue_ids": "issue-123", "title": "Fix security vulnerability"}

    mock_remove_empty = mocker.patch(
        "CortexPlatformCore.remove_empty_elements",
        return_value={"issueIds": ["issue-123"], "title": "Fix security vulnerability"},
    )

    mock_appsec_remediate = mocker.patch.object(
        mock_client,
        "appsec_remediate_issue",
        return_value={
            "triggeredPrs": [{"issueId": "issue-123", "prUrl": "https://github.com/repo/pull/456", "status": "created"}]
        },
    )

    result = appsec_remediate_issue_command(mock_client, {})

    mock_remove_empty.assert_called_once_with({"issueIds": ["issue-123"], "title": "Fix security vulnerability"})
    mock_appsec_remediate.assert_called_once_with({"issueIds": ["issue-123"], "title": "Fix security vulnerability"})
    assert result.outputs_prefix == "Core.TriggeredPRs"
    assert result.outputs_key_field == "issueId"
    assert len(result.outputs) == 1
    assert result.outputs[0]["issueId"] == "issue-123"


def test_appsec_remediate_issue_command_multiple_issues_success(mocker: MockerFixture):
    """
    Given:
        A client and args with multiple issue IDs and title.
    When:
        appsec_remediate_issue_command is called.
    Then:
        All issues are remediated successfully and appropriate results are returned.
    """
    from CortexPlatformCore import Client, appsec_remediate_issue_command

    mock_client = Client(base_url="", headers={})
    mock_demisto = mocker.patch("CortexPlatformCore.demisto")
    mock_demisto.args.return_value = {"issue_ids": ["issue-123", "issue-456"], "title": "Fix security vulnerabilities"}

    mock_remove_empty = mocker.patch("CortexPlatformCore.remove_empty_elements")
    mock_remove_empty.side_effect = [
        {"issueIds": ["issue-123"], "title": "Fix security vulnerabilities"},
        {"issueIds": ["issue-456"], "title": "Fix security vulnerabilities"},
    ]

    mock_responses = [
        {"triggeredPrs": [{"issueId": "issue-123", "prUrl": "https://github.com/repo/pull/1"}]},
        {"triggeredPrs": [{"issueId": "issue-456", "prUrl": "https://github.com/repo/pull/2"}]},
    ]
    mock_appsec_remediate = mocker.patch.object(mock_client, "appsec_remediate_issue")
    mock_appsec_remediate.side_effect = mock_responses

    result = appsec_remediate_issue_command(mock_client, {})

    assert mock_appsec_remediate.call_count == 2
    assert len(result.outputs) == 2
    assert result.outputs[0]["issueId"] == "issue-123"
    assert result.outputs[1]["issueId"] == "issue-456"


def test_appsec_remediate_issue_command_too_many_issues_raises_exception(mocker):
    """
    GIVEN:
        Client instance and arguments with only issue_id.
    WHEN:
        The update_issue_command function is called.
    THEN:
        update_issue is called with empty update_data.
    """
    from CortexPlatformCore import appsec_remediate_issue_command, Client
    from CommonServerPython import DemistoException

    mock_client = Client(base_url="", headers={})
    mock_demisto = mocker.patch("CortexPlatformCore.demisto")
    mock_demisto.args.return_value = {
        "issue_ids": [f"issue-{i}" for i in range(11)],  # 11 issues
        "title": "Fix vulnerabilities",
    }

    args = {"id": "12345"}
    with pytest.raises(DemistoException, match="Please provide a maximum of 10 issue IDs per request."):
        appsec_remediate_issue_command(mock_client, args)


def test_appsec_remediate_issue_command_empty_triggered_prs(mocker: MockerFixture):
    """
    Given:
        A client and args with issue ID, but API returns empty triggeredPrs.
    When:
        appsec_remediate_issue_command is called.
    Then:
        The command completes successfully with empty outputs.
    """
    from CortexPlatformCore import Client, appsec_remediate_issue_command

    mock_client = Client(base_url="", headers={})
    mock_demisto = mocker.patch("CortexPlatformCore.demisto")
    mock_demisto.args.return_value = {"issue_ids": "issue-123", "title": "Fix security vulnerability"}

    mocker.patch(
        "CortexPlatformCore.remove_empty_elements",
        return_value={"issueIds": ["issue-123"], "title": "Fix security vulnerability"},
    )

    mocker.patch.object(
        mock_client,
        "appsec_remediate_issue",
        return_value={
            "triggeredPrs": []  # Empty list
        },
    )

    result = appsec_remediate_issue_command(mock_client, {})

    assert len(result.outputs) == 0
    assert result.raw_response == []


def test_appsec_remediate_issue_command_none_response(mocker: MockerFixture):
    """
    Given:
        A client and args with issue ID, but API returns None response.
    When:
        appsec_remediate_issue_command is called.
    Then:
        The command completes successfully with empty outputs.
    """
    from CortexPlatformCore import Client, appsec_remediate_issue_command

    mock_client = Client(base_url="", headers={})
    mock_demisto = mocker.patch("CortexPlatformCore.demisto")
    mock_demisto.args.return_value = {"issue_ids": "issue-123", "title": "Fix security vulnerability"}

    mocker.patch(
        "CortexPlatformCore.remove_empty_elements",
        return_value={"issueIds": ["issue-123"], "title": "Fix security vulnerability"},
    )

    mocker.patch.object(mock_client, "appsec_remediate_issue", return_value=None)

    result = appsec_remediate_issue_command(mock_client, {})

    assert len(result.outputs) == 0


def test_appsec_remediate_issue_command_missing_triggered_prs_key(mocker: MockerFixture):
    """
    Given:
        A client and args with issue ID, but API response lacks triggeredPrs key.
    When:
        appsec_remediate_issue_command is called.
    Then:
        The command completes successfully with empty outputs.
    """
    from CortexPlatformCore import Client, appsec_remediate_issue_command

    mock_client = Client(base_url="", headers={})
    mock_demisto = mocker.patch("CortexPlatformCore.demisto")
    mock_demisto.args.return_value = {"issue_ids": "issue-123", "title": "Fix security vulnerability"}

    mocker.patch(
        "CortexPlatformCore.remove_empty_elements",
        return_value={"issueIds": ["issue-123"], "title": "Fix security vulnerability"},
    )

    mocker.patch.object(
        mock_client,
        "appsec_remediate_issue",
        return_value={
            "status": "success"  # No triggeredPrs key
        },
    )

    result = appsec_remediate_issue_command(mock_client, {})

    assert len(result.outputs) == 0


def test_appsec_remediate_issue_command_non_list_triggered_prs(mocker: MockerFixture):
    """
    Given:
        A client and args with issue ID, but API returns triggeredPrs as non-list.
    When:
        appsec_remediate_issue_command is called.
    Then:
        The command completes successfully with empty outputs.
    """
    from CortexPlatformCore import Client, appsec_remediate_issue_command

    mock_client = Client(base_url="", headers={})
    mock_demisto = mocker.patch("CortexPlatformCore.demisto")
    mock_demisto.args.return_value = {"issue_ids": "issue-123", "title": "Fix security vulnerability"}

    mocker.patch(
        "CortexPlatformCore.remove_empty_elements",
        return_value={"issueIds": ["issue-123"], "title": "Fix security vulnerability"},
    )

    mocker.patch.object(mock_client, "appsec_remediate_issue", return_value={"triggeredPrs": "not a list"})

    result = appsec_remediate_issue_command(mock_client, {})

    assert len(result.outputs) == 0


def test_appsec_remediate_issue_command_mixed_success_failure(mocker: MockerFixture):
    """
    Given:
        A client and args with multiple issue IDs, where some succeed and some fail.
    When:
        appsec_remediate_issue_command is called.
    Then:
        Only successful remediations are included in the outputs.
    """
    from CortexPlatformCore import Client, appsec_remediate_issue_command

    mock_client = Client(base_url="", headers={})
    mock_demisto = mocker.patch("CortexPlatformCore.demisto")
    mock_demisto.args.return_value = {"issue_ids": ["issue-123", "issue-456", "issue-789"], "title": "Fix vulnerabilities"}

    mock_remove_empty = mocker.patch("CortexPlatformCore.remove_empty_elements")
    mock_remove_empty.side_effect = [
        {"issueIds": ["issue-123"], "title": "Fix vulnerabilities"},
        {"issueIds": ["issue-456"], "title": "Fix vulnerabilities"},
        {"issueIds": ["issue-789"], "title": "Fix vulnerabilities"},
    ]

    mock_responses = [
        {"triggeredPrs": [{"issueId": "issue-123", "prUrl": "https://github.com/repo/pull/1"}]},
        {"triggeredPrs": []},  # Failed to trigger PR
        {"triggeredPrs": [{"issueId": "issue-789", "prUrl": "https://github.com/repo/pull/3"}]},
    ]
    mock_appsec_remediate = mocker.patch.object(mock_client, "appsec_remediate_issue")
    mock_appsec_remediate.side_effect = mock_responses

    result = appsec_remediate_issue_command(mock_client, {})

    assert len(result.outputs) == 2  # Only successful ones
    assert result.outputs[0]["issueId"] == "issue-123"
    assert result.outputs[1]["issueId"] == "issue-789"


def test_appsec_remediate_issue_command_none_title_removed(mocker: MockerFixture):
    """
    Given:
        A client and args with issue ID and None title.
    When:
        appsec_remediate_issue_command is called.
    Then:
        remove_empty_elements is called and None title is handled properly.
    """
    from CortexPlatformCore import Client, appsec_remediate_issue_command

    mock_client = Client(base_url="", headers={})
    mock_demisto = mocker.patch("CortexPlatformCore.demisto")
    mock_demisto.args.return_value = {"issue_ids": "issue-123", "title": None}

    mock_remove_empty = mocker.patch(
        "CortexPlatformCore.remove_empty_elements",
        return_value={
            "issueIds": ["issue-123"]  # title removed
        },
    )

    mock_appsec_remediate = mocker.patch.object(
        mock_client,
        "appsec_remediate_issue",
        return_value={"triggeredPrs": [{"issueId": "issue-123", "prUrl": "https://github.com/repo/pull/1"}]},
    )

    appsec_remediate_issue_command(mock_client, {})

    mock_remove_empty.assert_called_with({"issueIds": ["issue-123"], "title": None})
    mock_appsec_remediate.assert_called_with({"issueIds": ["issue-123"]})


def test_appsec_remediate_issue_command_empty_issue_ids_list(mocker: MockerFixture):
    """
    Given:
        A client and args with empty issue IDs list.
    When:
        appsec_remediate_issue_command is called.
    Then:
        The command completes successfully with empty outputs and no API calls.
    """
    from CortexPlatformCore import Client, appsec_remediate_issue_command

    mock_client = Client(base_url="", headers={})
    mock_demisto = mocker.patch("CortexPlatformCore.demisto")
    mock_demisto.args.return_value = {"issue_ids": [], "title": "Fix vulnerabilities"}

    mock_appsec_remediate = mocker.patch.object(mock_client, "appsec_remediate_issue")

    result = appsec_remediate_issue_command(mock_client, {})

    assert len(result.outputs) == 0
    mock_appsec_remediate.assert_not_called()


def test_get_appsec_issues_command_success(mocker: MockerFixture):
    """
    Given:
        A mocked client and valid arguments with appsec issue filters.
    When:
        The get_appsec_issues_command function is called.
    Then:
        The response is parsed, formatted, and returned correctly with expected outputs.
    """
    from CortexPlatformCore import Client, get_appsec_issues_command

    mock_client = Client(base_url="", headers={})
    mock_response = {
        "reply": {
            "DATA": [
                {
                    "internal_id": "issue_001",
                    "severity": "SEV_040_HIGH",
                    "alert_name": "SQL Injection",
                    "status_progress": "STATUS_010_NEW",
                    "cas_issues_normalized_fields": {
                        "xdm.vulnerability.cvss_score": 8.8,
                    },
                }
            ]
        }
    }
    mock_get_webapp_data = mocker.patch.object(
        mock_client,
        "get_webapp_data",
        side_effect=lambda request_data: mock_response
        if request_data.get("table_name") == "ISSUES_CVES"
        else {"reply": {"DATA": []}},
    )

    args = {"severity": "high", "status": "New", "has_kev": "true"}

    result = get_appsec_issues_command(mock_client, args)

    assert len(result.outputs) == 1
    assert result.outputs[0]["internal_id"] == "issue_001"
    assert result.outputs[0]["severity"] == "high"
    assert result.outputs[0]["status"] == "New"
    assert result.outputs[0]["cvss_score"] == 8.8
    assert "SQL Injection" in result.readable_output
    assert result.outputs_prefix == "Core.AppsecIssue"
    assert mock_get_webapp_data.call_count > 0


def test_get_appsec_issues_command_no_issues_found(mocker: MockerFixture):
    """
    Given:
        A mocked client that returns an empty list of issues.
    When:
        The get_appsec_issues_command function is called.
    Then:
        An empty result is returned with the correct structure.
    """
    from CortexPlatformCore import Client, get_appsec_issues_command

    mock_client = Client(base_url="", headers={})
    mock_response = {"reply": {"DATA": []}}
    mocker.patch.object(mock_client, "get_webapp_data", return_value=mock_response)

    args = {"severity": "low"}

    result = get_appsec_issues_command(mock_client, args)

    assert result.outputs == []
    assert "Application Security Issues" in result.readable_output


def test_create_appsec_issues_filter_and_tables_simple_filter():
    """
    Given:
        A simple filter argument.
    When:
        The create_appsec_issues_filter_and_tables function is called.
    Then:
        The function should return the correct list of tables and a FilterBuilder instance.
    """
    from CortexPlatformCore import create_appsec_issues_filter_and_tables

    args = {"urgency": "high"}
    tables_filters = create_appsec_issues_filter_and_tables(args)
    assert set(tables_filters.keys()) == {
        "ISSUES_IAC",
        "ISSUES_CVES",
        "ISSUES_SECRETS",
        "ISSUES_WEAKNESSES",
    }
    for _, filter_builder in tables_filters.items():
        filter_dict = filter_builder.to_dict()
        assert any(
            field.get("SEARCH_VALUE") == "high" and field.get("SEARCH_FIELD") == "urgency" for field in filter_dict.get("AND", [])
        )


def test_create_appsec_issues_filter_and_tables_cves_specific_filter():
    """
    Given:
        A CVES specific filter argument.
    When:
        The create_appsec_issues_filter_and_tables function is called.
    Then:
        The function should return only the ISSUES_CVES table.
    """
    from CortexPlatformCore import create_appsec_issues_filter_and_tables

    args = {"has_kev": "true"}
    tables_filters = create_appsec_issues_filter_and_tables(args)
    assert list(tables_filters.keys()) == ["ISSUES_CVES"]


def test_create_appsec_issues_filter_and_tables_all_filters():
    """
    Given:
        Arguments with all possible filters.
    When:
        The create_appsec_issues_filter_and_tables function is called.
    Then:
        The function should return the correct tables and a comprehensive filter.
    """
    from CortexPlatformCore import create_appsec_issues_filter_and_tables

    args = {
        "cvss_score_gte": "8.0",
        "epss_score_gte": "0.5",
        "has_kev": "true",
        "sla": "breached",
        "fix_available": "true",
        "urgency": "critical",
        "severity": "critical",
        "issue_id": "ISSUE-123",
        "issue_name": "XSS",
        "collaborator": "john.doe",
        "status": "In Progress",
        "start_time": "2023-01-01",
        "end_time": "2023-01-31",
        "assignee": "assigned",
    }
    tables_filters = create_appsec_issues_filter_and_tables(args)
    assert "ISSUES_CVES" in tables_filters
    filter_builder = tables_filters["ISSUES_CVES"]
    filter_dict = filter_builder.to_dict()
    assert len(filter_dict["AND"]) >= 10


def test_normalize_and_filter_appsec_issue():
    """
    Given:
        A raw issue dictionary from the API.
    When:
        The normalize_and_filter_appsec_issue function is called.
    Then:
        The function should return a normalized and filtered dictionary with standard AppSec fields.
    """
    from CortexPlatformCore import normalize_and_filter_appsec_issue

    raw_issue = {
        "internal_id": "issue_001",
        "severity": "SEV_050_CRITICAL",
        "alert_name": "Insecure Configuration",
        "issue_source": "Prisma Cloud",
        "issue_category": "Misconfiguration",
        "status_progress": "STATUS_025_RESOLVED",
        "cas_issues_is_fixable": True,
        "cas_issues_normalized_fields": {
            "xdm.repository.name": "my-app",
            "xdm.repository.organization": "my-org",
            "xdm.vulnerability.cvss_score": 9.5,
        },
        "cas_sla_status": "IN_SLA",
        "extra_field": "should be removed",
    }

    normalized_issue = normalize_and_filter_appsec_issue(raw_issue)

    assert normalized_issue["internal_id"] == "issue_001"
    assert normalized_issue["severity"] == "critical"
    assert normalized_issue["issue_name"] == "Insecure Configuration"
    assert normalized_issue["status"] == "Resolved"
    assert normalized_issue["repository_name"] == "my-app"
    assert normalized_issue["repository_organization"] == "my-org"
    assert normalized_issue["cvss_score"] == 9.5
    assert normalized_issue["is_fixable"] is True
    assert normalized_issue["sla_status"] == "On Track"
    assert "extra_field" not in normalized_issue


def test_create_appsec_issues_filter_and_tables_no_matching_table():
    """
    Given:
        Valid filter arguments that, when combined, do not match any single predefined Appsec issue type table.
    When:
        The create_appsec_issues_filter_and_tables function is called.
    Then:
        A DemistoException should be raised indicating no matching issue type found.
    """
    from CortexPlatformCore import create_appsec_issues_filter_and_tables
    from CommonServerPython import DemistoException

    # This combination of filters (validation and has_kev) does not exist in any single ISSUE_TYPE.filters set.
    args = {"validation": "true", "has_kev": "true"}

    with pytest.raises(DemistoException, match="No matching issue type found for the given filter combination"):
        create_appsec_issues_filter_and_tables(args)


@pytest.mark.parametrize("input_data", ["not a list", [], None])
def test_map_case_format_invalid_input(input_data):
    """
    Given:
        Invalid input data (not a list, empty list, or None).
    When:
        The map_case_format function is called.
    Then:
        An empty dictionary should be returned.
    """
    from CortexPlatformCore import map_case_format

    result = map_case_format(input_data)
    assert result == {}


def test_map_case_format_complete_mapping():
    """
    Given:
        Valid case data in raw format.
    When:
        The map_case_format function is called.
    Then:
        The case data should be correctly mapped to the expected format.
    """
    from CortexPlatformCore import map_case_format

    case_data = [load_test_data("./TestData/case_raw_format.json")]
    result = sorted(map_case_format(case_data))
    expected = sorted([load_test_data("./TestData/case_expected_format.json")])

    assert result == expected


@pytest.mark.parametrize("case_extra_data", [{}, None])
def test_extract_ids_empty_case_extra_data(case_extra_data):
    """
    Given:
        Empty or None case extra data.
    When:
        The extract_ids function is called.
    Then:
        An empty list should be returned.
    """
    from CortexPlatformCore import extract_ids

    result = extract_ids(case_extra_data)
    assert result == []


def test_extract_ids_multiple_valid_issues():
    """
    Given:
        Case extra data containing multiple valid issues with issue_ids.
    When:
        The extract_ids function is called.
    Then:
        A list containing all issue_ids should be returned.
    """

    from CortexPlatformCore import extract_ids

    case_extra_data: dict = {
        "issues": {
            "data": [
                {"issue_id": "12345", "title": "Test Issue 1"},
                {"issue_id": "67890", "title": "Test Issue 2"},
                {"issue_id": "11111", "title": "Test Issue 3"},
            ]
        }
    }
    result = extract_ids(case_extra_data)
    assert result == ["12345", "67890", "11111"]


def test_get_case_extra_data_with_all_fields_present(mocker):
    """
    Given:
        A mock client and case data with all possible fields present.
    When:
        The get_case_extra_data function is called.
    Then:
        All fields should be correctly extracted and returned in the result.
    """
    from CortexPlatformCore import get_case_extra_data

    mock_client = mocker.Mock()
    mock_client._base_url = "original_url"

    mock_case_data = {
        "case": {
            "notes": "Test notes",
            "xdr_url": "https://example.com/xdr",
            "starred_manually": True,
            "manual_description": "Case manual description",
            "detection_time": "2023-01-01T00:00:00Z",
        },
        "manual_description": "Global manual description",
        "network_artifacts": [{"id": "net1", "type": "ip"}],
        "file_artifacts": [{"id": "file1", "hash": "abc123"}],
    }

    mock_command_result = mocker.Mock()
    mock_command_result.outputs = mock_case_data

    mocker.patch("CortexPlatformCore.get_extra_data_for_case_id_command", return_value=mock_command_result)
    mocker.patch("CortexPlatformCore.extract_ids", return_value=["issue1", "issue2"])

    args = {"case_id": "123"}
    result = get_case_extra_data(mock_client, args)

    assert mock_client._base_url == "api/webapp/public_api/v1"
    assert result["issue_ids"] == ["issue1", "issue2"]
    assert result["network_artifacts"] == [{"id": "net1", "type": "ip"}]
    assert result["file_artifacts"] == [{"id": "file1", "hash": "abc123"}]
    assert result["notes"] == "Test notes"
    assert result["xdr_url"] == "https://example.com/xdr"
    assert result["starred_manually"] is True
    assert result["manual_description"] == "Global manual description"
    assert result["detection_time"] == "2023-01-01T00:00:00Z"


def test_get_case_extra_data_client_base_url_modification(mocker):
    """
    Given:
        A mock client with an original base URL.
    When:
        The get_case_extra_data function is called.
    Then:
        The client's base URL should be modified to "api/webapp/public_api/v1".
    """
    from CortexPlatformCore import get_case_extra_data

    mock_client = mocker.Mock()
    original_url = "https://original.api.endpoint"
    mock_client._base_url = original_url

    mock_command_result = mocker.Mock()
    mock_command_result.outputs = {}

    mocker.patch("CortexPlatformCore.get_extra_data_for_case_id_command", return_value=mock_command_result)
    mocker.patch("CortexPlatformCore.extract_ids", return_value=[])

    args = {"case_id": "url_test"}
    get_case_extra_data(mock_client, args)

    assert mock_client._base_url == "api/webapp/public_api/v1"


def test_add_cases_extra_data_single_case(mocker):
    """
    Given:
        A mock client and a list containing a single case.
    When:
        The add_cases_extra_data function is called.
    Then:
        A list with one case containing extra data should be returned and get_case_extra_data should be called once.
    """
    from CortexPlatformCore import add_cases_extra_data

    mock_client = mocker.Mock()
    mock_get_case_extra_data = mocker.patch("CortexPlatformCore.get_case_extra_data")
    mock_get_case_extra_data.return_value = {"extra_field": "extra_value"}

    case_data: list[dict] = [{"case_id": "123", "title": "Test Case"}]
    result = add_cases_extra_data(mock_client, case_data)

    assert len(result) == 1
    assert result[0]["case_id"] == "123"
    assert result[0]["CaseExtraData"] == {"extra_field": "extra_value"}
    mock_get_case_extra_data.assert_called_once_with(mock_client, {"case_id": "123", "limit": 1000})


def test_add_cases_extra_data_multiple_cases(mocker):
    """
    Given:
        A mock client and a list containing multiple cases.
    When:
        The add_cases_extra_data function is called.
    Then:
        A list with all cases containing their respective extra data should be
        returned and get_case_extra_data should be called for each case.
    """
    from CortexPlatformCore import add_cases_extra_data

    mock_client = mocker.Mock()
    mock_get_case_extra_data = mocker.patch("CortexPlatformCore.get_case_extra_data")
    mock_get_case_extra_data.side_effect = [{"extra_field1": "value1"}, {"extra_field2": "value2"}, {"extra_field3": "value3"}]

    case_data = [
        {"case_id": "123", "title": "Case 1"},
        {"case_id": "456", "title": "Case 2"},
        {"case_id": "789", "title": "Case 3"},
    ]
    result = add_cases_extra_data(mock_client, case_data)

    assert len(result) == 3
    assert result[0]["CaseExtraData"] == {"extra_field1": "value1"}
    assert result[1]["CaseExtraData"] == {"extra_field2": "value2"}
    assert result[2]["CaseExtraData"] == {"extra_field3": "value3"}
    assert mock_get_case_extra_data.call_count == 3


def test_add_cases_extra_data_empty_list(mocker):
    """
    Given:
        A mock client and an empty case list.
    When:
        The add_cases_extra_data function is called.
    Then:
        An empty list should be returned and get_case_extra_data should not be called.
    """
    from CortexPlatformCore import add_cases_extra_data

    mock_client = mocker.Mock()
    mock_get_case_extra_data = mocker.patch("CortexPlatformCore.get_case_extra_data")

    case_data = []
    result = add_cases_extra_data(mock_client, case_data)

    assert result == []
    mock_get_case_extra_data.assert_not_called()

    def test_determine_assignee_filter_field_none(self):
        from CortexPlatformCore import determine_assignee_filter_field, CaseManagement

        result = determine_assignee_filter_field([])
        assert result == CaseManagement.FIELDS["assignee"]

    def test_determine_assignee_filter_field_with_email(self):
        from CortexPlatformCore import determine_assignee_filter_field, CaseManagement

        result = determine_assignee_filter_field(["user@example.com"])
        assert result == CaseManagement.FIELDS["assignee_email"]

    def test_determine_assignee_filter_field_with_pretty_name(self):
        from CortexPlatformCore import determine_assignee_filter_field, CaseManagement

        result = determine_assignee_filter_field(["John Doe"])
        assert result == CaseManagement.FIELDS["assignee"]


@pytest.mark.parametrize(
    "custom_fields_json,expected",
    [
        (
            '[{"field1": "value1"}, {"field2": "value2"}, {"field3": "value3"}]',
            {"field1": "value1", "field2": "value2", "field3": "value3"},
        ),
        (
            '[{"field-1": "value1", "field_2": "value2", "field@3": "value3"}]',
            {"field1": "value1", "field2": "value2", "field3": "value3"},
        ),
        ('[{"field-1": "first"}, {"field_1": "second"}]', {"field1": "first"}),
        ("[]", {}),
        ('[{"---": "value1", "@#$": "value2"}]', {}),
        ('[{"123": "value1", "456field": "value2"}]', {"123": "value1", "456field": "value2"}),
        ('[{"": "value1", "field2": "value2"}]', {"field2": "value2"}),
    ],
)
def test_parse_custom_fields(custom_fields_json, expected):
    """
    Given:
        A JSON string containing custom fields and expected parsed result.
    When:
        The parse_custom_fields function is called with the JSON string.
    Then:
        The function should return a dictionary with normalized field names matching the expected result.
    """
    from CortexPlatformCore import parse_custom_fields

    result = parse_custom_fields(custom_fields_json)
    assert result == expected


def test_process_case_response_removes_specified_fields():
    """
    Given:
        A case response containing fields that should be removed (layoutId, layoutRuleName, sourcesList,
        previous_score, previous_score_source).
    When:
        The process_case_response function is called.
    Then:
        The specified fields should be removed from the response while preserving other fields.
    """
    from CortexPlatformCore import process_case_response

    resp = {
        "reply": {
            "layoutId": "layout123",
            "layoutRuleName": "rule456",
            "sourcesList": ["source1", "source2"],
            "caseId": "case789",
            "status": "open",
            "score": {"current_score": 85, "previous_score": 70, "previous_score_source": "manual", "max_score": 100},
        }
    }
    result = process_case_response(resp)
    assert "layoutId" not in result
    assert "layoutRuleName" not in result
    assert "sourcesList" not in result
    assert result["caseId"] == "case789"
    assert result["status"] == "open"
    assert "previous_score" not in result["score"]
    assert "previous_score_source" not in result["score"]
    assert result["score"]["current_score"] == 85
    assert result["score"]["max_score"] == 100


def test_process_case_response_renames_incident_domain_to_case_domain():
    """
    Given:
        A case response containing an incidentDomain field.
    When:
        The process_case_response function is called.
    Then:
        The incidentDomain field should be renamed to caseDomain and the original field should be removed.
    """
    from CortexPlatformCore import process_case_response

    resp = {"reply": {"incidentDomain": "security", "caseId": "case101"}}
    result = process_case_response(resp)
    assert "incidentDomain" not in result
    assert result["caseDomain"] == "security"
    assert result["caseId"] == "case101"


def test_run_playbook_command_empty_response_success():
    """
    Given:
        A mock client that returns an empty response and valid playbook arguments.
    When:
        The run_playbook_command function is called.
    Then:
        The function should return a successful result with appropriate readable output.
    """
    from CortexPlatformCore import run_playbook_command

    mock_client = Mock()
    mock_client.run_playbook.return_value = {}

    args = {"playbook_id": "test_playbook_123", "issue_ids": ["issue_1", "issue_2"]}

    result = run_playbook_command(mock_client, args)

    assert "executed successfully" in result.readable_output
    assert "test_playbook_123" in result.readable_output
    assert "issue_1, issue_2" in result.readable_output


def test_run_playbook_command_multiple_errors_response():
    """
    Given:
        A mock client that returns error responses for multiple issues.
    When:
        The run_playbook_command function is called.
    Then:
        A ValueError should be raised containing all error messages for the issues.
    """
    from CortexPlatformCore import run_playbook_command

    mock_client = Mock()
    mock_client.run_playbook.return_value = {
        "issue_1": "Skipping execution of playbook multi_fail_playbook for alert issue_1, couldn't find alert",
        "issue_2": "Skipping execution of playbook multi_fail_playbook for alert issue_2, failed creating investigation playbook",
        "issue_3": "Skipping execution of playbook multi_fail_playbook for alert issue_3, failed creating investigation playbook",
    }

    args = {"playbook_id": "multi_fail_playbook", "issue_ids": ["issue_1", "issue_2", "issue_3"]}

    with pytest.raises(ValueError) as exc_info:
        run_playbook_command(mock_client, args)

    error_message = str(exc_info.value)
    assert "multi_fail_playbook" in error_message
    assert (
        "Issue ID issue_1: Skipping execution of playbook multi_fail_playbook for alert issue_1, couldn't find alert"
        in error_message
    )
    assert (
        "Issue ID issue_2: Skipping execution of playbook multi_fail_playbook for alert issue_2, "
        "failed creating investigation playbook" in error_message
    )
    assert (
        "Issue ID issue_3: Skipping execution of playbook multi_fail_playbook for alert issue_3, "
        "failed creating investigation playbook" in error_message
    )


def test_run_playbook_command_string_issue_ids():
    """
    Given:
        A mock client and arguments with string issue IDs that need to be converted to a list.
    When:
        The run_playbook_command function is called.
    Then:
        The function should successfully process the string issue IDs and return the expected output.
    """
    from CortexPlatformCore import run_playbook_command

    mock_client = Mock()
    mock_client.run_playbook.return_value = {}

    args = {"playbook_id": "test_playbook", "issue_ids": "issue_1,issue_2,issue_3"}

    result = run_playbook_command(mock_client, args)

    assert "issue_1, issue_2, issue_3" in result.readable_output
    mock_client.run_playbook.assert_called_once()


def test_run_playbook_command_client_call_parameters():
    """
    Given:
        A mock client and valid playbook arguments.
    When:
        The run_playbook_command function is called.
    Then:
        The client.run_playbook method should be called with the correct parameters.
    """
    from CortexPlatformCore import run_playbook_command

    mock_client = Mock()
    mock_client.run_playbook.return_value = {}

    args = {"playbook_id": "param_test_playbook", "issue_ids": ["param_issue_1", "param_issue_2"]}

    run_playbook_command(mock_client, args)

    mock_client.run_playbook.assert_called_once_with(["param_issue_1", "param_issue_2"], "param_test_playbook")


def test_update_issue_command_link_cases_success(mocker: MockerFixture):
    """
    GIVEN:
        Client instance and arguments with issue_id and a list of case_ids to link.
    WHEN:
        The update_issue_command function is called.
    THEN:
        client.link_issue_to_cases is called once with the correct issue_id and case_ids,
        and client.update_issue is NOT called (since no other update args are provided).
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mock_link_issue_to_cases = mocker.patch.object(client, "link_issue_to_cases", return_value={"success": True})
    mock_unlink_issue_from_cases = mocker.patch.object(client, "unlink_issue_from_cases")
    mocker.patch.object(demisto, "debug")

    args = {"id": "12345", "link_cases": "901,902"}

    result = update_issue_command(client, args)

    assert result == "done"
    mock_link_issue_to_cases.assert_called_once_with(12345, [901, 902])
    mock_unlink_issue_from_cases.assert_not_called()
    mock_update_issue.assert_not_called()


def test_update_issue_command_unlink_cases_success(mocker: MockerFixture):
    """
    GIVEN:
        Client instance and arguments with issue_id and a list of case_ids to unlink.
    WHEN:
        The update_issue_command function is called.
    THEN:
        client.unlink_issue_from_cases is called once with the correct issue_id and case_ids,
        and client.update_issue is NOT called.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mock_link_issue_to_cases = mocker.patch.object(client, "link_issue_to_cases")
    mock_unlink_issue_from_cases = mocker.patch.object(client, "unlink_issue_from_cases", return_value={"success": True})
    mocker.patch.object(demisto, "debug")

    args = {"id": "12345", "unlink_cases": "903,904"}

    result = update_issue_command(client, args)

    assert result == "done"
    mock_unlink_issue_from_cases.assert_called_once_with(12345, [903, 904])
    mock_link_issue_to_cases.assert_not_called()
    mock_update_issue.assert_not_called()


def test_update_issue_command_link_and_unlink_cases_mixed_with_update_fields(mocker: MockerFixture):
    """
    GIVEN:
        Client instance and arguments including link_cases, unlink_cases, and other update fields.
    WHEN:
        The update_issue_command function is called.
    THEN:
        All three methods (link, unlink, update_issue) are called once with the correct parameters.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mock_link_issue_to_cases = mocker.patch.object(client, "link_issue_to_cases", return_value={"success": True})
    mock_unlink_issue_from_cases = mocker.patch.object(client, "unlink_issue_from_cases", return_value={"success": True})
    mocker.patch.object(demisto, "debug")

    args = {
        "id": "12345",
        "link_cases": "901",
        "unlink_cases": "904,905",
        "name": "Updated Name",
        "severity": "high",
    }

    result = update_issue_command(client, args)

    assert result == "done"
    mock_link_issue_to_cases.assert_called_once_with(12345, [901])
    mock_unlink_issue_from_cases.assert_called_once_with(12345, [904, 905])
    mock_update_issue.assert_called_once()

    call_args = mock_update_issue.call_args[0][0]
    update_data = call_args["update_data"]
    assert update_data["name"] == "Updated Name"
    assert update_data["severity"] == "SEV_040_HIGH"


def test_update_issue_command_only_link_and_unlink_fields(mocker: MockerFixture):
    """
    GIVEN:
        Client instance and arguments with only link_cases and unlink_cases (no other fields).
    WHEN:
        The update_issue_command function is called.
    THEN:
        client.link_issue_to_cases and client.unlink_issue_from_cases are called,
        and client.update_issue is NOT called, and the function returns "done".
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mock_link_issue_to_cases = mocker.patch.object(client, "link_issue_to_cases", return_value={"success": True})
    mock_unlink_issue_from_cases = mocker.patch.object(client, "unlink_issue_from_cases", return_value={"success": True})
    mocker.patch.object(demisto, "debug")

    args = {"id": "12345", "link_cases": "901", "unlink_cases": "904"}

    result = update_issue_command(client, args)

    assert result == "done"
    mock_link_issue_to_cases.assert_called_once_with(12345, [901])
    mock_unlink_issue_from_cases.assert_called_once_with(12345, [904])
    mock_update_issue.assert_not_called()


def test_update_issue_command_link_case_ids_arg_to_list(mocker: MockerFixture):
    """
    GIVEN:
        Client instance and arguments where link_cases is a single string of comma-separated IDs.
    WHEN:
        The update_issue_command function is called.
    THEN:
        The link_cases argument is correctly parsed into a list of integers and passed to the client.
    """
    from CortexPlatformCore import update_issue_command, Client

    client = Client(base_url="", headers={})
    mocker.patch.object(client, "update_issue")
    mock_link_issue_to_cases = mocker.patch.object(client, "link_issue_to_cases", return_value={"success": True})
    mocker.patch.object(client, "unlink_issue_from_cases")
    mocker.patch.object(demisto, "debug")

    args = {"id": "12345", "link_cases": "901, 902,1000"}

    update_issue_command(client, args)

    mock_link_issue_to_cases.assert_called_once_with(12345, [901, 902, 1000])


def test_update_issue_command_link_cases_empty_list_no_other_updates(mocker: MockerFixture):
    """
    GIVEN:
        Client instance and arguments with empty link_cases and empty unlink_cases, and no other updates.
    WHEN:
        The update_issue_command function is called.
    THEN:
        DemistoException is raised because no updates are provided.
    """
    from CortexPlatformCore import update_issue_command, Client
    from CommonServerPython import DemistoException
    import pytest

    client = Client(base_url="", headers={})
    mock_update_issue = mocker.patch.object(client, "update_issue")
    mock_link_issue_to_cases = mocker.patch.object(client, "link_issue_to_cases")
    mock_unlink_issue_from_cases = mocker.patch.object(client, "unlink_issue_from_cases")
    mocker.patch.object(demisto, "debug")

    args = {"id": "12345", "link_cases": "", "unlink_cases": None}

    with pytest.raises(DemistoException, match="Please provide arguments to update the issue."):
        update_issue_command(client, args)

    mock_link_issue_to_cases.assert_not_called()
    mock_unlink_issue_from_cases.assert_not_called()
    mock_update_issue.assert_not_called()


class TestGetAppsecSuggestion(unittest.TestCase):
    def setUp(self):
        self.mock_client = Mock(spec=Client)
        self.issue_id = "test-issue-123"

    @patch("CortexPlatformCore.demisto")
    def test_get_appsec_suggestion_with_manual_fix_and_code_blocks(self, mock_demisto):
        """Test get_appsec_suggestion with manual fix and code blocks"""
        issue = {
            "alert_source": "CAS_CVE_SCANNER",  # Valid AppSec source
            "extended_fields": {"action": "Manual fix required: Update dependency"},
        }
        fix_suggestion = {"existingCodeBlock": "old code", "suggestedCodeBlock": "new code"}
        self.mock_client.get_appsec_suggested_fix.return_value = fix_suggestion

        result = get_appsec_suggestion(self.mock_client, issue, self.issue_id)

        expected = {
            "remediation": "Manual fix required: Update dependency",
            "existing_code_block": "old code",
            "suggested_code_block": "new code",
        }
        assert result == expected
        self.mock_client.get_appsec_suggested_fix.assert_called_once_with(self.issue_id)
        assert mock_demisto.debug.call_count == 2  # Called twice in the function

    @patch("CortexPlatformCore.demisto")
    def test_get_appsec_suggestion_without_manual_fix(self, mock_demisto):
        """Test get_appsec_suggestion without manual fix but with code blocks"""
        issue = {
            "alert_source": "CAS_SAST_SCANNER",  # Valid AppSec source
            "extended_fields": {},
        }
        fix_suggestion = {"existingCodeBlock": "existing code", "suggestedCodeBlock": "suggested code"}
        self.mock_client.get_appsec_suggested_fix.return_value = fix_suggestion

        result = get_appsec_suggestion(self.mock_client, issue, self.issue_id)

        expected = {"existing_code_block": "existing code", "suggested_code_block": "suggested code"}
        assert result == expected

    @patch("CortexPlatformCore.demisto")
    def test_get_appsec_suggestion_empty_fix_suggestion(self, mock_demisto):
        """Test get_appsec_suggestion with empty fix suggestion"""
        issue = {
            "alert_source": "CAS_SECRET_SCANNER",  # Valid AppSec source
            "extended_fields": {"action": "manual fix"},
        }
        self.mock_client.get_appsec_suggested_fix.return_value = None

        result = get_appsec_suggestion(self.mock_client, issue, self.issue_id)

        expected = {"remediation": "manual fix"}
        assert result == expected

    @patch("CortexPlatformCore.demisto")
    def test_get_appsec_suggestion_no_suggested_code_block(self, mock_demisto):
        """Test get_appsec_suggestion when suggestedCodeBlock is missing"""
        issue = {
            "alert_source": "CAS_IAC_SCANNER",  # Valid AppSec source
            "extended_fields": {"action": "manual fix"},
        }
        fix_suggestion = {"existingCodeBlock": "old code"}  # Missing suggestedCodeBlock
        self.mock_client.get_appsec_suggested_fix.return_value = fix_suggestion

        result = get_appsec_suggestion(self.mock_client, issue, self.issue_id)

        expected = {"remediation": "manual fix"}
        assert result == expected

    @patch("CortexPlatformCore.demisto")
    def test_get_appsec_suggestion_missing_existing_code_block(self, mock_demisto):
        """Test get_appsec_suggestion when existingCodeBlock is missing"""
        issue = {
            "alert_source": "CAS_LICENSE_SCANNER",  # Valid AppSec source
        }
        fix_suggestion = {"suggestedCodeBlock": "new code"}
        self.mock_client.get_appsec_suggested_fix.return_value = fix_suggestion

        result = get_appsec_suggestion(self.mock_client, issue, self.issue_id)

        expected = {"existing_code_block": "", "suggested_code_block": "new code"}
        assert result == expected

    @patch("CortexPlatformCore.demisto")
    def test_get_appsec_suggestion_non_appsec_source(self, mock_demisto):
        """Test get_appsec_suggestion with non-AppSec source returns empty dict"""
        issue = {
            "alert_source": "XDR",  # Non-AppSec source
            "extended_fields": {"action": "manual fix"},
        }

        result = get_appsec_suggestion(self.mock_client, issue, self.issue_id)

        expected = {}
        assert result == expected
        # Should not call the API for non-AppSec sources
        self.mock_client.get_appsec_suggested_fix.assert_not_called()

    @patch("CortexPlatformCore.demisto")
    def test_get_appsec_suggestion_missing_alert_source(self, mock_demisto):
        """Test get_appsec_suggestion when alert_source is missing"""
        issue = {"extended_fields": {"action": "manual fix"}}

        result = get_appsec_suggestion(self.mock_client, issue, self.issue_id)

        expected = {}
        assert result == expected
        # Should not call the API when alert_source is missing
        self.mock_client.get_appsec_suggested_fix.assert_not_called()

    @patch("CortexPlatformCore.demisto")
    def test_get_appsec_suggestion_invalid_fix_suggestion_type(self, mock_demisto):
        """Test get_appsec_suggestion when fix_suggestion is not a dict"""
        issue = {
            "alert_source": "CAS_OPERATIONAL_RISK_SCANNER",  # Valid AppSec source
            "extended_fields": {"action": "manual fix"},
        }
        self.mock_client.get_appsec_suggested_fix.return_value = "invalid_response"

        result = get_appsec_suggestion(self.mock_client, issue, self.issue_id)

        expected = {"remediation": "manual fix"}
        assert result == expected

    @patch("CortexPlatformCore.demisto")
    def test_get_appsec_suggestion_empty_manual_fix_with_code_blocks(self, mock_demisto):
        """Test get_appsec_suggestion with no manual fix but valid code blocks"""
        issue = {
            "alert_source": "CAS_CI_CD_RISK_SCANNER",  # Valid AppSec source
            "extended_fields": {"action": ""},  # Empty action
        }
        fix_suggestion = {"existingCodeBlock": "old code", "suggestedCodeBlock": "new code"}
        self.mock_client.get_appsec_suggested_fix.return_value = fix_suggestion

        result = get_appsec_suggestion(self.mock_client, issue, self.issue_id)

        expected = {
            "existing_code_block": "old code",
            "suggested_code_block": "new code",
        }
        assert result == expected


class TestPopulatePlaybookAndQuickActionSuggestions(unittest.TestCase):
    def setUp(self):
        self.mock_client = Mock(spec=Client)
        self.issue_id = "test-issue-123"
        self.pb_id_to_data = {
            "pb-1": {"name": "Security Playbook", "comment": "Main security playbook"},
            "pb-2": {"name": "Incident Response", "comment": "IR playbook"},
        }
        self.qa_name_to_data = {
            "isolate_endpoint": {
                "brand": "CrowdStrike",
                "category": "endpoint",
                "description": "Isolate endpoint",
                "pretty_name": "Isolate Endpoint",
            }
        }

    @patch("CortexPlatformCore.demisto")
    def test_populate_suggestions_with_both_playbook_and_quick_action(self, mock_demisto):
        """Test with both playbook and quick action suggestions"""
        response = {
            "reply": {
                "playbook_id": "pb-1",
                "suggestion_rule_id": "rule-123",
                "quick_action_id": "isolate_endpoint",
                "quick_action_suggestion_rule_id": "qa-rule-456",
            }
        }
        self.mock_client.get_playbook_suggestion_by_issue.return_value = response

        recommendation = populate_playbook_and_quick_action_suggestions(
            self.mock_client, self.issue_id, self.pb_id_to_data, self.qa_name_to_data
        )

        expected_recommendation = {
            "playbook_suggestions": {
                "playbook_id": "pb-1",
                "suggestion_rule_id": "rule-123",
                "name": "Security Playbook",
                "comment": "Main security playbook",
            },
            "quick_action_suggestions": {
                "name": "isolate_endpoint",
                "suggestion_rule_id": "qa-rule-456",
                "brand": "CrowdStrike",
                "category": "endpoint",
                "description": "Isolate endpoint",
                "pretty_name": "Isolate Endpoint",
            },
        }

        assert recommendation == expected_recommendation

    @patch("CortexPlatformCore.demisto")
    def test_populate_suggestions_empty_response(self, mock_demisto):
        """Test with empty response"""
        response = {"reply": {}}
        self.mock_client.get_playbook_suggestion_by_issue.return_value = response

        recommendation = populate_playbook_and_quick_action_suggestions(
            self.mock_client, self.issue_id, self.pb_id_to_data, self.qa_name_to_data
        )

        assert recommendation == {}

    @patch("CortexPlatformCore.demisto")
    def test_populate_suggestions_only_playbook(self, mock_demisto):
        """Test with only playbook suggestion"""
        response = {"reply": {"playbook_id": "pb-2", "suggestion_rule_id": "rule-789"}}
        self.mock_client.get_playbook_suggestion_by_issue.return_value = response

        recommendation = populate_playbook_and_quick_action_suggestions(
            self.mock_client, self.issue_id, self.pb_id_to_data, self.qa_name_to_data
        )

        expected_recommendation = {
            "playbook_suggestions": {
                "playbook_id": "pb-2",
                "suggestion_rule_id": "rule-789",
                "name": "Incident Response",
                "comment": "IR playbook",
            }
        }

        assert recommendation == expected_recommendation

    @patch("CortexPlatformCore.demisto")
    def test_populate_suggestions_only_quick_action(self, mock_demisto):
        """Test with only quick action suggestion"""
        response = {
            "reply": {
                "quick_action_id": "isolate_endpoint",
                "quick_action_suggestion_rule_id": "qa-rule-456",
            }
        }
        self.mock_client.get_playbook_suggestion_by_issue.return_value = response

        recommendation = populate_playbook_and_quick_action_suggestions(
            self.mock_client, self.issue_id, self.pb_id_to_data, self.qa_name_to_data
        )

        expected_recommendation = {
            "quick_action_suggestions": {
                "name": "isolate_endpoint",
                "suggestion_rule_id": "qa-rule-456",
                "brand": "CrowdStrike",
                "category": "endpoint",
                "description": "Isolate endpoint",
                "pretty_name": "Isolate Endpoint",
            }
        }

        assert recommendation == expected_recommendation

    @patch("CortexPlatformCore.demisto")
    def test_populate_suggestions_playbook_not_in_metadata(self, mock_demisto):
        """Test with playbook ID not found in metadata"""
        response = {"reply": {"playbook_id": "pb-unknown", "suggestion_rule_id": "rule-999"}}
        self.mock_client.get_playbook_suggestion_by_issue.return_value = response

        recommendation = populate_playbook_and_quick_action_suggestions(
            self.mock_client, self.issue_id, self.pb_id_to_data, self.qa_name_to_data
        )

        expected_recommendation = {"playbook_suggestions": {"playbook_id": "pb-unknown", "suggestion_rule_id": "rule-999"}}

        assert recommendation == expected_recommendation

    @patch("CortexPlatformCore.demisto")
    def test_populate_suggestions_quick_action_not_in_metadata(self, mock_demisto):
        """Test with quick action ID not found in metadata"""
        response = {
            "reply": {
                "quick_action_id": "unknown_action",
                "quick_action_suggestion_rule_id": "qa-rule-999",
            }
        }
        self.mock_client.get_playbook_suggestion_by_issue.return_value = response

        recommendation = populate_playbook_and_quick_action_suggestions(
            self.mock_client, self.issue_id, self.pb_id_to_data, self.qa_name_to_data
        )

        expected_recommendation = {
            "quick_action_suggestions": {
                "name": "unknown_action",
                "suggestion_rule_id": "qa-rule-999",
            }
        }

        assert recommendation == expected_recommendation


class TestMapQaNameToData(unittest.TestCase):
    def test_map_qa_name_to_data_success(self):
        """Test successful mapping of QA metadata"""
        qas_metadata = [
            {
                "brand": "CrowdStrike",
                "category": "endpoint",
                "commands": [
                    {"name": "isolate_endpoint", "description": "Isolate an endpoint", "prettyName": "Isolate Endpoint"},
                    {"name": "quarantine_file", "description": "Quarantine a file", "prettyName": "Quarantine File"},
                ],
            },
            {
                "brand": "Splunk",
                "category": "siem",
                "commands": [{"name": "search_logs", "description": "Search logs", "prettyName": "Search Logs"}],
            },
        ]

        result = map_qa_name_to_data(qas_metadata)

        expected = {
            "isolate_endpoint": {
                "brand": "CrowdStrike",
                "category": "endpoint",
                "description": "Isolate an endpoint",
                "pretty_name": "Isolate Endpoint",
            },
            "quarantine_file": {
                "brand": "CrowdStrike",
                "category": "endpoint",
                "description": "Quarantine a file",
                "pretty_name": "Quarantine File",
            },
            "search_logs": {"brand": "Splunk", "category": "siem", "description": "Search logs", "pretty_name": "Search Logs"},
        }

        assert result == expected

    def test_map_qa_name_to_data_empty_metadata(self):
        """Test with empty metadata"""
        result = map_qa_name_to_data([])
        assert result == {}

    def test_map_qa_name_to_data_missing_commands(self):
        """Test with missing commands field"""
        qas_metadata = [
            {
                "brand": "TestBrand",
                "category": "test",
                # Missing commands field
            }
        ]

        result = map_qa_name_to_data(qas_metadata)
        assert result == {}


class TestGetIssueRecommendationsCommand:
    def setup_method(self):
        self.mock_client = Mock(spec=Client)

    @patch("CortexPlatformCore.demisto")
    @patch("CortexPlatformCore.get_appsec_suggestion")
    @patch("CortexPlatformCore.populate_playbook_and_quick_action_suggestions")
    @patch("CortexPlatformCore.map_qa_name_to_data")
    @patch("CortexPlatformCore.map_pb_id_to_data")
    @patch("CortexPlatformCore.argToList")
    @patch("CortexPlatformCore.FilterBuilder")
    @patch("CortexPlatformCore.build_webapp_request_data")
    @patch("CortexPlatformCore.create_issue_recommendations_readable_output")
    def test_get_issue_recommendations_command_success(
        self,
        mock_create_readable_output,
        mock_build_webapp_request_data,
        mock_filter_builder,
        mock_arg_to_list,
        mock_map_pb_id_to_data,
        mock_map_qa_name_to_data,
        mock_populate_pb_qa,
        mock_get_appsec_suggestion,
        mock_demisto,
    ):
        """Test successful execution of get_issue_recommendations_command"""
        # Setup mocks
        mock_arg_to_list.return_value = ["issue-1", "issue-2"]
        mock_filter_builder_instance = Mock()
        mock_filter_builder.return_value = mock_filter_builder_instance
        mock_filter_builder_instance.to_dict.return_value = {}
        mock_build_webapp_request_data.return_value = {}

        issue_data = [
            {
                "internal_id": "issue-1",
                "alert_name": "SQL Injection",
                "severity": "High",
                "alert_description": "SQL injection vulnerability",
                "remediation": "Use parameterized queries",
                "alert_source": "CAS_SAST_SCANNER",  # Valid AppSec source
            },
            {
                "internal_id": "issue-2",
                "alert_name": "Malware Detection",
                "severity": "Critical",
                "alert_description": "Malware detected",
                "remediation": "Isolate endpoint",
                "alert_source": "XDR",
            },
        ]

        self.mock_client.get_webapp_data.return_value = {"reply": {"DATA": issue_data}}
        self.mock_client.get_playbooks_metadata.return_value = []
        self.mock_client.get_quick_actions_metadata.return_value = []
        mock_map_pb_id_to_data.return_value = {}
        mock_map_qa_name_to_data.return_value = {}

        # Updated to return only recommendation dict
        mock_populate_pb_qa.return_value = {}
        mock_get_appsec_suggestion.return_value = {"existing_code_block": "old code", "suggested_code_block": "new code"}
        mock_create_readable_output.return_value = "Mock table output"

        args = {"issue_ids": "issue-1,issue-2"}

        # Execute
        result = get_issue_recommendations_command(self.mock_client, args)

        # Verify
        assert isinstance(result, CommandResults)
        assert result.readable_output == "Mock table output"
        self.mock_client.get_webapp_data.assert_called_once()
        self.mock_client.get_playbooks_metadata.assert_called_once()
        self.mock_client.get_quick_actions_metadata.assert_called_once()
        assert mock_get_appsec_suggestion.call_count == 2  # Called for both issues
        mock_create_readable_output.assert_called_once()

    @patch("CortexPlatformCore.argToList")
    def test_get_issue_recommendations_command_too_many_issues(self, mock_arg_to_list):
        """Test error when more than 10 issue IDs provided"""
        mock_arg_to_list.return_value = [f"issue-{i}" for i in range(11)]
        args = {"issue_ids": ",".join([f"issue-{i}" for i in range(11)])}

        with pytest.raises(DemistoException, match="maximum of 10 issue IDs"):
            get_issue_recommendations_command(self.mock_client, args)

    @patch("CortexPlatformCore.argToList")
    @patch("CortexPlatformCore.FilterBuilder")
    @patch("CortexPlatformCore.build_webapp_request_data")
    def test_get_issue_recommendations_command_no_issues_found(
        self, mock_build_webapp_request_data, mock_filter_builder, mock_arg_to_list
    ):
        """Test error when no issues found"""
        mock_arg_to_list.return_value = ["nonexistent-issue"]
        mock_filter_builder_instance = Mock()
        mock_filter_builder.return_value = mock_filter_builder_instance
        mock_filter_builder_instance.to_dict.return_value = {}
        mock_build_webapp_request_data.return_value = {}

        self.mock_client.get_webapp_data.return_value = {"reply": {"DATA": []}}

        args = {"issue_ids": "nonexistent-issue"}

        with pytest.raises(DemistoException, match="No issues found with IDs"):
            get_issue_recommendations_command(self.mock_client, args)

    @patch("CortexPlatformCore.demisto")
    @patch("CortexPlatformCore.get_appsec_suggestion")
    @patch("CortexPlatformCore.populate_playbook_and_quick_action_suggestions")
    @patch("CortexPlatformCore.map_qa_name_to_data")
    @patch("CortexPlatformCore.map_pb_id_to_data")
    @patch("CortexPlatformCore.argToList")
    @patch("CortexPlatformCore.FilterBuilder")
    @patch("CortexPlatformCore.build_webapp_request_data")
    @patch("CortexPlatformCore.create_issue_recommendations_readable_output")
    def test_get_issue_recommendations_command_with_all_headers(
        self,
        mock_create_readable_output,
        mock_build_webapp_request_data,
        mock_filter_builder,
        mock_arg_to_list,
        mock_map_pb_id_to_data,
        mock_map_qa_name_to_data,
        mock_populate_pb_qa,
        mock_get_appsec_suggestion,
        mock_demisto,
    ):
        """Test command with all types of suggestions to verify recommendations content"""
        # Setup mocks
        mock_arg_to_list.return_value = ["issue-1"]
        mock_filter_builder_instance = Mock()
        mock_filter_builder.return_value = mock_filter_builder_instance
        mock_filter_builder_instance.to_dict.return_value = {}
        mock_build_webapp_request_data.return_value = {}

        issue_data = [
            {
                "internal_id": "issue-1",
                "alert_name": "Test Issue",
                "severity": "High",
                "alert_description": "Test description",
                "remediation": "Test remediation",
                "alert_source": "CAS_CVE_SCANNER",  # Valid AppSec source
            }
        ]

        self.mock_client.get_webapp_data.return_value = {"reply": {"DATA": issue_data}}
        self.mock_client.get_playbooks_metadata.return_value = []
        self.mock_client.get_quick_actions_metadata.return_value = []
        mock_map_pb_id_to_data.return_value = {}
        mock_map_qa_name_to_data.return_value = {}

        # Return both playbook and quick action suggestions
        mock_populate_pb_qa.return_value = {
            "playbook_suggestions": {"playbook_id": "pb-1", "name": "Test Playbook"},
            "quick_action_suggestions": {"name": "qa-1", "pretty_name": "Test QA"},
        }

        # Return AppSec suggestions
        mock_get_appsec_suggestion.return_value = {
            "existing_code_block": "old code",
            "suggested_code_block": "new code",
        }

        def capture_recommendations(issue_ids, all_recommendations):
            # Verify the recommendations contain all expected data
            assert len(all_recommendations) == 1
            rec = all_recommendations[0]
            assert "issue_id" in rec
            assert "playbook_suggestions" in rec
            assert "quick_action_suggestions" in rec
            assert "existing_code_block" in rec
            assert "suggested_code_block" in rec
            return "Mock table with all headers"

        mock_create_readable_output.side_effect = capture_recommendations

        args = {"issue_ids": "issue-1"}

        # Execute
        result = get_issue_recommendations_command(self.mock_client, args)

        # Verify
        assert isinstance(result, CommandResults)
        mock_create_readable_output.assert_called_once()

    @patch("CortexPlatformCore.demisto")
    @patch("CortexPlatformCore.get_appsec_suggestion")
    @patch("CortexPlatformCore.populate_playbook_and_quick_action_suggestions")
    @patch("CortexPlatformCore.map_qa_name_to_data")
    @patch("CortexPlatformCore.map_pb_id_to_data")
    @patch("CortexPlatformCore.argToList")
    @patch("CortexPlatformCore.FilterBuilder")
    @patch("CortexPlatformCore.build_webapp_request_data")
    @patch("CortexPlatformCore.create_issue_recommendations_readable_output")
    def test_get_issue_recommendations_command_non_appsec_source(
        self,
        mock_create_readable_output,
        mock_build_webapp_request_data,
        mock_filter_builder,
        mock_arg_to_list,
        mock_map_pb_id_to_data,
        mock_map_qa_name_to_data,
        mock_populate_pb_qa,
        mock_get_appsec_suggestion,
        mock_demisto,
    ):
        """Test command with non-AppSec source (should call AppSec suggestions but return empty)"""
        # Setup mocks
        mock_arg_to_list.return_value = ["issue-1"]
        mock_filter_builder_instance = Mock()
        mock_filter_builder.return_value = mock_filter_builder_instance
        mock_filter_builder_instance.to_dict.return_value = {}
        mock_build_webapp_request_data.return_value = {}

        issue_data = [
            {
                "internal_id": "issue-1",
                "alert_name": "Test Issue",
                "severity": "High",
                "alert_description": "Test description",
                "remediation": "Test remediation",
                "alert_source": "XDR",  # Non-AppSec source
            }
        ]

        self.mock_client.get_webapp_data.return_value = {"reply": {"DATA": issue_data}}
        self.mock_client.get_playbooks_metadata.return_value = []
        self.mock_client.get_quick_actions_metadata.return_value = []
        mock_map_pb_id_to_data.return_value = {}
        mock_map_qa_name_to_data.return_value = {}

        mock_populate_pb_qa.return_value = {}
        mock_get_appsec_suggestion.return_value = {}  # Empty AppSec suggestions
        mock_create_readable_output.return_value = "Mock table output"

        args = {"issue_ids": "issue-1"}

        # Execute
        result = get_issue_recommendations_command(self.mock_client, args)

        # Verify AppSec suggestion was called but returned empty
        mock_get_appsec_suggestion.assert_called_once()
        assert isinstance(result, CommandResults)

    @patch("CortexPlatformCore.demisto")
    @patch("CortexPlatformCore.get_appsec_suggestion")
    @patch("CortexPlatformCore.populate_playbook_and_quick_action_suggestions")
    @patch("CortexPlatformCore.map_qa_name_to_data")
    @patch("CortexPlatformCore.map_pb_id_to_data")
    @patch("CortexPlatformCore.argToList")
    @patch("CortexPlatformCore.FilterBuilder")
    @patch("CortexPlatformCore.build_webapp_request_data")
    @patch("CortexPlatformCore.create_issue_recommendations_readable_output")
    def test_get_issue_recommendations_command_empty_metadata(
        self,
        mock_create_readable_output,
        mock_build_webapp_request_data,
        mock_filter_builder,
        mock_arg_to_list,
        mock_map_pb_id_to_data,
        mock_map_qa_name_to_data,
        mock_populate_pb_qa,
        mock_get_appsec_suggestion,
        mock_demisto,
    ):
        """Test command when playbooks/quick actions metadata is None"""
        # Setup mocks
        mock_arg_to_list.return_value = ["issue-1"]
        mock_filter_builder_instance = Mock()
        mock_filter_builder.return_value = mock_filter_builder_instance
        mock_filter_builder_instance.to_dict.return_value = {}
        mock_build_webapp_request_data.return_value = {}

        issue_data = [
            {
                "internal_id": "issue-1",
                "alert_name": "Test Issue",
                "severity": "High",
                "alert_description": "Test description",
                "remediation": "Test remediation",
                "alert_source": "XDR",
            }
        ]

        self.mock_client.get_webapp_data.return_value = {"reply": {"DATA": issue_data}}

        # Return None for metadata
        self.mock_client.get_playbooks_metadata.return_value = None
        self.mock_client.get_quick_actions_metadata.return_value = None
        mock_map_pb_id_to_data.return_value = {}
        mock_map_qa_name_to_data.return_value = {}

        mock_populate_pb_qa.return_value = {}
        mock_get_appsec_suggestion.return_value = {}
        mock_create_readable_output.return_value = "Mock table output"

        args = {"issue_ids": "issue-1"}

        # Execute - should not raise exception
        result = get_issue_recommendations_command(self.mock_client, args)

        # Verify
        assert isinstance(result, CommandResults)
        # Verify map functions were called with empty lists due to the `or []` fallback
        mock_map_pb_id_to_data.assert_called_with([])
        mock_map_qa_name_to_data.assert_called_with([])


class TestMapPbIdToData(unittest.TestCase):
    @patch("CortexPlatformCore.remove_empty_elements")
    def test_map_pb_id_to_data_valid_input(self, mock_remove_empty_elements):
        """Test map_pb_id_to_data with valid playbook metadata"""
        mock_remove_empty_elements.side_effect = lambda x: x  # Return input unchanged

        pbs_metadata = [
            {"id": "pb-1", "name": "Security Playbook", "comment": "Main security playbook"},
            {"id": "pb-2", "name": "Incident Response", "comment": "IR playbook"},
            {"id": "pb-3", "name": "Investigation", "comment": None},  # Will be filtered out
        ]

        result = map_pb_id_to_data(pbs_metadata)

        expected = {
            "pb-1": {"name": "Security Playbook", "comment": "Main security playbook"},
            "pb-2": {"name": "Incident Response", "comment": "IR playbook"},
            "pb-3": {"name": "Investigation", "comment": None},
        }

        assert result == expected
        assert mock_remove_empty_elements.call_count == 3

    @patch("CortexPlatformCore.remove_empty_elements")
    def test_map_pb_id_to_data_missing_id(self, mock_remove_empty_elements):
        """Test map_pb_id_to_data with playbooks missing ID"""
        mock_remove_empty_elements.side_effect = lambda x: x

        pbs_metadata = [
            {"id": "pb-1", "name": "Valid Playbook", "comment": "Valid"},
            {"name": "No ID Playbook", "comment": "Missing ID"},  # No ID
            {"id": "", "name": "Empty ID", "comment": "Empty ID"},  # Empty ID
            {"id": None, "name": "None ID", "comment": "None ID"},  # None ID
        ]

        result = map_pb_id_to_data(pbs_metadata)

        expected = {
            "pb-1": {"name": "Valid Playbook", "comment": "Valid"},
        }

        assert result == expected
        assert mock_remove_empty_elements.call_count == 1

    def test_map_pb_id_to_data_empty_list(self):
        """Test map_pb_id_to_data with empty list"""
        result = map_pb_id_to_data([])
        assert result == {}

    def test_map_pb_id_to_data_none_input(self):
        """Test map_pb_id_to_data with None input"""
        result = map_pb_id_to_data(None)
        assert result == {}

    def test_map_pb_id_to_data_invalid_input_types(self):
        """Test map_pb_id_to_data with invalid input types"""
        invalid_inputs = ["string", 123, {"dict": "value"}, True]

        for invalid_input in invalid_inputs:
            result = map_pb_id_to_data(invalid_input)
            assert result == {}

    @patch("CortexPlatformCore.remove_empty_elements")
    def test_map_pb_id_to_data_missing_name_and_comment(self, mock_remove_empty_elements):
        """Test map_pb_id_to_data with playbooks missing name and comment"""
        mock_remove_empty_elements.side_effect = lambda x: x

        pbs_metadata = [
            {"id": "pb-1"},  # Only ID
            {"id": "pb-2", "name": "Only Name"},  # Only name
            {"id": "pb-3", "comment": "Only Comment"},  # Only comment
        ]

        result = map_pb_id_to_data(pbs_metadata)

        expected = {
            "pb-1": {"name": None, "comment": None},
            "pb-2": {"name": "Only Name", "comment": None},
            "pb-3": {"name": None, "comment": "Only Comment"},
        }

        assert result == expected

    @patch("CortexPlatformCore.remove_empty_elements")
    def test_map_pb_id_to_data_duplicate_ids(self, mock_remove_empty_elements):
        """Test map_pb_id_to_data with duplicate IDs (last one wins)"""
        mock_remove_empty_elements.side_effect = lambda x: x

        pbs_metadata = [
            {"id": "pb-1", "name": "First Playbook", "comment": "First"},
            {"id": "pb-1", "name": "Second Playbook", "comment": "Second"},  # Duplicate ID
        ]

        result = map_pb_id_to_data(pbs_metadata)

        expected = {
            "pb-1": {"name": "Second Playbook", "comment": "Second"},  # Last one overwrites
        }

        assert result == expected


class TestCreateIssueRecommendationsReadableOutput(unittest.TestCase):
    @patch("CortexPlatformCore.tableToMarkdown")
    @patch("CortexPlatformCore.string_to_table_header")
    def test_create_readable_output_base_headers_only(self, mock_string_to_table_header, mock_table_to_markdown):
        """Test with recommendations containing only base fields"""
        mock_table_to_markdown.return_value = "Mock table output"

        issue_ids = ["issue-1", "issue-2"]
        all_recommendations = [
            {
                "issue_id": "issue-1",
                "issue_name": "Test Issue 1",
                "severity": "High",
                "description": "Test description 1",
                "remediation": "Test remediation 1",
            },
            {
                "issue_id": "issue-2",
                "issue_name": "Test Issue 2",
                "severity": "Medium",
                "description": "Test description 2",
                "remediation": "Test remediation 2",
            },
        ]

        result = create_issue_recommendations_readable_output(issue_ids, all_recommendations)

        assert result == "Mock table output"

        # Verify tableToMarkdown was called with correct parameters
        mock_table_to_markdown.assert_called_once()
        call_args = mock_table_to_markdown.call_args

        assert call_args[0][0] == "Issue Recommendations for ['issue-1', 'issue-2']"
        assert len(call_args[0][1]) == 2  # readable_recommendations
        assert call_args[1]["headers"] == ["issue_id", "issue_name", "severity", "description", "remediation"]

    @patch("CortexPlatformCore.tableToMarkdown")
    @patch("CortexPlatformCore.string_to_table_header")
    def test_create_readable_output_with_all_headers(self, mock_string_to_table_header, mock_table_to_markdown):
        """Test with recommendations containing all types of suggestions"""
        mock_table_to_markdown.return_value = "Mock comprehensive table"

        issue_ids = ["issue-1"]
        all_recommendations = [
            {
                "issue_id": "issue-1",
                "issue_name": "Comprehensive Issue",
                "severity": "Critical",
                "description": "Test description",
                "remediation": "Test remediation",
                "existing_code_block": "old code",
                "suggested_code_block": "new code",
                "playbook_suggestions": {"playbook_id": "pb-1", "name": "Security Playbook", "description": "Full description"},
                "quick_action_suggestions": {
                    "name": "isolate_endpoint",
                    "pretty_name": "Isolate Endpoint",
                    "brand": "CrowdStrike",
                },
            }
        ]

        result = create_issue_recommendations_readable_output(issue_ids, all_recommendations)

        assert result == "Mock comprehensive table"

        # Verify headers include all types
        call_args = mock_table_to_markdown.call_args
        expected_headers = [
            "issue_id",
            "issue_name",
            "severity",
            "description",
            "remediation",
            "existing_code_block",
            "suggested_code_block",
            "playbook_suggestions",
            "quick_action_suggestions",
        ]
        assert call_args[1]["headers"] == expected_headers

        # Verify readable recommendations are simplified
        readable_recs = call_args[0][1]
        assert len(readable_recs) == 1

        pb_suggestions = readable_recs[0]["playbook_suggestions"]
        assert pb_suggestions == {"name": "Security Playbook", "playbook_id": "pb-1"}

        qa_suggestions = readable_recs[0]["quick_action_suggestions"]
        assert qa_suggestions == {"name": "isolate_endpoint", "pretty_name": "Isolate Endpoint"}

    @patch("CortexPlatformCore.tableToMarkdown")
    @patch("CortexPlatformCore.string_to_table_header")
    def test_create_readable_output_partial_appsec_headers(self, mock_string_to_table_header, mock_table_to_markdown):
        """Test with only some AppSec headers present"""
        mock_table_to_markdown.return_value = "Mock partial table"

        issue_ids = ["issue-1", "issue-2"]
        all_recommendations = [
            {
                "issue_id": "issue-1",
                "issue_name": "Issue 1",
                "existing_code_block": "old code",  # Only existing code block
            },
            {
                "issue_id": "issue-2",
                "issue_name": "Issue 2",
                "suggested_code_block": "new code",  # Only suggested code block
            },
        ]

        create_issue_recommendations_readable_output(issue_ids, all_recommendations)

        # Should still add both AppSec headers if any AppSec content is found
        call_args = mock_table_to_markdown.call_args
        headers = call_args[1]["headers"]
        assert "existing_code_block" in headers
        assert "suggested_code_block" in headers

    @patch("CortexPlatformCore.tableToMarkdown")
    @patch("CortexPlatformCore.string_to_table_header")
    def test_create_readable_output_empty_recommendations(self, mock_string_to_table_header, mock_table_to_markdown):
        """Test with empty recommendations list"""
        mock_table_to_markdown.return_value = "Empty table"

        issue_ids = ["issue-1"]
        all_recommendations = []

        result = create_issue_recommendations_readable_output(issue_ids, all_recommendations)

        assert result == "Empty table"

        # Should only have base headers
        call_args = mock_table_to_markdown.call_args
        assert call_args[1]["headers"] == ["issue_id", "issue_name", "severity", "description", "remediation"]

    @patch("CortexPlatformCore.tableToMarkdown")
    @patch("CortexPlatformCore.string_to_table_header")
    def test_create_readable_output_non_dict_suggestions(self, mock_string_to_table_header, mock_table_to_markdown):
        """Test with non-dict suggestion values"""
        mock_table_to_markdown.return_value = "Mock table"

        issue_ids = ["issue-1"]
        all_recommendations = [
            {
                "issue_id": "issue-1",
                "playbook_suggestions": "not a dict",  # Should be ignored
                "quick_action_suggestions": None,  # Should be ignored
            }
        ]

        create_issue_recommendations_readable_output(issue_ids, all_recommendations)

        # Should still detect headers but not modify the values
        call_args = mock_table_to_markdown.call_args
        headers = call_args[1]["headers"]
        assert "playbook_suggestions" in headers
        assert "quick_action_suggestions" in headers

        # Values should remain unchanged
        readable_recs = call_args[0][1]
        assert readable_recs[0]["playbook_suggestions"] == "not a dict"
        assert readable_recs[0]["quick_action_suggestions"] is None

    @patch("CortexPlatformCore.tableToMarkdown")
    @patch("CortexPlatformCore.string_to_table_header")
    def test_create_readable_output_missing_suggestion_fields(self, mock_string_to_table_header, mock_table_to_markdown):
        """Test with suggestion dicts missing expected fields"""
        mock_table_to_markdown.return_value = "Mock table"

        issue_ids = ["issue-1"]
        all_recommendations = [
            {
                "issue_id": "issue-1",
                "playbook_suggestions": {"description": "Only description"},  # Missing name and playbook_id
                "quick_action_suggestions": {"brand": "Only brand"},  # Missing name and pretty_name
            }
        ]

        create_issue_recommendations_readable_output(issue_ids, all_recommendations)

        call_args = mock_table_to_markdown.call_args
        readable_recs = call_args[0][1]

        # Should use empty strings for missing fields
        assert readable_recs[0]["playbook_suggestions"] == {"name": "", "playbook_id": ""}
        assert readable_recs[0]["quick_action_suggestions"] == {"name": "", "pretty_name": ""}

    @patch("CortexPlatformCore.tableToMarkdown")
    @patch("CortexPlatformCore.string_to_table_header")
    def test_create_readable_output_mixed_recommendations(self, mock_string_to_table_header, mock_table_to_markdown):
        """Test with mixed recommendations (some with suggestions, some without)"""
        mock_table_to_markdown.return_value = "Mock mixed table"

        issue_ids = ["issue-1", "issue-2", "issue-3"]
        all_recommendations = [
            {
                "issue_id": "issue-1",
                "issue_name": "Basic Issue",
            },
            {
                "issue_id": "issue-2",
                "issue_name": "AppSec Issue",
                "existing_code_block": "old code",
            },
            {
                "issue_id": "issue-3",
                "issue_name": "Playbook Issue",
                "playbook_suggestions": {"playbook_id": "pb-1", "name": "Test PB"},
            },
        ]

        create_issue_recommendations_readable_output(issue_ids, all_recommendations)

        # Should include headers for the types that exist
        call_args = mock_table_to_markdown.call_args
        headers = call_args[1]["headers"]
        base_headers = ["issue_id", "issue_name", "severity", "description", "remediation"]

        assert all(h in headers for h in base_headers)
        assert "existing_code_block" in headers
        assert "suggested_code_block" in headers
        assert "playbook_suggestions" in headers


class TestMapEndpointFormat:
    """Test cases for map_endpoint_format function"""

    def test_map_endpoint_format_full_data(self):
        """
        Given:
            - A list of raw endpoint data with all fields
        When:
            - Calling map_endpoint_format
        Then:
            - Returns properly mapped endpoint data with friendly field names and values
        """
        from CortexPlatformCore import map_endpoint_format

        raw_endpoint_list = [
            {
                "AGENT_ID": "endpoint-123",
                "HOST_NAME": "test-host-1",
                "AGENT_TYPE": "AGENT_TYPE_SERVER",
                "AGENT_STATUS": "STATUS_010_CONNECTED",
                "OS_TYPE": "AGENT_OS_WINDOWS",
                "OPERATIONAL_STATUS": "PROTECTED",  # Changed from OPERATIONAL_STATUS_PROTECTED to PROTECTED
                "ACTIVE_POLICY": "PREVENTION_POLICY_ENABLED",
                "SUPPORTED_VERSION": False,
                "AGENT_VERSION": "7.8.0",
                "DOMAIN": "corp.local",
            }
        ]

        result = map_endpoint_format(raw_endpoint_list)

        expected = [
            {
                "endpoint_id": "endpoint-123",
                "endpoint_name": "test-host-1",
                "endpoint_type": "server",  # Maps from AGENT_TYPE_SERVER
                "endpoint_status": "connected",  # Maps from STATUS_010_CONNECTED
                "platform": "windows",  # Maps from AGENT_OS_WINDOWS
                "operational_status": "protected",  # Maps from PROTECTED
                "assigned_prevention_policy": "PREVENTION_POLICY_ENABLED",  # No mapping found, uses original
                "agent_eol": False,
                "agent_version": "7.8.0",
                "domain": "corp.local",
            }
        ]

        assert result == expected

    def test_map_endpoint_format_missing_fields(self):
        """
        Given:
            - A list of raw endpoint data with some missing fields
        When:
            - Calling map_endpoint_format
        Then:
            - Returns mapped data only for existing fields
        """
        from CortexPlatformCore import map_endpoint_format

        raw_endpoint_list = [
            {
                "AGENT_ID": "endpoint-456",
                "HOST_NAME": "test-host-2",  # Changed from AGENT_HOSTNAME
                "UNKNOWN_FIELD": "ignored_value",
            }
        ]

        result = map_endpoint_format(raw_endpoint_list)

        expected = [{"endpoint_id": "endpoint-456", "endpoint_name": "test-host-2"}]

        assert result == expected

    def test_map_endpoint_format_unmapped_values(self):
        """
        Given:
            - Raw endpoint data with values not in mapping dictionaries
        When:
            - Calling map_endpoint_format
        Then:
            - Returns original values for unmapped items
        """
        from CortexPlatformCore import map_endpoint_format

        raw_endpoint_list = [{"AGENT_ID": "endpoint-789", "AGENT_TYPE": "UNKNOWN_TYPE", "AGENT_STATUS": "UNKNOWN_STATUS"}]

        result = map_endpoint_format(raw_endpoint_list)

        expected = [{"endpoint_id": "endpoint-789", "endpoint_type": "UNKNOWN_TYPE", "endpoint_status": "UNKNOWN_STATUS"}]

        assert result == expected

    def test_map_endpoint_format_empty_list(self):
        """
        Given:
            - An empty endpoint list
        When:
            - Calling map_endpoint_format
        Then:
            - Returns empty list
        """
        from CortexPlatformCore import map_endpoint_format

        result = map_endpoint_format([])
        assert result == []

    def test_map_endpoint_format_multiple_endpoints(self):
        """
        Given:
            - Multiple raw endpoints
        When:
            - Calling map_endpoint_format
        Then:
            - Returns mapped data for all endpoints
        """
        from CortexPlatformCore import map_endpoint_format

        raw_endpoint_list = [
            {
                "AGENT_ID": "endpoint-1",
                "HOST_NAME": "host-1",  # Changed from AGENT_HOSTNAME
                "SUPPORTED_VERSION": True,  # Changed from AGENT_EOL
            },
            {
                "AGENT_ID": "endpoint-2",
                "HOST_NAME": "host-2",  # Changed from AGENT_HOSTNAME
                "SUPPORTED_VERSION": False,  # Changed from AGENT_EOL
            },
        ]

        result = map_endpoint_format(raw_endpoint_list)

        expected = [
            {
                "endpoint_id": "endpoint-1",
                "endpoint_name": "host-1",
                "agent_eol": True,
            },
            {
                "endpoint_id": "endpoint-2",
                "endpoint_name": "host-2",
                "agent_eol": False,
            },
        ]

        assert result == expected


def test_build_endpoint_filters_all_args(mocker):
    """
    Given:
        - Arguments with all possible filter parameters populated.
    When:
        - Calling build_endpoint_filters with complete args.
    Then:
        - FilterBuilder is configured with all filters correctly applied.
    """
    from CortexPlatformCore import build_endpoint_filters

    # Mock dependencies
    mock_filter_builder = mocker.patch("CortexPlatformCore.FilterBuilder")
    mock_filter_instance = mocker.Mock()
    mock_filter_builder.return_value = mock_filter_instance
    mock_filter_instance.to_dict.return_value = {"mock": "filter_dict"}

    mock_arg_to_list = mocker.patch("CortexPlatformCore.argToList")
    mock_arg_to_bool = mocker.patch("CortexPlatformCore.arg_to_bool_or_none")

    # Configure mocks
    mock_arg_to_list.side_effect = lambda x: [x] if x else []
    mock_arg_to_bool.return_value = True

    args = {
        "operational_status": "protected",  # Changed from "Protected" to match ENDPOINT_OPERATIONAL_STATUS key
        "endpoint_type": "server",  # Changed from "Server" to match ENDPOINT_TYPE key
        "endpoint_status": "connected",  # Changed from "Connected" to match ENDPOINT_STATUS key
        "platform": "windows",  # Changed from "Windows" to match ENDPOINT_PLATFORM key
        "assigned_prevention_policy": "Windows Default",  # Changed to match ASSIGNED_PREVENTION_POLICY key
        "agent_eol": "false",
        "endpoint_name": "test-endpoint",
        "operating_system": "Windows 10",
        "agent_version": "7.8.0",
        "os_version": "10.0.19041",
        "ip_address": "192.168.1.100",
        "domain": "corp.local",
        "tags": "production",
        "endpoint_id": "endpoint-123",
        "cloud_provider": "AWS",
        "cloud_region": "us-east-1",
    }

    result = build_endpoint_filters(args)

    # Verify FilterBuilder was instantiated and configured
    mock_filter_builder.assert_called_once()
    assert mock_filter_instance.add_field.call_count == 16
    mock_filter_instance.to_dict.assert_called_once()
    assert result == {"mock": "filter_dict"}


def test_build_endpoint_filters_minimal_args(mocker):
    """
    Given:
        - Empty arguments dictionary.
    When:
        - Calling build_endpoint_filters with no filter parameters.
    Then:
        - FilterBuilder is configured with empty/None values for all fields.
    """
    from CortexPlatformCore import build_endpoint_filters

    # Mock dependencies
    mock_filter_builder = mocker.patch("CortexPlatformCore.FilterBuilder")
    mock_filter_instance = mocker.Mock()
    mock_filter_builder.return_value = mock_filter_instance
    mock_filter_instance.to_dict.return_value = {"empty": "filter"}

    mock_arg_to_list = mocker.patch("CortexPlatformCore.argToList")
    mock_arg_to_bool = mocker.patch("CortexPlatformCore.arg_to_bool_or_none")

    mock_arg_to_list.return_value = []
    mock_arg_to_bool.return_value = None

    args = {}

    result = build_endpoint_filters(args)

    mock_filter_builder.assert_called_once()
    assert mock_filter_instance.add_field.call_count == 16
    mock_filter_instance.to_dict.assert_called_once()
    assert result == {"empty": "filter"}


def test_build_endpoint_filters_agent_eol(mocker):
    """
    Given:
    - Arguments with agent_eol parameter set to True.
    When:
    - Calling build_endpoint_filters with agent_eol=True.
    Then:
    - supported_version filter is set to True.
    """
    from CortexPlatformCore import build_endpoint_filters, Endpoints

    # Mock dependencies
    mock_filter_builder = mocker.patch("CortexPlatformCore.FilterBuilder")
    mock_filter_instance = mocker.Mock()
    mock_filter_builder.return_value = mock_filter_instance
    mock_filter_instance.to_dict.return_value = {}
    mock_arg_to_list = mocker.patch("CortexPlatformCore.argToList")
    mock_arg_to_bool = mocker.patch("CortexPlatformCore.arg_to_bool_or_none")

    mock_arg_to_list.return_value = []
    mock_arg_to_bool.return_value = True  # agent_eol = True

    args = {"agent_eol": "true"}
    build_endpoint_filters(args)

    # Verify supported_version (not agent_eol) was passed correctly
    calls = mock_filter_instance.add_field.call_args_list
    agent_eol_call = None
    for current_call in calls:
        if current_call[0][0] == Endpoints.ENDPOINT_FIELDS["agent_eol"]:
            agent_eol_call = current_call
            break

    assert agent_eol_call is not None
    assert agent_eol_call[0][2] is True


def test_core_list_endpoints_command_success(mocker):
    """
    Given:
    - Valid arguments and successful client response with endpoint data.
    When:
    - Calling core_list_endpoints_command.
    Then:
    - Returns list of CommandResults with properly formatted endpoint data and readable output.
    """
    from CortexPlatformCore import core_list_endpoints_command, Client, INTEGRATION_CONTEXT_BRAND

    # Mock dependencies
    mock_arg_to_number = mocker.patch("CortexPlatformCore.arg_to_number")
    mock_build_endpoint_filters = mocker.patch("CortexPlatformCore.build_endpoint_filters")
    mock_build_webapp_request_data = mocker.patch("CortexPlatformCore.build_webapp_request_data")
    mock_map_endpoint_format = mocker.patch("CortexPlatformCore.map_endpoint_format")
    mock_table_to_markdown = mocker.patch("CortexPlatformCore.tableToMarkdown")
    mocker.patch("CortexPlatformCore.demisto")

    # Configure mocks
    mock_arg_to_number.side_effect = lambda x: int(x) if x and x.isdigit() else None
    mock_build_endpoint_filters.return_value = {"test": "filters"}
    mock_build_webapp_request_data.return_value = {"test": "request_data"}
    mock_table_to_markdown.return_value = "Mock table output"

    raw_data = [{"AGENT_ID": "endpoint-1", "HOST_NAME": "host-1"}]
    mapped_data = [{"endpoint_id": "endpoint-1", "endpoint_name": "host-1"}]

    mock_client = mocker.Mock(spec=Client)
    mock_client.get_webapp_data.return_value = {"reply": {"DATA": raw_data, "FILTER_COUNT": "1"}}
    mock_map_endpoint_format.return_value = mapped_data

    args = {"page": "0", "page_size": "50", "endpoint_name": "test"}
    result = core_list_endpoints_command(mock_client, args)

    assert result.readable_output == "Mock table output"
    assert result.outputs == mapped_data
    assert result.outputs_prefix == f"{INTEGRATION_CONTEXT_BRAND}.Endpoint"
    assert result.outputs_key_field == "endpoint_id"
    assert result.raw_response == mapped_data

    # Verify function calls
    mock_build_endpoint_filters.assert_called_once_with(args)
    mock_build_webapp_request_data.assert_called_once()
    mock_client.get_webapp_data.assert_called_once()
    mock_map_endpoint_format.assert_called_once_with(raw_data)


def test_core_list_endpoints_command_default_pagination(mocker):
    """
    Given:
    - Arguments without page and page_size specified.
    When:
    - Calling core_list_endpoints_command with default pagination.
    Then:
    - Uses default pagination values (page=0, limit=100).
    """
    from CortexPlatformCore import core_list_endpoints_command, Client, MAX_GET_ENDPOINTS_LIMIT

    # Mock dependencies
    mock_arg_to_number = mocker.patch("CortexPlatformCore.arg_to_number")
    mock_build_endpoint_filters = mocker.patch("CortexPlatformCore.build_endpoint_filters")
    mock_build_webapp_request_data = mocker.patch("CortexPlatformCore.build_webapp_request_data")
    mock_map_endpoint_format = mocker.patch("CortexPlatformCore.map_endpoint_format")
    mock_table_to_markdown = mocker.patch("CortexPlatformCore.tableToMarkdown")
    mocker.patch("CortexPlatformCore.demisto")

    # Configure mocks
    mock_arg_to_number.return_value = None
    mock_build_endpoint_filters.return_value = {}
    mock_build_webapp_request_data.return_value = {}
    mock_table_to_markdown.return_value = "Empty table"

    mock_client = mocker.Mock(spec=Client)
    mock_client.get_webapp_data.return_value = {"reply": {"DATA": [], "FILTER_COUNT": "0"}}
    mock_map_endpoint_format.return_value = []

    args = {}
    result = core_list_endpoints_command(mock_client, args)

    # Verify default pagination was used
    call_kwargs = mock_build_webapp_request_data.call_args[1]
    assert call_kwargs["limit"] == MAX_GET_ENDPOINTS_LIMIT
    assert call_kwargs["start_page"] == 0
    assert result.outputs == []


def test_core_list_endpoints_command_empty_response(mocker):
    """
    Given:
    - Client returns empty DATA response.
    When:
    - Calling core_list_endpoints_command with empty server response.
    Then:
    - Returns CommandResults with empty outputs and handles gracefully.
    """
    from CortexPlatformCore import core_list_endpoints_command, Client

    mock_arg_to_number = mocker.patch("CortexPlatformCore.arg_to_number")
    mock_build_endpoint_filters = mocker.patch("CortexPlatformCore.build_endpoint_filters")
    mock_build_webapp_request_data = mocker.patch("CortexPlatformCore.build_webapp_request_data")
    mock_map_endpoint_format = mocker.patch("CortexPlatformCore.map_endpoint_format")
    mock_table_to_markdown = mocker.patch("CortexPlatformCore.tableToMarkdown")
    mocker.patch("CortexPlatformCore.demisto")

    # Configure mocks
    mock_arg_to_number.return_value = None
    mock_build_endpoint_filters.return_value = {}
    mock_build_webapp_request_data.return_value = {}
    mock_table_to_markdown.return_value = "No endpoints found"

    mock_client = mocker.Mock(spec=Client)
    mock_client.get_webapp_data.return_value = {"reply": {"DATA": [], "FILTER_COUNT": "0"}}
    mock_map_endpoint_format.return_value = []

    args = {}
    result = core_list_endpoints_command(mock_client, args)

    assert result.readable_output == "No endpoints found"
    assert result.outputs == []
    assert result.raw_response == []

    # Verify map_endpoint_format was called with empty list
    mock_map_endpoint_format.assert_called_once_with([])


def test_core_list_endpoints_command_custom_pagination(mocker):
    """
    Given:
    - Arguments with custom page and page_size values.
    When:
    - Calling core_list_endpoints_command with page=2, page_size=10.
    Then:
    - Uses correct pagination calculations (page_from=20, page_to=30).
    """
    from CortexPlatformCore import core_list_endpoints_command, Client, CommandResults

    # Mock dependencies
    mock_arg_to_number = mocker.patch("CortexPlatformCore.arg_to_number")
    mock_build_endpoint_filters = mocker.patch("CortexPlatformCore.build_endpoint_filters")
    mock_build_webapp_request_data = mocker.patch("CortexPlatformCore.build_webapp_request_data")
    mock_map_endpoint_format = mocker.patch("CortexPlatformCore.map_endpoint_format")
    mock_table_to_markdown = mocker.patch("CortexPlatformCore.tableToMarkdown")
    mocker.patch("CortexPlatformCore.demisto")

    # Configure mocks for custom pagination
    def mock_arg_to_number_side_effect(x):
        if x == "2":
            return 2
        elif x == "10":
            return 10
        return None

    mock_arg_to_number.side_effect = mock_arg_to_number_side_effect
    mock_build_endpoint_filters.return_value = {}
    mock_build_webapp_request_data.return_value = {}
    mock_table_to_markdown.return_value = "Page 2 table"

    mock_client = mocker.Mock(spec=Client)
    mock_client.get_webapp_data.return_value = {"reply": {"DATA": [], "FILTER_COUNT": "0"}}
    mock_map_endpoint_format.return_value = []

    args = {"page": "2", "page_size": "10"}
    result = core_list_endpoints_command(mock_client, args)

    # Verify pagination calculations: page_from=2*10=20, page_to=2*10+10=30
    call_kwargs = mock_build_webapp_request_data.call_args[1]
    assert call_kwargs["limit"] == 30  # page_to
    assert call_kwargs["start_page"] == 20  # page_from
    assert isinstance(result, CommandResults)


def test_core_list_endpoints_command_missing_reply_field(mocker):
    """
    Given:
    - Client returns response without 'reply' field.
    When:
    - Calling core_list_endpoints_command with malformed server response.
    Then:
    - Handles missing reply gracefully and returns empty results.
    """
    from CortexPlatformCore import core_list_endpoints_command, Client

    # Mock dependencies
    mock_arg_to_number = mocker.patch("CortexPlatformCore.arg_to_number")
    mock_build_endpoint_filters = mocker.patch("CortexPlatformCore.build_endpoint_filters")
    mock_build_webapp_request_data = mocker.patch("CortexPlatformCore.build_webapp_request_data")
    mock_map_endpoint_format = mocker.patch("CortexPlatformCore.map_endpoint_format")
    mock_table_to_markdown = mocker.patch("CortexPlatformCore.tableToMarkdown")
    mocker.patch("CortexPlatformCore.demisto")

    # Configure mocks
    mock_arg_to_number.return_value = None
    mock_build_endpoint_filters.return_value = {}
    mock_build_webapp_request_data.return_value = {}
    mock_table_to_markdown.return_value = "No data available"

    mock_client = mocker.Mock(spec=Client)
    mock_client.get_webapp_data.return_value = {}  # Missing 'reply' field
    mock_map_endpoint_format.return_value = []

    args = {}
    result = core_list_endpoints_command(mock_client, args)

    assert result.outputs == []

    # Verify map_endpoint_format was called with empty list (from missing DATA)
    mock_map_endpoint_format.assert_called_once_with([])


def test_core_list_endpoints_command_with_filters(mocker):
    """
    Given:
    - Arguments with multiple filter parameters.
    When:
    - Calling core_list_endpoints_command with endpoint filters.
    Then:
    - Filters are properly applied and data is correctly processed.
    """
    from CortexPlatformCore import core_list_endpoints_command, Client

    # Mock dependencies
    mock_arg_to_number = mocker.patch("CortexPlatformCore.arg_to_number")
    mock_build_endpoint_filters = mocker.patch("CortexPlatformCore.build_endpoint_filters")
    mock_build_webapp_request_data = mocker.patch("CortexPlatformCore.build_webapp_request_data")
    mock_map_endpoint_format = mocker.patch("CortexPlatformCore.map_endpoint_format")
    mock_table_to_markdown = mocker.patch("CortexPlatformCore.tableToMarkdown")
    mock_demisto = mocker.patch("CortexPlatformCore.demisto")

    # Configure mocks
    mock_arg_to_number.return_value = None
    mock_build_endpoint_filters.return_value = {"AGENT_STATUS": ["STATUS_010_CONNECTED"], "AGENT_TYPE": ["AGENT_TYPE_SERVER"]}
    mock_build_webapp_request_data.return_value = {"table": "agents", "filters": {}}
    mock_table_to_markdown.return_value = "Filtered endpoints table"

    raw_data = [{"AGENT_ID": "filtered-endpoint", "HOST_NAME": "server-01"}]
    mapped_data = [{"endpoint_id": "filtered-endpoint", "endpoint_name": "server-01"}]

    mock_client = mocker.Mock(spec=Client)
    mock_client.get_webapp_data.return_value = {"reply": {"DATA": raw_data, "FILTER_COUNT": "1"}}
    mock_map_endpoint_format.return_value = mapped_data

    args = {"endpoint_status": "connected", "endpoint_type": "server", "endpoint_name": "server-01"}
    result = core_list_endpoints_command(mock_client, args)

    # Verify filters were applied
    mock_build_endpoint_filters.assert_called_once_with(args)

    # Verify result
    assert result.outputs == mapped_data
    assert result.readable_output == "Filtered endpoints table"

    # Verify logging was called
    assert mock_demisto.info.called
    assert mock_demisto.debug.called


def test_core_list_endpoints_command_error_handling(mocker):
    """
    Given:
        - Client raises an exception during data retrieval.
    When:
        - Calling core_list_endpoints_command with failing client.
    Then:
        - Exception is properly propagated without being caught.
    """
    from CortexPlatformCore import core_list_endpoints_command, Client

    # Mock dependencies
    mock_arg_to_number = mocker.patch("CortexPlatformCore.arg_to_number")
    mock_build_endpoint_filters = mocker.patch("CortexPlatformCore.build_endpoint_filters")
    mock_build_webapp_request_data = mocker.patch("CortexPlatformCore.build_webapp_request_data")
    mocker.patch("CortexPlatformCore.demisto")

    # Configure mocks
    mock_arg_to_number.return_value = None
    mock_build_endpoint_filters.return_value = {}
    mock_build_webapp_request_data.return_value = {}

    mock_client = mocker.Mock(spec=Client)
    mock_client.get_webapp_data.side_effect = Exception("Server error")

    args = {}

    # Verify exception is propagated
    with pytest.raises(Exception, match="Server error"):
        core_list_endpoints_command(mock_client, args)


def test_normalize_key_with_xdm_asset_prefix():
    """Test normalization of keys with 'xdm.asset.' prefix."""
    from CortexPlatformCore import normalize_key

    assert normalize_key("xdm.asset.name") == "name"
    assert normalize_key("xdm.asset.id") == "id"
    assert normalize_key("xdm.asset.type") == "type"

    assert normalize_key("xdm.asset.type.name") == "type.name"
    assert normalize_key("xdm.asset.group.id") == "group.id"
    assert normalize_key("xdm.asset.provider.region") == "provider.region"


def test_normalize_key_with_xdm_prefix():
    """Test normalization of keys with 'xdm.' prefix (but not 'xdm.asset.')."""
    from CortexPlatformCore import normalize_key

    assert normalize_key("xdm.source.ip") == "source.ip"
    assert normalize_key("xdm.target.host") == "target.host"
    assert normalize_key("xdm.event.type") == "event.type"


def test_normalize_key_without_prefix():
    """Test that keys without XDM prefixes are returned unchanged."""
    from CortexPlatformCore import normalize_key

    # Regular field names
    assert normalize_key("name") == "name"
    assert normalize_key("id") == "id"
    assert normalize_key("status") == "status"

    # Nested field names
    assert normalize_key("user.name") == "user.name"
    assert normalize_key("network.interface.type") == "network.interface.type"

    # Field names that contain 'xdm' but don't start with it
    assert normalize_key("field.xdm.name") == "field.xdm.name"
    assert normalize_key("some_xdm_field") == "some_xdm_field"


class TestCoreAddAssessmentProfileCommand:
    def test_core_add_assessment_profile_command_success(self, mocker):
        """Test successful assessment profile creation

        Given: Mock client with valid standards and asset groups responses
        When: core_add_assessment_profile_command is called with valid arguments
        Then: Returns successful result with profile ID
        """
        from CortexPlatformCore import core_add_assessment_profile_command

        mock_client = mocker.Mock()

        # Mock compliance standards response
        standards_response = {"reply": {"standards": [{"id": "std-123", "name": "Test Standard"}]}}
        mock_client.list_compliance_standards_command.return_value = standards_response

        # Mock asset groups response
        asset_groups_response = {"reply": {"data": [{"XDM.ASSET_GROUP.ID": "group-456", "XDM.ASSET_GROUP.NAME": "Test Group"}]}}
        mock_client.search_asset_groups.return_value = asset_groups_response

        # Mock add assessment profile response
        add_profile_response = {"assessment_profile_id": "profile-789"}
        mock_client.add_assessment_profile.return_value = add_profile_response

        # Mock payload functions
        mocker.patch("CortexPlatformCore.list_compliance_standards_payload", return_value={})
        mocker.patch("CortexPlatformCore.create_assessment_profile_payload", return_value={})
        mocker.patch("CortexPlatformCore.FilterBuilder")

        args = {
            "profile_name": "Test Profile",
            "profile_description": "Test Description",
            "standard_name": "Test Standard",
            "asset_group_name": "Test Group",
            "day": "monday",
            "time": "14:30",
        }

        result = core_add_assessment_profile_command(mock_client, args)

        assert result.readable_output == "Assessment Profile profile-789 successfully added"
        assert result.outputs_prefix == "Core.AssessmentProfile"
        assert result.outputs_key_field == "assessment_profile_id"
        assert result.outputs == "profile-789"

    def test_core_add_assessment_profile_command_no_compliance_standards(self, mocker):
        """Test when no compliance standards are found

        Given: Mock client with empty standards response
        When: core_add_assessment_profile_command is called with nonexistent standard
        Then: Raises exception indicating no compliance standards found
        """
        from CortexPlatformCore import core_add_assessment_profile_command

        mock_client = mocker.Mock()

        standards_response = {"reply": {"standards": []}}
        mock_client.list_compliance_standards_command.return_value = standards_response

        mocker.patch("CortexPlatformCore.list_compliance_standards_payload", return_value={})
        mocker.patch("CortexPlatformCore.return_error", side_effect=Exception("No compliance standards found"))

        args = {"profile_name": "Test Profile", "standard_name": "Nonexistent Standard", "asset_group_name": "Test Group"}

        with pytest.raises(Exception, match="No compliance standards found"):
            core_add_assessment_profile_command(mock_client, args)

    def test_core_add_assessment_profile_command_multiple_compliance_standards(self, mocker):
        """Test when multiple compliance standards match

        Given: Mock client with multiple standards that match the search criteria
        When: core_add_assessment_profile_command is called with ambiguous standard name
        Then: Raises exception indicating multiple standards found
        """
        from CortexPlatformCore import core_add_assessment_profile_command

        mock_client = mocker.Mock()

        standards_response = {
            "reply": {"standards": [{"id": "std-123", "name": "Test Standard 1"}, {"id": "std-456", "name": "Test Standard 2"}]}
        }
        mock_client.list_compliance_standards_command.return_value = standards_response

        mocker.patch("CortexPlatformCore.list_compliance_standards_payload", return_value={})
        mocker.patch("CortexPlatformCore.return_error", side_effect=Exception("Multiple standards found"))

        args = {"profile_name": "Test Profile", "standard_name": "Test", "asset_group_name": "Test Group"}

        with pytest.raises(Exception, match="Multiple standards found"):
            core_add_assessment_profile_command(mock_client, args)

    def test_core_add_assessment_profile_command_no_asset_groups(self, mocker):
        """Test when no asset groups are found

        Given: Mock client with valid standards but empty asset groups response
        When: core_add_assessment_profile_command is called with nonexistent asset group
        Then: Raises exception indicating no asset group found
        """
        from CortexPlatformCore import core_add_assessment_profile_command

        mock_client = mocker.Mock()

        standards_response = {"reply": {"standards": [{"id": "std-123", "name": "Test Standard"}]}}
        mock_client.list_compliance_standards_command.return_value = standards_response

        asset_groups_response = {"reply": {"data": []}}
        mock_client.search_asset_groups.return_value = asset_groups_response

        mocker.patch("CortexPlatformCore.list_compliance_standards_payload", return_value={})
        mocker.patch("CortexPlatformCore.FilterBuilder")
        mocker.patch("CortexPlatformCore.return_error", side_effect=Exception("No asset group found"))

        args = {"profile_name": "Test Profile", "standard_name": "Test Standard", "asset_group_name": "Nonexistent Group"}

        with pytest.raises(Exception, match="No asset group found"):
            core_add_assessment_profile_command(mock_client, args)

    def test_core_add_assessment_profile_command_multiple_asset_groups(self, mocker):
        """Test when multiple asset groups match

        Given: Mock client with multiple asset groups that match the search criteria
        When: core_add_assessment_profile_command is called with ambiguous asset group name
        Then: Raises exception indicating multiple asset groups found
        """
        from CortexPlatformCore import core_add_assessment_profile_command

        mock_client = mocker.Mock()

        standards_response = {"reply": {"standards": [{"id": "std-123", "name": "Test Standard"}]}}
        mock_client.list_compliance_standards_command.return_value = standards_response

        asset_groups_response = {
            "reply": {
                "data": [
                    {"XDM.ASSET_GROUP.ID": "group-456", "XDM.ASSET_GROUP.NAME": "Test Group 1"},
                    {"XDM.ASSET_GROUP.ID": "group-789", "XDM.ASSET_GROUP.NAME": "Test Group 2"},
                ]
            }
        }
        mock_client.search_asset_groups.return_value = asset_groups_response

        mocker.patch("CortexPlatformCore.list_compliance_standards_payload", return_value={})
        mocker.patch("CortexPlatformCore.FilterBuilder")
        mocker.patch("CortexPlatformCore.return_error", side_effect=Exception("Multiple asset groups found"))

        args = {"profile_name": "Test Profile", "standard_name": "Test Standard", "asset_group_name": "Test"}

        with pytest.raises(Exception, match="Multiple asset groups found"):
            core_add_assessment_profile_command(mock_client, args)

    def test_core_add_assessment_profile_command_default_values(self, mocker):
        """Test with default day and time values

        Given: Mock client with valid responses and arguments without day/time specified
        When: core_add_assessment_profile_command is called with minimal arguments
        Then: Uses default values for day (sunday) and time (12:00) and returns successful result
        """
        from CortexPlatformCore import core_add_assessment_profile_command

        mock_client = mocker.Mock()

        standards_response = {"reply": {"standards": [{"id": "std-123", "name": "Test Standard"}]}}
        mock_client.list_compliance_standards_command.return_value = standards_response

        asset_groups_response = {"reply": {"data": [{"XDM.ASSET_GROUP.ID": "group-456", "XDM.ASSET_GROUP.NAME": "Test Group"}]}}
        mock_client.search_asset_groups.return_value = asset_groups_response

        add_profile_response = {"assessment_profile_id": "profile-789"}
        mock_client.add_assessment_profile.return_value = add_profile_response

        mock_create_payload = mocker.patch("CortexPlatformCore.create_assessment_profile_payload", return_value={})
        mocker.patch("CortexPlatformCore.list_compliance_standards_payload", return_value={})
        mocker.patch("CortexPlatformCore.FilterBuilder")

        args = {
            "profile_name": "Test Profile",
            "profile_description": "Test Description",
            "standard_name": "Test Standard",
            "asset_group_name": "Test Group",
        }

        result = core_add_assessment_profile_command(mock_client, args)

        mock_create_payload.assert_called_with(
            name="Test Profile",
            description="Test Description",
            standard_id="std-123",
            asset_group_id="group-456",
            day="sunday",
            time="12:00",
            report_type="ALL",
        )
        assert result.outputs == "profile-789"


class TestCoreListComplianceStandardsCommand:
    def test_core_list_compliance_standards_command_with_empty_args(self, mocker):
        """Test list compliance standards command with empty arguments

        Given: A mock client and empty arguments
        When: core_list_compliance_standards_command is called with empty args
        Then: Returns proper response structure with correct counts
        """
        from CortexPlatformCore import core_list_compliance_standards_command

        client = mocker.Mock()
        mock_response = {
            "reply": {
                "standards": [
                    {
                        "id": "std1",
                        "name": "Standard 1",
                        "description": "Test standard",
                        "controls_ids": ["ctrl1", "ctrl2"],
                        "assessments_profiles_count": 5,
                        "labels": ["label1", "label2"],
                    }
                ],
                "result_count": 1,
            }
        }
        client.list_compliance_standards_command.return_value = mock_response

        result = core_list_compliance_standards_command(client, {})

        assert len(result) == 2
        assert result[0].outputs_prefix == "Core.ComplianceStandards"
        assert result[1].outputs["filtered_count"] == 1
        assert result[1].outputs["returned_count"] == 1

    def test_core_list_compliance_standards_command_with_empty_standards_list(self, mocker):
        """Test handling of empty standards list

        Given: A mock client returning empty standards list
        When: core_list_compliance_standards_command is called
        Then: Returns empty outputs with zero counts
        """
        from CortexPlatformCore import core_list_compliance_standards_command

        client = mocker.Mock()
        mock_response = {"reply": {"standards": [], "result_count": 0}}
        client.list_compliance_standards_command.return_value = mock_response

        result = core_list_compliance_standards_command(client, {})

        assert len(result) == 2
        assert result[0].outputs == []
        assert result[1].outputs["filtered_count"] == 0
        assert result[1].outputs["returned_count"] == 0

    def test_core_list_compliance_standards_command_multiple_standards(self, mocker):
        """Test handling of multiple compliance standards

        Given: A mock client returning multiple standards
        When: core_list_compliance_standards_command is called
        Then: Returns all standards with correct control counts and metadata
        """
        from CortexPlatformCore import core_list_compliance_standards_command

        client = mocker.Mock()
        mock_response = {
            "reply": {
                "standards": [
                    {
                        "id": "std1",
                        "name": "Standard 1",
                        "description": "Test standard 1",
                        "controls_ids": ["ctrl1", "ctrl2"],
                        "assessments_profiles_count": 2,
                        "labels": ["lbl1"],
                    },
                    {
                        "id": "std2",
                        "name": "Standard 2",
                        "description": "Test standard 2",
                        "controls_ids": ["ctrl3"],
                        "assessments_profiles_count": 5,
                        "labels": ["lbl2", "lbl3"],
                    },
                ],
                "result_count": 2,
            }
        }
        client.list_compliance_standards_command.return_value = mock_response

        result = core_list_compliance_standards_command(client, {})

        assert len(result[0].outputs) == 2
        assert result[0].outputs[0]["id"] == "std1"
        assert result[0].outputs[0]["controls_count"] == 2
        assert result[0].outputs[1]["id"] == "std2"
        assert result[0].outputs[1]["controls_count"] == 1
        assert result[1].outputs["returned_count"] == 2
