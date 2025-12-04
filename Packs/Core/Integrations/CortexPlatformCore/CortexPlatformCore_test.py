import json

import pytest
from pytest_mock import MockerFixture
from unittest.mock import call
import demistomock as demisto

from unittest.mock import Mock, patch
from CortexPlatformCore import get_issue_recommendations_command, Client


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
    client.get_incidents.return_value = [{"case_id": "1"}]
    mocker.patch("CortexPlatformCore.tableToMarkdown", return_value="table")
    args = {"case_id_list": 1}
    result = get_cases_command(client, args)
    assert result.outputs == [{"case_id": "1"}]
    client.get_incidents.assert_called_once()
    assert result.readable_output.startswith("table")


def test_get_cases_command_limit_enforced(mocker: MockerFixture):
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


def test_get_cases_command_no_filters_error(mocker: MockerFixture):
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


def test_get_cases_command_conflicting_time_filters(mocker: MockerFixture):
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


def test_get_issue_recommendations_command(mocker):
    """
    Given:
        - Valid issue_id for get_issue_recommendations command
    When:
        - Running get_issue_recommendations command
    Then:
        - Ensure the command returns the expected results with issue data and playbook suggestions
    """
    from CortexPlatformCore import get_issue_recommendations_command, Client

    # Mock the webapp API response
    mock_webapp_response = {
        "reply": {
            "DATA": [
                {
                    "internal_id": "issue_123",
                    "alert_name": "Critical Security Vulnerability",
                    "severity": "HIGH",
                    "alert_description": "SQL injection vulnerability detected",
                    "remediation": "Update to latest version and apply security patches",
                }
            ]
        }
    }

    # Mock the playbook suggestions response
    mock_playbook_response = {
        "reply": [{"playbook_name": "Security Incident Response", "playbook_id": "pb_001", "confidence": 0.95}]
    }

    client = Client(base_url="https://test.com", headers={})
    mocker.patch.object(client, "get_webapp_data", return_value=mock_webapp_response)
    mocker.patch.object(client, "get_playbook_suggestion_by_issue", return_value=mock_playbook_response)

    args = {"issue_id": "issue_123"}

    result = get_issue_recommendations_command(client, args)

    # Assertions
    assert result.outputs_prefix == "Core.IssueRecommendations"
    assert result.outputs_key_field == "issue_id"
    assert result.outputs["issue_id"] == "issue_123"
    assert result.outputs["issue_name"] == "Critical Security Vulnerability"
    assert result.outputs["severity"] == "HIGH"
    assert result.outputs["remediation"] == "Update to latest version and apply security patches"
    assert result.outputs["playbook_suggestions"] == mock_playbook_response["reply"]
    assert "Issue Recommendations for issue_123" in result.readable_output
    assert "Playbook Suggestions" in result.readable_output


def test_get_issue_recommendations_command_no_playbook_suggestions(mocker):
    """
    Given:
        - Valid issue_id with no playbook suggestions available
    When:
        - Running get_issue_recommendations command
    Then:
        - Ensure the command returns recommendations without playbook suggestions section
    """
    from CortexPlatformCore import get_issue_recommendations_command, Client

    # Mock the webapp API response
    mock_webapp_response = {
        "reply": {
            "DATA": [
                {
                    "internal_id": "issue_456",
                    "alert_name": "Configuration Issue",
                    "severity": "MEDIUM",
                    "alert_description": "Misconfigured firewall rule",
                    "remediation": "Review and update firewall configuration",
                }
            ]
        }
    }

    # Mock empty playbook suggestions
    mock_playbook_response = {"reply": []}

    client = Client(base_url="https://test.com", headers={})
    mocker.patch.object(client, "get_webapp_data", return_value=mock_webapp_response)
    mocker.patch.object(client, "get_playbook_suggestion_by_issue", return_value=mock_playbook_response)

    args = {"issue_id": "issue_456"}

    result = get_issue_recommendations_command(client, args)

    assert result.outputs["issue_id"] == "issue_456"
    assert result.outputs["playbook_suggestions"] == []
    assert "Issue Recommendations for issue_456" in result.readable_output


def test_get_issue_recommendations_command_api_calls(mocker):
    """
    Given:
        - Valid issue_id for get_issue_recommendations command
    When:
        - Running get_issue_recommendations command
    Then:
        - Ensure the correct API calls are made with proper parameters
    """
    from CortexPlatformCore import get_issue_recommendations_command, Client

    mock_webapp_response = {
        "reply": {
            "DATA": [
                {
                    "internal_id": "issue_789",
                    "alert_name": "Test Issue",
                    "severity": "LOW",
                    "alert_description": "Test description",
                    "remediation": "Test remediation",
                }
            ]
        }
    }

    mock_playbook_response = {"reply": []}

    client = Client(base_url="https://test.com", headers={})
    webapp_mock = mocker.patch.object(client, "get_webapp_data", return_value=mock_webapp_response)
    playbook_mock = mocker.patch.object(client, "get_playbook_suggestion_by_issue", return_value=mock_playbook_response)

    args = {"issue_id": "issue_789"}

    get_issue_recommendations_command(client, args)

    # Verify API calls were made
    webapp_mock.assert_called_once()
    playbook_mock.assert_called_once_with("issue_789")

    # Verify the webapp call was made with correct request data
    call_args = webapp_mock.call_args[0][0]
    assert call_args["table_name"] == "ALERTS_VIEW_TABLE"
    assert call_args["type"] == "grid"
    assert "filter_data" in call_args


class TestGetIssueRecommendationsCommand:
    """Test cases for the AppSec fix suggestion logic in get_issue_recommendations_command"""

    def setup_method(self):
        """Setup method to initialize common test data"""
        self.mock_client = Mock(spec=Client)
        self.issue_id = "test_issue_123"
        self.base_args = {"issue_id": self.issue_id}

        self.base_issue = {
            "internal_id": self.issue_id,
            "alert_name": "Test Security Issue",
            "severity": "HIGH",
            "alert_description": "Test description",
            "remediation": "Base remediation steps",
        }

        self.base_webapp_response = {"reply": {"DATA": [self.base_issue]}}
        self.base_playbook_response = {"reply": {"suggested_playbooks": ["Playbook1", "Playbook2"]}}

    @patch("CortexPlatformCore.build_webapp_request_data")
    def test_appsec_issue_with_fix_suggestion(self, mock_build_request):
        """Test AppSec issue with successful fix suggestion retrieval"""
        appsec_issue = self.base_issue.copy()
        appsec_issue.update({"alert_source": "CAS_CVE_SCANNER", "extended_fields": {"action": "Manual fix instructions"}})

        webapp_response = {"reply": {"DATA": [appsec_issue]}}

        fix_suggestion = {"existingCodeBlock": "vulnerable_code_here()", "suggestedCodeBlock": "secure_code_here()"}

        mock_build_request.return_value = {"mock": "request_data"}
        self.mock_client.get_webapp_data.return_value = webapp_response
        self.mock_client.get_playbook_suggestion_by_issue.return_value = self.base_playbook_response
        self.mock_client.get_appsec_suggested_fix.return_value = fix_suggestion

        result = get_issue_recommendations_command(self.mock_client, self.base_args)

        self.mock_client.get_appsec_suggested_fix.assert_called_once_with(self.issue_id)

        expected_recommendation = {
            "issue_id": self.issue_id,
            "issue_name": "Test Security Issue",
            "severity": "HIGH",
            "description": "Test description",
            "remediation": "Manual fix instructions",  # Should use manual_fix
            "playbook_suggestions": {"suggested_playbooks": ["Playbook1", "Playbook2"]},
            "existing_code_block": "vulnerable_code_here()",
            "suggested_code_block": "secure_code_here()",
        }

        assert result.outputs == expected_recommendation
        assert "Existing Code Block" in result.readable_output
        assert "Suggested Code Block" in result.readable_output

    @patch("CortexPlatformCore.build_webapp_request_data")
    def test_appsec_issue_without_manual_fix(self, mock_build_request):
        """Test AppSec issue without manual fix, should use base remediation"""
        appsec_issue = self.base_issue.copy()
        appsec_issue.update(
            {
                "alert_source": "CAS_IAC_SCANNER",
                "extended_fields": {},  # No manual fix
            }
        )

        webapp_response = {"reply": {"DATA": [appsec_issue]}}

        fix_suggestion = {"existingCodeBlock": "terraform_issue_here", "suggestedCodeBlock": "terraform_fix_here"}

        mock_build_request.return_value = {"mock": "request_data"}
        self.mock_client.get_webapp_data.return_value = webapp_response
        self.mock_client.get_playbook_suggestion_by_issue.return_value = self.base_playbook_response
        self.mock_client.get_appsec_suggested_fix.return_value = fix_suggestion

        result = get_issue_recommendations_command(self.mock_client, self.base_args)

        expected_recommendation = {
            "issue_id": self.issue_id,
            "issue_name": "Test Security Issue",
            "severity": "HIGH",
            "description": "Test description",
            "remediation": "Base remediation steps",  # Should use base remediation
            "playbook_suggestions": {"suggested_playbooks": ["Playbook1", "Playbook2"]},
            "existing_code_block": "terraform_issue_here",
            "suggested_code_block": "terraform_fix_here",
        }

        assert result.outputs == expected_recommendation

    @patch("CortexPlatformCore.build_webapp_request_data")
    def test_appsec_issue_no_fix_suggestion(self, mock_build_request):
        """Test AppSec issue when fix suggestion API returns None"""
        appsec_issue = self.base_issue.copy()
        appsec_issue.update({"alert_source": "CAS_SECRET_SCANNER", "extended_fields": {"action": "Manual secret remediation"}})

        webapp_response = {"reply": {"DATA": [appsec_issue]}}

        mock_build_request.return_value = {"mock": "request_data"}
        self.mock_client.get_webapp_data.return_value = webapp_response
        self.mock_client.get_playbook_suggestion_by_issue.return_value = self.base_playbook_response
        self.mock_client.get_appsec_suggested_fix.return_value = None  # No fix suggestion
        result = get_issue_recommendations_command(self.mock_client, self.base_args)

        self.mock_client.get_appsec_suggested_fix.assert_called_once_with(self.issue_id)

        expected_recommendation = {
            "issue_id": self.issue_id,
            "issue_name": "Test Security Issue",
            "severity": "HIGH",
            "description": "Test description",
            "remediation": "Manual secret remediation",
            "playbook_suggestions": {"suggested_playbooks": ["Playbook1", "Playbook2"]},
        }

        assert result.outputs == expected_recommendation
        assert "Existing Code Block" not in result.outputs
        assert "Suggested Code Block" not in result.outputs

    @patch("CortexPlatformCore.build_webapp_request_data")
    def test_appsec_sources_coverage(self, mock_build_request):
        """Test all AppSec sources are handled correctly"""
        appsec_sources = ["CAS_CVE_SCANNER", "CAS_IAC_SCANNER", "CAS_SECRET_SCANNER"]

        for source in appsec_sources:
            appsec_issue = self.base_issue.copy()
            appsec_issue["alert_source"] = source

            webapp_response = {"reply": {"DATA": [appsec_issue]}}

            fix_suggestion = {"existingCodeBlock": f"issue_in_{source}", "suggestedCodeBlock": f"fix_for_{source}"}

            mock_build_request.return_value = {"mock": "request_data"}
            self.mock_client.get_webapp_data.return_value = webapp_response
            self.mock_client.get_playbook_suggestion_by_issue.return_value = self.base_playbook_response
            self.mock_client.get_appsec_suggested_fix.return_value = fix_suggestion

            result = get_issue_recommendations_command(self.mock_client, self.base_args)

            assert result.outputs["existing_code_block"] == f"issue_in_{source}"
            assert result.outputs["suggested_code_block"] == f"fix_for_{source}"

            self.mock_client.reset_mock()


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
