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


def test_create_filter_from_fields_single_value():
    """
    GIVEN:
        A Filter with a single Field containing one value.
    WHEN:
        Filter.to_dict() is called.
    THEN:
        A filter with a single search object is created.
    """
    from CortexPlatformCore import FilterBuilder, FilterType

    filter_obj = FilterBuilder()
    filter_obj.add_field("xdm.asset.name", FilterType.EQ, ["test-asset-name"])
    result = filter_obj.to_dict()

    expected = {
        "AND": [
            {
                "SEARCH_FIELD": "xdm.asset.name",
                "SEARCH_TYPE": "EQ",
                "SEARCH_VALUE": "test-asset-name",
            }
        ]
    }
    assert result == expected


def test_create_filter_from_fields_multiple_fields():
    """
    GIVEN:
        A Filter with multiple Field objects with different operators.
    WHEN:
        Filter.to_dict() is called.
    THEN:
        A filter with multiple AND conditions is created.
    """
    from CortexPlatformCore import FilterBuilder, FilterType

    filter_obj = FilterBuilder()
    filter_obj.add_field("xdm.asset.name", FilterType.EQ, ["test-asset"])
    filter_obj.add_field("xdm.asset.tags", FilterType.CONTAINS, ["production", "critical"])
    filter_obj.add_field("xdm.asset.id", FilterType.EQ, ["12345"])
    filter_obj.add_field("xdm.asset.name", FilterType.EQ, [])
    result = filter_obj.to_dict()

    expected = {
        "AND": [
            {
                "SEARCH_FIELD": "xdm.asset.name",
                "SEARCH_TYPE": "EQ",
                "SEARCH_VALUE": "test-asset",
            },
            {
                "OR": [
                    {
                        "SEARCH_FIELD": "xdm.asset.tags",
                        "SEARCH_TYPE": "CONTAINS",
                        "SEARCH_VALUE": "production",
                    },
                    {
                        "SEARCH_FIELD": "xdm.asset.tags",
                        "SEARCH_TYPE": "CONTAINS",
                        "SEARCH_VALUE": "critical",
                    },
                ]
            },
            {
                "SEARCH_FIELD": "xdm.asset.id",
                "SEARCH_TYPE": "EQ",
                "SEARCH_VALUE": "12345",
            },
        ]
    }
    assert result == expected


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
