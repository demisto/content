from CommonServerPython import *


def test_arg_parse():
    """
    Given:
       - The integration, the arguments
    When:
       - Parsing the arguments
    Then:
       - The arguments with correct python types
    """

    from O365SecurityComplianceSearch import parse_args

    args = {
        "search_name": "test search",
        "force": "true",
        "preview": "false",
        "case": "test case",
        "kql_search": "test search",
        "include_mailboxes": "true",
        "exchange_location": "exchange1,exchange2",
        "exchange_location_exclusion": "exclude1,exclude2",
        "public_folder_location": "public1,public2",
        "share_point_location": "sharepoint1,sharepoint2",
        "share_point_location_exclusion": "exclude1,exclude2",
        "polling_interval": "15",
        "polling_timeout": "300",
    }

    expected_args = {
        "search_name": "test search",
        "force": True,
        "preview": False,
        "case": "test case",
        "kql_search": "test search",
        "include_mailboxes": True,
        "exchange_location": ["exchange1", "exchange2"],
        "exchange_location_exclusion": ["exclude1", "exclude2"],
        "public_folder_location": ["public1", "public2"],
        "share_point_location": ["sharepoint1", "sharepoint2"],
        "share_point_location_exclusion": ["exclude1", "exclude2"],
        "polling_interval": 15,
        "polling_timeout": 300,
    }

    assert expected_args == parse_args(args)


def test_get_result_value():
    """
    Given:
       - The integration, CommandResults, key name, value
    When:
       - Parsing the CommandResults
    Then:
       - The value for the given key
    """

    from O365SecurityComplianceSearch import get_result_value

    cmd_result = [{"Contents": {"OuterKey": {"InnerKey": "Value"}}}]
    expected_value = "Value"

    assert get_result_value(cmd_result, "OuterKey.InnerKey") == expected_value  # type: ignore


def test_add_to_context():
    """
    Given:
       - The integration, context, sub-key name, value
    When:
       - Adding values to context
    Then:
       - The updated context
    """

    from O365SecurityComplianceSearch import add_to_context

    context = {"Search": {}, "Preview": {}}

    expected_context = {
        "Search": {"Name": "search name", "Results": "search results"},
        "Preview": {"Name": "preview name", "Results": "preview results"},
    }

    add_to_context(context=context, sub_key="Search", new_key="Name", new_value="search name")
    add_to_context(context=context, sub_key="Search", new_key="Results", new_value="search results")
    add_to_context(context=context, sub_key="Preview", new_key="Name", new_value="preview name")
    add_to_context(context=context, sub_key="Preview", new_key="Results", new_value="preview results")

    assert expected_context == context


def test_wait_for_results(mocker):
    """
    Given:
       - The integration, args, search command, results
    When:
       - Waiting for search results
    Then:
       - The search results
    """

    from O365SecurityComplianceSearch import wait_for_results

    args = {"polling_interval": 2, "polling_timeout": 10}

    expected_results = [{"Contents": {"Status": "Completed", "SuccessResults": '{Location: "location",Count: 10}'}}]

    mocker.patch.object(demisto, "executeCommand", return_value=expected_results)
    mock_results = wait_for_results(args=args, cmd="o365-sc-get-search", result_key="SuccessResults")

    assert mock_results == expected_results
