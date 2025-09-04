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

    from O365SecurityComplianceSearch import O365SearchRunner

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

    search_runner = O365SearchRunner(args=args, modules={})
    assert expected_args == search_runner.args


def test_add_to_context():
    """
    Given:
       - The integration, context, sub-key name, value
    When:
       - Adding values to context
    Then:
       - The updated context
    """

    from O365SecurityComplianceSearch import O365SearchRunner

    expected_context = {
        "Search": {"Name": "search name", "Results": "search results"},
        "Preview": {"Name": "preview name", "Results": "preview results"},
    }

    search_runner = O365SearchRunner(args={}, modules={})
    search_runner._add_to_context(sub_key="Search", new_key="Name", new_value="search name")
    search_runner._add_to_context(sub_key="Search", new_key="Results", new_value="search results")
    search_runner._add_to_context(sub_key="Preview", new_key="Name", new_value="preview name")
    search_runner._add_to_context(sub_key="Preview", new_key="Results", new_value="preview results")

    assert expected_context == search_runner.context


def test_wait_for_results(mocker):
    """
    Given:
       - The integration, args, search command, results
    When:
       - Waiting for search results
    Then:
       - The search results
    """

    from O365SecurityComplianceSearch import O365SearchRunner

    search_runner = O365SearchRunner(args={"polling_interval": 2, "polling_timeout": 10}, modules={})

    execute_command_results = [
        {"Type": 1, "Contents": {"Status": "Completed", "SuccessResults": '{Location: "location",Count: 10}'}}
    ]
    expected_results = {"Status": "Completed", "SuccessResults": '{Location: "location",Count: 10}'}

    mocker.patch.object(demisto, "executeCommand", return_value=execute_command_results)
    mock_results = search_runner._wait_for_results(cmd="o365-sc-get-search")

    assert mock_results == expected_results
