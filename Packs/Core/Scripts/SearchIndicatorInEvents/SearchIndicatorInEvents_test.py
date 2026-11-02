def test_retrieve_data_from_xdr_sanity_check(mocker):
    """
    Given:
        All the required args.
    When:
        Executing retrieve_data_from_xdr function (first case of executing query).
    Then:
        Ensure executeCommand was called once with the correct query and time_frame args.
    """

    # Mock input arguments
    args = {"time_frame": "7 days", "indicator": "1.2.3.4", "query_name": "Test Query", "data_set": "xdr_data"}

    # Mock return values
    initial_response = [
        {"Type": 1, "Contents": {"status": "PENDING"}, "Metadata": {"pollingArgs": {"query_id": "abc123", "query_name": "TEST"}}}
    ]
    completed_response = [{"Type": 1, "Contents": {"status": "COMPLETED"}, "HumanReadable": "Query results here"}]

    # Patching dependencies
    mock_execute = mocker.patch(
        "SearchIndicatorInEvents.demisto.executeCommand", side_effect=[initial_response, completed_response]
    )

    from SearchIndicatorInEvents import retrieve_data_from_xdr

    poll_result = retrieve_data_from_xdr(args)

    assert mock_execute.call_count == 1
    call_args = mock_execute.mock_calls[0][2]["args"]
    assert call_args["query"] == 'search "1.2.3.4" dataset = xdr_data'
    assert call_args["time_frame"] == "7 days"
    assert poll_result.scheduled_command._args["query_id"] == "abc123"


def test_check_status(mocker):
    """
    Given:
    - All the required args

    When:
    - Executing retrieve_data_from_xdr function (second case of checking status)

    Then:
    - Ensure executeCommand was called once
    - Ensure the correct args were sent in executeCommand call, query_id and the right command
    - Ensure the readable_output is correct
    """

    # Mock input arguments
    args = {
        "time_frame": "7 days",
        "indicator": "1.2.3.4",
        "query_name": "Test Query",
        "data_set": "xdr_data",
        "query_id": "abc123",
    }

    # Mock return values
    completed_response = [{"Type": 1, "Contents": {"status": "COMPLETED", "results": []}}]

    # Patching dependencies
    mock_execute = mocker.patch("SearchIndicatorInEvents.demisto.executeCommand", side_effect=[completed_response])

    from SearchIndicatorInEvents import retrieve_data_from_xdr

    poll_result = retrieve_data_from_xdr(args)

    assert mock_execute.call_count == 1
    assert mock_execute.mock_calls[0][2]["args"] == {"query_id": "abc123"}
    assert mock_execute.mock_calls[0][2]["command"] == "xdr-xql-get-query-results"
    assert poll_result.readable_output == "job ID abc123 is finished!"


PLATFORM_ARGS = {"time_frame": "7 days", "indicator": "1.2.3.4", "query_name": "Test Query", "data_set": "xdr_data"}


def test_run_platform_query_success(mocker):
    """
    Given:
    - All the required args and a successful runXQLQuery response.

    When:
    - Executing run_platform_query (platform path).

    Then:
    - Ensure runXQLQuery is called once with the expected args (wait_for_results=true).
    - Ensure the results are extracted from GenericXQLQuery and returned under PaloAltoNetworksXQL.
    """
    results = [{"agent_hostname": "host1", "action_local_ip": "1.2.3.4"}]
    response = [
        {
            "Type": 1,
            "EntryContext": {"GenericXQLQuery": {"execution_id": "e1", "status": "SUCCESS", "results": results}},
        }
    ]
    mock_execute = mocker.patch("SearchIndicatorInEvents.demisto.executeCommand", return_value=response)

    from SearchIndicatorInEvents import run_platform_query

    command_results = run_platform_query(PLATFORM_ARGS)

    mock_execute.assert_called_once_with(
        "runXQLQuery",
        {
            "query": 'search "1.2.3.4" dataset = xdr_data',
            "query_name": "Test Query",
            "timeframe": "7 days",
            "wait_for_results": "true",
            "interval_in_seconds": "30",
            "timeout_in_seconds": "600",
        },
    )
    assert command_results.outputs == results
    assert command_results.outputs_prefix == "PaloAltoNetworksXQL"
    assert "host1" in command_results.readable_output


def test_run_platform_query_custom_polling_args_and_escaping(mocker):
    """
    Given:
    - An indicator containing quotes and backslashes, and custom interval/timeout args.

    When:
    - Executing run_platform_query.

    Then:
    - Ensure the indicator is escaped in the query and the polling args are passed through.
    - Ensure empty results produce an empty output list.
    """
    args = PLATFORM_ARGS | {"indicator": 'a"b\\c', "interval_in_seconds": "5", "timeout_in_seconds": "60"}
    response = [{"Type": 1, "EntryContext": {"GenericXQLQuery": {"status": "SUCCESS"}}}]
    mock_execute = mocker.patch("SearchIndicatorInEvents.demisto.executeCommand", return_value=response)

    from SearchIndicatorInEvents import run_platform_query

    command_results = run_platform_query(args)

    sent_args = mock_execute.call_args[0][1]
    assert sent_args["query"] == 'search "a\\"b\\\\c" dataset = xdr_data'
    assert sent_args["interval_in_seconds"] == "5"
    assert sent_args["timeout_in_seconds"] == "60"
    assert command_results.outputs == []


def test_run_platform_query_fail_status(mocker):
    """
    Given:
    - A runXQLQuery error entry whose GenericXQLQuery status is FAIL, with the formatted message in Contents.

    When:
    - Executing run_platform_query.

    Then:
    - Ensure a DemistoException with the clean formatted error message is raised.
    """
    import re
    import pytest
    from CommonServerPython import DemistoException

    error_message = "XQL query 'Test Query' failed with status FAIL. Error: Syntax error"
    response = [
        {
            "Type": 4,
            "Contents": error_message,
            "EntryContext": {"GenericXQLQuery": {"status": "FAIL", "error_details": {"error": {"err_msg": "Syntax error"}}}},
        }
    ]
    mocker.patch("SearchIndicatorInEvents.demisto.executeCommand", return_value=response)

    from SearchIndicatorInEvents import run_platform_query

    with pytest.raises(DemistoException, match=f"^{re.escape(f'XQL query failed: {error_message}')}$"):
        run_platform_query(PLATFORM_ARGS)


def test_run_platform_query_not_completed(mocker):
    """
    Given:
    - A runXQLQuery "Running XQL query:" entry with an empty EntryContext (query still running).

    When:
    - Executing run_platform_query.

    Then:
    - Ensure a DemistoException is raised instead of returning an empty result.
    """
    import pytest
    from CommonServerPython import DemistoException

    response = [{"Type": 1, "Contents": None, "HumanReadable": "Running XQL query: abc", "EntryContext": {}}]
    mocker.patch("SearchIndicatorInEvents.demisto.executeCommand", return_value=response)

    from SearchIndicatorInEvents import run_platform_query

    with pytest.raises(DemistoException, match=r"XQL query did not complete \(status: unknown\)\."):
        run_platform_query(PLATFORM_ARGS)


def test_run_platform_query_error_entry(mocker):
    """
    Given:
    - A runXQLQuery error entry without query outputs (e.g. API error).

    When:
    - Executing run_platform_query.

    Then:
    - Ensure a DemistoException with the error message is raised.
    """
    import pytest
    from CommonServerPython import DemistoException

    response = [{"Type": 4, "Contents": "API Error: unauthorized"}]
    mocker.patch("SearchIndicatorInEvents.demisto.executeCommand", return_value=response)

    from SearchIndicatorInEvents import run_platform_query

    with pytest.raises(DemistoException, match="Failed to execute query: API Error: unauthorized"):
        run_platform_query(PLATFORM_ARGS)


def test_run_dispatches_to_runxqlquery_on_platform(mocker):
    """
    Given:
    - The script runs on the Cortex platform (is_platform returns True).

    When:
    - Executing run.

    Then:
    - Ensure the runXQLQuery built-in command is used.
    """
    response = [{"Type": 1, "EntryContext": {"GenericXQLQuery": {"status": "SUCCESS", "results": []}}}]
    mocker.patch("SearchIndicatorInEvents.is_platform", return_value=True)
    mock_execute = mocker.patch("SearchIndicatorInEvents.demisto.executeCommand", return_value=response)

    from SearchIndicatorInEvents import run

    run(PLATFORM_ARGS)

    assert mock_execute.call_count == 1
    assert mock_execute.call_args[0][0] == "runXQLQuery"


def test_run_dispatches_to_legacy_query_off_platform(mocker):
    """
    Given:
    - The script does not run on the Cortex platform (is_platform returns False).

    When:
    - Executing run.

    Then:
    - Ensure the legacy xdr-xql-generic-query polling path is used.
    """
    response = [
        {"Type": 1, "Contents": {"status": "PENDING"}, "Metadata": {"pollingArgs": {"query_id": "abc123", "query_name": "TEST"}}}
    ]
    mocker.patch("SearchIndicatorInEvents.is_platform", return_value=False)
    mock_execute = mocker.patch("SearchIndicatorInEvents.demisto.executeCommand", return_value=response)

    from SearchIndicatorInEvents import run

    run(PLATFORM_ARGS)

    assert mock_execute.call_count == 1
    assert mock_execute.call_args[1]["command"] == "xdr-xql-generic-query"


def test_extract_xql_outputs_missing_context():
    """
    Given:
    - Responses without a GenericXQLQuery context.

    When:
    - Executing extract_xql_outputs.

    Then:
    - Ensure an empty dict is returned.
    """
    from SearchIndicatorInEvents import extract_xql_outputs

    assert extract_xql_outputs([]) == {}
    assert extract_xql_outputs([{"Type": 1}]) == {}
    assert extract_xql_outputs([{"Type": 1, "EntryContext": {"Other": {}}}]) == {}
