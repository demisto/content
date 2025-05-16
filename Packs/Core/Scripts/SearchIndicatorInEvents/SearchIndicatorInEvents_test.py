def test_retrieve_data_from_xdr_sanity_check(mocker):
    """
    Given:
    - All the required args

    When:
    - Executing retrieve_data_from_xdr function (first case of executing query)

    Then:
    - Ensure executeCommand was called once
    - Ensure the correct args were sent in executeCommand call
    - Ensure shorten_text function generated a correct output (a part of the query's check)
    """

    # Mock input arguments
    args = {"time_frame": "7 days", "indicator": "1.2.3.4", "query_name": "Test Query", "data_set": "xdr_data"}

    # Mock return values
    initial_response = [
        {"Contents": {"status": "PENDING"}, "Metadata": {"pollingArgs": {"query_id": "abc123", "query_name": "TEST"}}}
    ]
    completed_response = [{"Contents": {"status": "COMPLETED"}, "HumanReadable": "Query results here"}]

    # Patching dependencies
    mock_execute = mocker.patch(
        "SearchIndicatorInEvents.demisto.executeCommand", side_effect=[initial_response, completed_response]
    )

    from SearchIndicatorInEvents import retrieve_data_from_xdr

    poll_result = retrieve_data_from_xdr(args)

    assert mock_execute.call_count == 1
    assert mock_execute.mock_calls[0][2]["args"]["query"] == 'config timeframe = 7d | search "1.2.3.4" dataset = xdr_data'
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
    completed_response = [{"Contents": {"status": "COMPLETED", "results": []}}]

    # Patching dependencies
    mock_execute = mocker.patch("SearchIndicatorInEvents.demisto.executeCommand", side_effect=[completed_response])

    from SearchIndicatorInEvents import retrieve_data_from_xdr

    poll_result = retrieve_data_from_xdr(args)

    assert mock_execute.call_count == 1
    assert mock_execute.mock_calls[0][2]["args"] == {"query_id": "abc123"}
    assert mock_execute.mock_calls[0][2]["command"] == "xdr-xql-get-query-results"
    assert poll_result.readable_output == "job ID abc123 is finished!"
