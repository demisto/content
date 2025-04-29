
def test_search_for_indicator(mocker):
    """
    Given:
    - All the required args

    When:
    - Executing search_for_indicator function.

    Then:
    - Ensure executeCommand was called twice.
    - Ensure the correct args were sent in every executeCommand call
    - Ensure shorten_text function generated a correct output (a part of the query's check)
    """

    # Mock input arguments
    args = {
        "time_frame": "7 days",
        "indicator": "1.2.3.4",
        "query_name": "Test Query",
        "data_set": "xdr_data"
    }

    # Mock return values
    initial_response = [{
        "Contents": {"status": "PENDING"},
        "Metadata": {"pollingArgs": {"query_id": "abc123"}}
    }]
    completed_response = [{
        "Contents": {"status": "COMPLETED"},
        "HumanReadable": "Query results here"
    }]

    # Patching dependencies
    mock_execute = mocker.patch("AgentixRetrieveData.demisto.executeCommand", side_effect=[initial_response, completed_response])
    mock_results = mocker.patch("AgentixRetrieveData.return_results")
    mocker.patch("AgentixRetrieveData.sleep", return_value=None)

    from AgentixRetrieveData import search_for_indicator
    search_for_indicator(args)

    assert mock_execute.call_count == 2
    assert mock_execute.mock_calls[0][2]['args']['query'] == 'config timeframe = 7d | search "1.2.3.4" dataset = xdr_data'
    assert mock_execute.mock_calls[1][2]['args'] == {'query_id': 'abc123'}
    mock_results.assert_called_once_with(completed_response)