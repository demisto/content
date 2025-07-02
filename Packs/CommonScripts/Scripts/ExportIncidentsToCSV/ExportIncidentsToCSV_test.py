import demistomock as demisto
import pytest
from ExportIncidentsToCSV import main


def test_main(mocker):
    side_effect = iter([[{"Contents": {"response": {"test": "test"}}}], [{"Contents": {"response": b"123"}}]])
    mocker.patch.object(demisto, "args", return_value={"query": "html", "fetchdays": "6", "columns": "id,name"})
    mocker.patch.object(demisto, "results", return_value={})
    mocker.patch("ExportIncidentsToCSV.is_error", return_value=False)
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=side_effect)
    main()
    assert execute_command_mock.call_args_list[0][0][1]["body"]["columns"] == ["id", "name"]


def test_main_error(mocker):
    side_effect = iter([[{"Contents": {"response": {"test": "test"}}}], Exception("error")])
    mocker.patch.object(demisto, "args", return_value={"query": "html", "fetchdays": "6"})
    mocker.patch.object(demisto, "results", return_value={})
    mocker.patch("ExportIncidentsToCSV.is_error", return_value=True)
    mocker.patch("ExportIncidentsToCSV.get_error", return_value="error")
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "executeCommand", side_effect=side_effect)
    with pytest.raises(Exception):
        main()


def test_no_incidents_found(mocker):
    """
    Given: NO_INCIDENTS_FOUND global string
    When: The main() function is called and no incidents are found
    Then: The NO_INCIDENTS_FOUND message is expected to be called as a result within the results object,
     and the call count for results is expected to be 1.
    """

    from ExportIncidentsToCSV import main, NO_INCIDENTS_FOUND
    export_to_csv_result = [{'Contents': ' - Script failed to run: Core REST APIs - '
                                         '"Status":"400 Bad Request "title": "Incidents search returned no results" '}]
    mocker.patch.object(demisto, "args", return_value={"query": "html", "fetchdays": "6"})
    mocker.patch.object(demisto, "executeCommand", return_value=export_to_csv_result)
    mocker.patch("ExportIncidentsToCSV.is_error", return_value=True)
    mocker.patch.object(demisto, "results")
    main()
    demisto.results.assert_called_once_with(NO_INCIDENTS_FOUND)
    assert demisto.results.call_count == 1


def test_incidents_amount_limit_exceeded(mocker):
    """
    Given: LIMIT_EXCEEDED global string
    When: The main() function is called and the incidents amount exceeded the limit
    Then: The LIMIT_EXCEEDED message is expected to be called as a result within the results object,
     and the call count for results is expected to be 1.
    """

    from ExportIncidentsToCSV import main, LIMIT_EXCEEDED
    export_to_csv_result = [{'Contents': ' - Script failed to run: Core REST APIs - '
                                         '"StatusCode":413, title\":\"Limit Exceeded\" '}]
    mocker.patch.object(demisto, "args", return_value={"query": "html", "fetchdays": "6"})
    mocker.patch.object(demisto, "executeCommand", return_value=export_to_csv_result)
    mocker.patch("ExportIncidentsToCSV.is_error", return_value=True)
    return_error_mock = mocker.patch("ExportIncidentsToCSV.return_error")
    main()
    expected_error_message = f"{LIMIT_EXCEEDED} (10,000 incidents). Try to run the same query with lower fetchdays value"
    return_error_mock.assert_called_once_with(expected_error_message)
    assert return_error_mock.call_count == 1


def test_general_error_occurred(mocker):
    """
    Given: None
    When: The main() function is called and general error returned as response from executeCommand
    Then: ValueError is expected to be raised
    """

    from ExportIncidentsToCSV import main
    export_to_csv_result = [{'Contents': ' - Script failed to run: Core REST APIs - '}]
    mocker.patch.object(demisto, "args", return_value={"query": "html", "fetchdays": "6"})
    mocker.patch.object(demisto, "executeCommand", return_value=export_to_csv_result)
    mocker.patch("ExportIncidentsToCSV.is_error", return_value=True)
    with pytest.raises(ValueError) as ve:
        main()
        assert "Couldn't export incidents to CSV." in str(ve)


def test_execute_command_empty_response(mocker):
    """
    Given: None
    When: The main() function is called and general error occurred when executing executeCommand
    Then: ValueError is expected to be raised
    """

    from ExportIncidentsToCSV import main
    mocker.patch.object(demisto, "args", return_value={"query": "html", "fetchdays": "6"})
    mocker.patch.object(demisto, "executeCommand", return_value=[])
    with pytest.raises(ValueError) as ve:
        main()
        assert "when trying to export incident(s) with query" in str(ve)