import demistomock as demisto
from ExportIndicatorsToCSV import main

side_effect = iter([[{"Contents": {"response": "test-file-id"}}], [{"Contents": {"response": b"123"}}]])


def test_main(mocker):
    mocker.patch.object(demisto, "args", return_value={"query": "html", "seenDays": "6", "columns": "id,name"})
    mocker.patch.object(demisto, "results", return_value={})
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=side_effect)
    main()
    assert execute_command_mock.call_args_list[0][0][1]["body"]["columns"] == ["id", "name"]


def test_main_with_error_response(mocker):
    """Test handling of error responses from executeCommand"""
    mocker.patch.object(demisto, "args", return_value={"query": "html", "seenDays": "6", "columns": "id,name"})
    # Simulate an error response (string instead of dict)
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 4, "Contents": "Error message"}])

    return_error_mock = mocker.patch("ExportIndicatorsToCSV.return_error")

    main()
    assert return_error_mock.called


def test_main_with_invalid_seen_days(mocker):
    """Test handling of invalid seenDays parameter"""
    mocker.patch.object(demisto, "args", return_value={"query": "html", "seenDays": "invalid", "columns": "id,name"})
    mocker.patch.object(demisto, "results", return_value={})
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=side_effect)

    main()
    # Should use default value of 7 days
    assert execute_command_mock.call_args_list[0][0][1]["body"]["filter"]["period"]["fromValue"] == 7
