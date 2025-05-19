from unittest.mock import patch


@patch("demistomock.executeCommand")
@patch("CommonServerPython.return_results")
def test_main(mock_return_results, mock_execute_command):
    mock_table_content = "TABLE"
    from Code42FileEventsToMarkdownTable import main

    mock_execute_command.return_value = [{"HumanReadable": mock_table_content}]
    main()
    mock_return_results.assert_called_with({"Type": 1, "Contents": mock_table_content, "ContentsFormat": "markdown"})
