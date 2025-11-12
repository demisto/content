from pytest_mock import MockerFixture
from PANOSQueryLogs import main


def test_main(mocker: MockerFixture):
    """
    Given:
        Command args.
    When:
        Calling `main`.
    Assert:
        Ensure `execute_polling_command` is called once with the correct command name and args.
    """

    args = {"log-type": "traffic", "number_of_logs": 1}
    mocker.patch("PANOSQueryLogs.demisto.args", return_value=args)
    mock_execute_polling_command = mocker.patch("PANOSQueryLogs.execute_polling_command", return_value=[])

    main()

    assert mock_execute_polling_command.call_count == 1
    assert mock_execute_polling_command.call_args[0] == ("pan-os-query-logs", args)


def test_url_log_query(mocker: MockerFixture):
    """
    Given:
        URL category log query arguments
    When:
        Calling `main` with URL category
    Assert:
        Ensure URL category is correctly formatted and query is constructed
    """
    args = {"log_type": "url", "url_category": "Command and Control"}
    mocker.patch("PANOSQueryLogs.demisto.args", return_value=args)
    mock_execute_polling_command = mocker.patch("PANOSQueryLogs.execute_polling_command", return_value=[])

    main()

    assert mock_execute_polling_command.call_args[0][1]["query"] == "url_category_list contains 'command-and-control'"


def test_invalid_input_url_log_query(mocker: MockerFixture):
    """
    Given:
        Invalid URL category log query arguments
    When:
        Calling `main` with invalid URL category
    Assert:
        Ensure ValueError is raised for incorrect URL category
    """
    invalid_test_cases = [("Invalid Category", "url"), ("Artificial Intelligence", "traffic")]

    for url_category, log_type in invalid_test_cases:
        args = {"log_type": log_type, "url_category": url_category}
        mocker.patch("PANOSQueryLogs.demisto.args", return_value=args)
        mocker.patch("PANOSQueryLogs.execute_polling_command", return_value=[])
        mock_return_error = mocker.patch("PANOSQueryLogs.return_error")

        main()

        # Check that return_error was called with the expected message
        assert mock_return_error.called
        error_message = mock_return_error.call_args[0][0]
        assert (
            "Invalid URL category" in error_message
            or "url_category arg is only valid for querying with log_type url" in error_message
        )
