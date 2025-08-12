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
    test_cases = [
        ("", "url_category_list contains ''"),
        ("AI", "url_category_list contains 'AI'"),
        ("A", "url_category_list contains 'a'"),
        ("AI Gaming", "url_category_list contains 'AI-gaming'"),
        ("Multiple  Spaces", "url_category_list contains 'multiple--spaces'"),
        ("Special-Characters_Test", "url_category_list contains 'special-characters_test'"),
    ]

    # args = {"log_type": "url", "url_category": "AI Conversational Assistant"}
    for url_category, expected_query in test_cases:
        args = {"log_type": "url", "url_category": url_category}
        mocker.patch("PANOSQueryLogs.demisto.args", return_value=args)
        mock_execute_polling_command = mocker.patch("PANOSQueryLogs.execute_polling_command", return_value=[])
    
        main()
    
        assert mock_execute_polling_command.call_args[0][1]["query"] == expected_query