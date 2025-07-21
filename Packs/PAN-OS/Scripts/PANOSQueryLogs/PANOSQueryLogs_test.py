from pytest_mock import MockerFixture


def test_main(mocker: MockerFixture):
    """
    Given:
        Command args.
    When:
        Calling `main`.
    Assert:
        Ensure `execute_polling_command` is called once with the correct command name and args.
    """
    from PANOSQueryLogs import main

    args = {"log-type": "traffic", "number_of_logs": 1}
    mocker.patch("PANOSQueryLogs.demisto.args", return_value=args)
    mock_execute_polling_command = mocker.patch("PANOSQueryLogs.execute_polling_command", return_value=[])

    main()

    assert mock_execute_polling_command.call_count == 1
    assert mock_execute_polling_command.call_args[0] == ("pan-os-query-logs", args)
