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
    from MicrosoftAtpEndpoint import main, INTEGRATION_NAME

    args = {"ip": "0.0.0.0"}
    mocker.patch("MicrosoftAtpEndpoint.demisto.args", return_value=args)
    mock_execute_polling_command = mocker.patch("MicrosoftAtpEndpoint.execute_polling_command", return_value=[])

    main()

    assert mock_execute_polling_command.call_count == 1
    assert mock_execute_polling_command.call_args[0] == ("endpoint", args)
    assert mock_execute_polling_command.call_args.kwargs["using_brand"] == INTEGRATION_NAME
