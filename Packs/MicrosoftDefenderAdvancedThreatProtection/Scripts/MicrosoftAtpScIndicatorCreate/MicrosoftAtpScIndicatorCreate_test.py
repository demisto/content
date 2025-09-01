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
    from MicrosoftAtpScIndicatorCreate import main

    args = {"indicator_type": "Url", "indicator_value": "example.com", "action": "Allowed"}
    mocker.patch("MicrosoftAtpScIndicatorCreate.demisto.args", return_value=args)
    mock_execute_polling_command = mocker.patch("MicrosoftAtpScIndicatorCreate.execute_polling_command", return_value=[])

    main()

    assert mock_execute_polling_command.call_count == 1
    assert mock_execute_polling_command.call_args[0] == ("microsoft-atp-sc-indicator-create", args)
