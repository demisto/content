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
    from CsFalconLiftHostContainment import main

    args = {"ids": "agentA,agentB"}
    mocker.patch("CsFalconLiftHostContainment.demisto.args", return_value=args)
    mock_execute_polling_command = mocker.patch("CsFalconLiftHostContainment.execute_polling_command", return_value=[])

    main()

    assert mock_execute_polling_command.call_count == 1
    assert mock_execute_polling_command.call_args[0] == ("cs-falcon-lift-host-containment", args)
