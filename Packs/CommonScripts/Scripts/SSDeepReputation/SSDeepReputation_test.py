import demistomock as demisto


def test_ssdeep_reputation_test_not_found(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the command.
    Then:
        - Validating the outputs as expected.
    """
    from SSDeepReputation import main
    args = {'input': '1'}
    mocker.patch.object(demisto, 'args', return_value=args)
    execute_command_res = [{'Contents': []}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    main()
    assert execute_mock.call_count == 3
