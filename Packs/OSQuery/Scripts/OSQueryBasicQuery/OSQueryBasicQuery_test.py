import demistomock as demisto


def test_OSQueryBasicQuery(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the OSQueryBasicQuery script.
    Then:
        - Validating the outputs as expected.
    """
    from OSQueryBasicQuery import main

    args_mock = mocker.patch.object(demisto, 'args', return_value={'system': 'system', 'query': 'query'})  # noqa: F841
    execute_command_res = [{'Type': 4, 'Contents': 'Error', 'Brand': 'brand'}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, 'results')
    main()

    assert execute_mock.call_count == 1
    assert 'An Error occurred on remote system' in results_mock.call_args[0][0][0]['Contents']
