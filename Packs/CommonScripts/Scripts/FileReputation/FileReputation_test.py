import demistomock as demisto


def test_file_reputation(mocker):
    """
    Given:
        - The script args.

    When:
        - Running the file_reputation function.

    Then:
        - Validating the outputs as expected.
    """
    from FileReputation import file_reputation
    mocker.patch.object(demisto, 'args', return_value={'file': 'somefile'})
    execute_command_res = [{'Type': 4, 'Contents': 'Error', 'Brand': 'brand'}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, 'results')
    file_reputation()
    assert execute_mock.call_count == 1
    assert 'returned an error' in results_mock.call_args[0][0][0]['Contents']
