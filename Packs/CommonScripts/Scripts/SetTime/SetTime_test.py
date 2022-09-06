import demistomock as demisto


def test_set_time(mocker):
    """
    Given:
        - The script args.

    When:
        - Running the set_time function.

    Then:
        - Validating the outputs as expected.
    """
    from SetTime import set_time
    mocker.patch.object(demisto, 'args', return_value={'fieldName': 'field'})
    mocker.patch.object(demisto, 'setContext')
    execute_mock = mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'results')
    set_time()
    assert execute_mock.call_count == 1
