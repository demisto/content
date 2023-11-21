import pytest
import demistomock as demisto


@pytest.mark.parametrize('args, expected_results', [
    ({}, None), ({'old': "yes"}, None), ({'old': "yes", "new": "yes"}, None),
    ({"new": "yes"}, "Assignment of the incident was successful and so the Time To Assignment timer has been stopped.")
])
def test_get_results(mocker, args, expected_results):
    """
    Given
    - case 1: Empty args.
    - case 2: args only with 'old' key.
    - case 3: Empty with both 'old' and 'new' key.
    - case 4: args with only 'new' key.
    When
    - Running StopTimeToAssignOnOwnerChange script.
    Then
    - Ensure the right results were given.
    - case 1: No results.
    - case 2: No results.
    - case 3: No results.
    - case 4: should results: "Assignment of the incident was successful and so the Time To Assignment timer has been stopped."
    """
    from StopTimeToAssignOnOwnerChange import main
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'executeCommand', return_value=None)
    main()
    res = demisto.results.call_args
    if not res:
        assert res == expected_results
    else:
        assert res[0][0] == expected_results
