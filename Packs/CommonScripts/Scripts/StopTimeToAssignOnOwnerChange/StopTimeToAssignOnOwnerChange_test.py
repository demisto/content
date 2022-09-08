import pytest
import demistomock as demisto


@pytest.mark.parametrize('args, expected_results', [
    ({}, None), ({'old': "yes"}, None), ({'old': "yes", "new": "yes"}, None),
    ({"new": "yes"}, "Assignment of the incident was successful and so the Time To Assignment timer has been stopped.")
])
def test_get_results(mocker, args, expected_results):
    """
    Given
    - case 1: get_results function args, including False 'feDone' argument and empty profiles list.
    - case 2: get_results function args, succesful fe-submit-result response mock with "Contents.alerts.alert" section.
    - case 2: get_results function args, succesful fe-submit-result response mock without "Contents.alerts.alert" section.
    - case 2: get_results function args, an errored fe-submit-result response mock.
    When
    - Running get_results function.
    Then
    - Ensure the right results were given and that the function paused the execution.
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
