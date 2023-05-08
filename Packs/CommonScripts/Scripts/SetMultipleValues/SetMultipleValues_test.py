import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from SetMultipleValues import main
import pytest


def test_main(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the main function.
    Then:
        - Validating the outputs as expected.
    """
    results_mock = mocker.patch.object(demisto, 'results')
    args = {
        'keys': 'a,b,c',
        'values': '1,2,3',
        'parent': 'Test'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    main()
    assert results_mock.call_args[0][0]['Contents'] == {'Test(true)': {'a': '1', 'b': '2', 'c': '3'}}


@pytest.mark.parametrize("keys, values, expected_result", [
    (
        "array1,array2",
        '["1.1.1.1","8.8.8.8"],["test@gmail.com", "google.com"]',
        {'array1': ['1.1.1.1', '8.8.8.8'], 'array2': ['test@gmail.com', 'google.com']}
    ),
    (
        "array,val",
        '["1.1.1.1","8.8.8.8"], "test_val"',
        {'array': ['1.1.1.1', '8.8.8.8'], 'val': "test_val"}),
])
def test_arrays_as_values(mocker, keys, values, expected_result):
    """
    Given:
        -  The script args (values = string contains arrays)
    When:
        - Running the main function.
    Then:
        - Validating the outputs as expected.
    """
    results_mock = mocker.patch.object(demisto, 'results')
    args = {
        'keys': keys,
        'values': values,
        'parent': 'Test'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    main()
    assert results_mock.call_args[0][0]['Contents'] == {'Test(true)': expected_result}
