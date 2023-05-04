import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from SetMultipleValues import main


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


def test_arrays_as_values(mocker):
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
        'keys': 'array1,array2',
        'values': '["1.1.1.1","8.8.8.8"],["test@gmail.com", "google.com"]',
        'parent': 'Test'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    main()
    assert results_mock.call_args[0][0]['Contents'] == {'Test(true)': {'array1': ['1.1.1.1', '8.8.8.8'],
                                                                       'array2': ['test@gmail.com', 'google.com']}}
