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
