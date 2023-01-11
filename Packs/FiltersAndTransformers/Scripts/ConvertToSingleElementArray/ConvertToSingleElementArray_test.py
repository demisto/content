import pytest
import demistomock as demisto
from ConvertToSingleElementArray import main


@pytest.mark.parametrize('args,expected_result', [
    ({'value': ''}, []),
    ({'value': ['1', '2']}, ['1', '2']),
    ({'value': '1'}, ['1']),
])
def test_main(mocker, args, expected_result):
    """
    Given:
        Case 1: value is ''.
        Case 2: value is a list ['1','2'].
        Case 3: value not empty.
    When:
        Running ConvertToSingleElementArray script.
    Then:
        Case 1: Ensure [] is returned
        Case 2: Ensure ['1', '2'] is returned
        Case 3: Ensure ['1'] is returned
    """
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    assert demisto.results.call_count == 1
    assert results == expected_result
