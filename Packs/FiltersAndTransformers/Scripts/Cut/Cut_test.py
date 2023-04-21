from Cut import cut

import pytest
import demistomock as demisto
from Cut import main


@pytest.mark.parametrize('value,delimiter,fields,expected', [
    ('A-B-C-D-E', '-', '1,5', 'A-E'),
    ('a,ב,c', ',', '2,3', 'ב,c'),
])
def test_cut(value, delimiter, fields, expected):
    """
    Given:
        Case 1: A-B-C-D-E to split by - from char 1 to 5
        Case 2: a,ב,c to split by , from char 2 to 3

    When:
        Running Cut

    Then:
        Case 1: Ensure A-E is returned
        Case 2: Ensure ב,c is returned
    """
    assert cut(value, fields, delimiter) == expected


@pytest.mark.parametrize('args, expected', [
    ({'value': 'a,ב,c', 'delimiter': ',', 'fields': '2,3'}, 'ב,c'),
])
def test_cut_main(mocker, args, expected):
    """
    Given:
        a,ב,c to split by , from char 2 to 3.
    When:
        Running Cut script.
    Then:
        demisto.results called.
    """
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == expected
