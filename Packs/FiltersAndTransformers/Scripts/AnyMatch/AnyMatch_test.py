import pytest
import demistomock as demisto
from AnyMatch import main

# Note: left and right can be all types, and in order to test list as an input we use a string that looks like a list,
# a comma separated string that will be converted to a list in the script.

# Note: When executing the filter within playbooks, a JSON on the left will be treated as a single long string, as designed.
# There is an example for that in the TestPlaybook.
# However, during testing, I encountered difficulty reproducing that behavior. In the test environment,
# a JSON containing a comma will be separated into two strings.


@pytest.mark.parametrize('left,right,expected_result', [
    ("2", "25,10", "No matches found."),
    ("'2'", "1,2,3", ["'2'"]),    # 2 is part of '2'
    ("'abc','aha','a'", "A", ["'abc'", "'a'", "'aha'"]),
    ("5,1,6,9,65,8,b", "1,'6'", ['1']),  # no part of 6 or 65 is in the list: 1,'6'
    ('a', "kfjua", "No matches found."),
    ("bca", "A", ["bca"]),  # case insensitive
    ("ABC", "a", ["ABC"]),  # case insensitive
    ('{"alert": {"data": "x"}}', "x", ['{"alert": {"data": "x"}}']),
    ("{'a':1,'c':2}", "{'a': 1}, {'b': 2}", "No matches found."),     # {'a':1} is not a part of {'a':1, or 'c':2}
    ("{'a': 1}, {'b': 2}", "{a:1}", "No matches found."),  # {a:1} is not a part of {'a': 1} or {'b': 2}
    # although '' is not a part of {'a':1,'c':2}, but ' is in {'a': 1 and in  'c': 2}
    ("{'a':1,'c':2}", "'', '", ["{'a':1", "'c':2}"]),
    # one of the arguments is missing -> return empty list
    ("1,2", "", "No matches found.")
])
def test_main(mocker, left, right, expected_result):
    """
    Given:
        left and right arguments.
    When:
        Running AnyMatch script.
    Then:
        Validate the results are as expected.
    """
    mocker.patch.object(demisto, 'args', return_value={'left': left, 'right': right})
    mocker.patch.object(demisto, 'results')
    main()
    # assert demisto.results.call_count == call_count
    results = demisto.results.call_args_list[0][0][0]
    assert len(results) == len(expected_result)
    for res in results:
        assert res in expected_result
    # assert results == expected_result
    # assert results == expected_result
    # for i in range(len(expected_result)):
    #     results = demisto.results.call_args_list[i][0][0]
    #     assert results[i] == expected_result[i]
