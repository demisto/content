import pytest
import demistomock as demisto
from AnyMatch import main

# Note: left and right can be all types, and in order to test list as an input we use a string that looks like a list,
# a comma separated string that will be converted to a list in the script.

# Note: When executing the filter within playbooks, a JSON on the left will be treated as a single long string, as designed.
# There is an example for that in the TestPlaybook.
# However, during testing, I encountered difficulty reproducing that behavior. In the test environment,
# a JSON containing a comma will be separated into two strings.


@pytest.mark.parametrize('left,right, call_count,expected_result', [
    (123, 1, 1, [True]),
    ("2", "25,10", 1, [False]),
    ("1, '2'", "1,2,3", 2, [True, True]),    # a part of '2' is in '1,2,3'
    ('"abc", "ahah", "a"', "A", 3, [True, True, True]),
    ("5,1,6,9,65,8,b", "1,'6'", 7, [False, True, False, False, False, False, False]),  # no part of 6 or 65 is in the list: 1,'6'
    ('a', "kfjua", 1, [False]),
    (1, "1", 1, [True]),       # int and str are equal
    ("bca", "A", 1, [True]),  # case insensitive
    ("ABC", "a", 1, [True]),  # case insensitive
    ({"alert": {"data": "x"}}, "x", 1, [True]),
    ("{'a':1,'c':2}", "{'a': 1}, {'b': 2}", 2, [False, False]),     # {'a':1} is not a part of {'a':1, or 'c':2}
    ("{'a': 1}, {'b': 2}", "{a:1}", 2, [False, False]),  # {a:1} is not a part of {'a': 1} or {'b': 2}
    # although '' is not a part of {'a':1,'c':2}, but ' is in {'a': 1 and in  'c': 2}
    ("{'a':1,'c':2}", "'', '", 2, [True, True]),
    (None, "A", 1, [False])
])
def test_main(mocker, left, right, call_count, expected_result):
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
    assert demisto.results.call_count == call_count
    for i in range(len(expected_result)):
        results = demisto.results.call_args_list[i][0][0]
        assert results == expected_result[i]
