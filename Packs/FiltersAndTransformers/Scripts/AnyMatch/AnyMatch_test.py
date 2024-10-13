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
    ("2", "25,10", False),
    ("'2'", "1,2,3", True),    # 2 is part of '2'
    ("'abc','aha','a'", "A", True),
    ("5,1,6,9,65,8,b", "1,'6'", True),  # no part of 6 or 65 is in the list: 1,'6'
    ('a', "kfjua", False),
    ("bca", "A", True),  # case insensitive
    ("ABC", "a", True),  # case insensitive
    ('{"alert": {"data": "x"}}', "x", True),
    ("{'a':1,'c':2}", "{'a': 1}, {'b': 2}", False),     # {'a':1} is not a part of {'a':1, or 'c':2}
    ("{'a': 1}, {'b': 2}", "{a:1}", False),  # {a:1} is not a part of {'a': 1} or {'b': 2}
    # although '' is not a part of {'a':1,'c':2}, but ' is in {'a': 1 and in  'c': 2}
    ("{'a':1,'c':2}", "'', '", True),
    # one of the arguments is missing -> return empty list
    ("1,2", "", False)
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
    results = demisto.results.call_args_list[0][0][0]
    assert results == expected_result

