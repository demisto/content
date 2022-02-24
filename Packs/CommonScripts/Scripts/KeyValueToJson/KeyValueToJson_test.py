from KeyValueToJson import key_to_json

import pytest


@pytest.mark.parametrize('values,keys,expected', [
    ([1, 2, 3, 4], ["A", "B", "C", "D"], [{"A": 1}, {"B": 2}, {"C": 3}, {"D": 4}]),
    ([(1, 2), (3, 4)], ["A", "B"], [{"A": 1, "B": 2}, {"A": 3, "B": 4}])
])
def test_key_to_json(values, keys, expected):
    """
    Given:
        Case 1: Values = [1,2,3,4] and keys = ["A", "B", "C", "D"] will return
        formatted key:value pairs as {"A": 1, "B": 2, "C": 3, "D": 4}

        Case 2: Values = [(1,2), (3,4)] and keys = ["A", "B"] will return
        list formatted key:value pairs as [{"A": 1, "B": 2}, {"A": 3, "B": 4}]
    When:
        Running key_to_json
    Then:
        Case 1: Ensure {"A": 1, "B": 2, "C": 3, "D": 4} is returned
        Case 1: Ensure [{"A": 1, "B": 2}, {"A": 3, "B": 4}] is returned
    """
    assert key_to_json(keys, values) == expected