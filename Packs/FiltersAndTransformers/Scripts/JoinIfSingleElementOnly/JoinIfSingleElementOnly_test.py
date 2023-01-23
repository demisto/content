import pytest

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from JoinIfSingleElementOnly import return_first_element_if_single


@pytest.mark.parametrize('value,expected_res', [
    (['1', '2', '3'], ['1', '2', '3']),
    (['1'], '1'),
    ('test', 'test')
])
def test_join_if_single(value, expected_res):
    res = return_first_element_if_single(value)
    assert res == expected_res
