from CommonServerPython import *
import pytest
from CiscoFirepower import Client, switch_list_to_list_counter


INPUT_TEST_SWITCH_LIST_TO_LIST_COUNTER = [
    ({'1': '1'}, {'1': '1'}),
    ({'1': '1', '2': ['1', '2']}, {'1': '1', '2': 2}),
    ({'1': '1', '2': ['1', '2', {'1': '1'}, ['1', '2']]}, {'1': '1', '2': 5}),
    ({'1': '1', '2': ['1', '2', {'1': '1', '2': ['1', '2']}, ['1', '2']]}, {'1': '1', '2': 7})
]

""" TESTS FUNCTION """


@pytest.mark.parametrize('list_input, list_output', INPUT_TEST_SWITCH_LIST_TO_LIST_COUNTER)
def test_switch_list_to_list_counter(list_input, list_output):
    result = switch_list_to_list_counter(list_input)
    assert result == list_output