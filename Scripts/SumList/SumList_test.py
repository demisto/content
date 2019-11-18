from __future__ import print_function
import pytest
from SumList import sum_value

'''Arguments as lists'''

only_numbers = [1, 2, 3, 4]
numbers_as_string = ['1', '2', '3', '4']
combined_string_numbers = ['1', 2, 3, '4']
fail_not_number = ['d', '1', 3]
empty_list = []

'''Arguments as strings'''

only_numbers_as_string = '1,2 ,3 ,4'
fail_not_number_as_string = 'd,1,3'
empty_string = ''

'''Expected results'''

good_result = (10, 'ok')
bad_result = ('error', 'error')
empty_list_result = (0, 'ok')


@pytest.mark.parametrize('list_value, expected_result', [
    (only_numbers, good_result),
    (numbers_as_string, good_result),
    (combined_string_numbers, good_result),
    (fail_not_number, bad_result),
    (empty_list, empty_list_result)
])
def test_lists(list_value, expected_result):
    value, return_type = sum_value(list_value)
    assert (value, return_type) == expected_result


@pytest.mark.parametrize('string_value, expected_result', [
    (only_numbers_as_string, good_result),
    (fail_not_number_as_string, bad_result),
    (empty_string, bad_result),
])
def test_strings(string_value, expected_result):
    value, return_type = sum_value(string_value)
    assert (value, return_type) == expected_result
