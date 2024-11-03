import pytest
from SumList import sum_value

'''Arguments as lists'''

only_numbers = [1, 2, 3, 4]
numbers_as_string = ['1', '2', '3', '4']
combined_string_numbers = ['1', 2, 3, '4']
fail_not_number = ['d', '1', 3]
empty_list = []
with_floats_to_int = ['1.0', '2.0', 3, '4']
with_floats_to_float = ['1.1', '2.0', 3, '4']

'''Arguments as strings'''

only_numbers_as_string = '1,2 ,3 ,4'
fail_not_number_as_string = 'd,1,3'
empty_string = ''
with_floats_to_int_string = '1.05, 2.95, 3, 3.0'
with_floats_to_float_string = '1.1,2.0,3,4'

'''Expected results'''

good_result = (10, 'ok')
good_result_floats = (10.1, 'ok')
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


@pytest.mark.parametrize('string_value, expected_result', [
    (with_floats_to_int, good_result),
    (with_floats_to_int_string, good_result),
])
def test_floats_that_will_be_ints(string_value, expected_result):
    value, return_type = sum_value(string_value)
    assert (value, return_type) == expected_result


@pytest.mark.parametrize('string_value, expected_result', [
    (with_floats_to_float, good_result_floats),
    (with_floats_to_float_string, good_result_floats),
])
def test_floats_that_will_be_floats(string_value, expected_result):
    value, return_type = sum_value(string_value)
    assert (value, return_type) == expected_result
