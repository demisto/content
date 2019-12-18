
from SetIfEmpty import get_value_to_set


def test_when_value_is_a_valid_string_should_return_value():
    validString = "validString"
    expectedOutput = validString
    result = get_value_to_set({'value': validString, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'true'})

    assert expectedOutput == result


def test_when_value_is_a_dictionary_should_return_value():
    dictionary = {'name': "John", 'lastName': 'Doe'}
    expectedOutput = dictionary
    result = get_value_to_set({'value': dictionary, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'true'})

    assert expectedOutput == result


def test_when_value_is_empty_string_should_return_value():
    expectedOutput = "defaultValue"
    result = get_value_to_set({'value': '', 'defaultValue': 'defaultValue', 'applyIfEmpty': 'True'})

    assert expectedOutput == result


def test_when_value_is_empty_dictionary_should_return_default_value():
    expectedOutput = "defaultValue"
    result = get_value_to_set({'value': {}, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'true'})

    assert expectedOutput == result


def test_when_value_is_none_should_return_default_value():
    expectedOutput = "defaultValue"
    result = get_value_to_set({'value': None, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'true'})

    assert expectedOutput == result


def test_when_value_is_empty_string_and_apply_if_empty_is_false_should_return_empty_string():
    expectedOutput = ""
    result = get_value_to_set({'value': '', 'defaultValue': 'defaultValue', 'applyIfEmpty': 'False'})

    assert expectedOutput == result


def test_when_value_is_empty_dictionary_and_apply_if_empty_is_false_should_return_empty_dictionary():
    expectedOutput = {}
    result = get_value_to_set({'value': {}, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'false'})

    assert expectedOutput == result


def test_when_value_is_none_and_apply_if_empty_is_false_should_return_default_value():
    expectedOutput = "defaultValue"
    result = get_value_to_set({'value': None, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'false'})

    assert expectedOutput == result


def test_when_value_is_empty_array_and_apply_if_empty_is_true_should_return_default_value():
    expectedOutput = "defaultValue"
    result = get_value_to_set({'value': [""], 'defaultValue': 'defaultValue', 'applyIfEmpty': 'true'})

    assert expectedOutput == result
