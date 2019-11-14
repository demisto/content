
from SetIfEmpty import getValueToSet

def test_WhenValueIsAValidString_ShouldReturnValue():
    validString = "validString"
    expectedOutput = validString
    result = getValueToSet({'value': validString, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'true'})

    assert expectedOutput == result

def test_WhenValueIsADictionary_ShouldReturnValue():
    dictionary = {'name': "John", 'lastName': 'Doe'}
    expectedOutput = dictionary
    result = getValueToSet({'value': dictionary, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'true'})

    assert expectedOutput == result

def test_WhenValueIsEmptyString_ShouldReturnDefaultValue():
    expectedOutput = "defaultValue"
    result = getValueToSet({'value': '', 'defaultValue': 'defaultValue', 'applyIfEmpty': 'True'})

    assert expectedOutput == result

def test_WhenValueIsEmptyDictionary_ShouldReturnDefaultValue():
    expectedOutput = "defaultValue"
    result = getValueToSet({'value': {}, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'true'})

    assert expectedOutput == result

def test_WhenValueIsNone_ShouldReturnDefaultValue():
    expectedOutput = "defaultValue"
    result = getValueToSet({'value': None, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'true'})

    assert expectedOutput == result

def test_WhenValueIsEmptyString_AndApplyIfEmptyIsFalse_ShouldReturnEmptyString():
    expectedOutput = ""
    result = getValueToSet({'value': '', 'defaultValue': 'defaultValue', 'applyIfEmpty': 'False'})

    assert expectedOutput == result

def test_WhenValueIsEmptyDictionary_AndApplyIfEmptyIsFalse__ShouldReturnEmptyDictionary():
    expectedOutput = {}
    result = getValueToSet({'value': {}, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'false'})

    assert expectedOutput == result

def test_WhenValueIsNone_AndApplyIfEmptyIsFalse__ShouldReturnDefaultValue():
    expectedOutput = "defaultValue"
    result = getValueToSet({'value': None, 'defaultValue': 'defaultValue', 'applyIfEmpty': 'false'})

    assert expectedOutput == result
