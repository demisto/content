import pytest
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from ExtractInbetween import extract_inbetween


def test_extract_inbetween():
    """
    Given:
        A string with specific characters

    When:
        Execute command extract_inbetween

    Then:
        Validate the right output returns.
    """

    # Test 1
    value = "<This is a value>"
    start = "<"
    end = ">"
    res = extract_inbetween(value, start, end)
    assert res == "This is a value"


@pytest.mark.parametrize("value", [{"key1": "value1", "key2": "value2"}, 10])
def test_extract_inbetween_on_invalid_input_types(mocker, value):
    """
    Given:
        a value which is not a string type

    When:
        Execute command extract_inbetween

    Then:
        Validate that return error is raised.
    """
    mocker.patch('CommonServerPython.return_error', return_value=Exception("ERROR: The input value must be a string"))
    with pytest.raises(Exception, match="ERROR: The input value must be a string"):
        extract_inbetween(value, '<', '>')
