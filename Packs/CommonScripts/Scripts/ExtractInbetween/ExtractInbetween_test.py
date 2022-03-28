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

    # Test 2
    value = {
        "key1": "value1",
        "key2": "value2"
    }
    res = extract_inbetween(value, start, end)
    assert res == value

    # Test3
    value = 10
    res = extract_inbetween(value, start, end)
    assert res == "ERROR: The input value must be a string"

