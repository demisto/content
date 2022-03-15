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
    value = "<This is a value>"
    start = "<"
    end = ">"
    res = extract_inbetween(value, start, end)
    assert res == "This is a value"
