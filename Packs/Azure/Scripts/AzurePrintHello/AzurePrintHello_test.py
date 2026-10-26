from AzurePrintHello import print_hello


def test_print_hello():
    """
    Given: No input.
    When: Running print_hello.
    Then: The readable output is "Hello".
    """
    result = print_hello()
    assert result.readable_output == "Hello"
