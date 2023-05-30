def test_hook():
    """
    Given
    - A string value representing a json
    When
    - Running the hook function
    Then
    - Ensure the string value is converted to json
    """
    from JsonUnescape import hook
    assert hook({"key": "value"}) == {"key": "value"}
    assert hook({"key": "{'key': 'value'}"}) == {'key': "{'key': 'value'}"}


def test_unescape():
    """
    Given
    - A dictionary with a string value
    When
    - Running the unescape function
    Then
    - Ensure the string value is converted to json
    """
    from JsonUnescape import unescape
    assert unescape({"value": "value"}) == 'value'
    assert unescape({"value": "{'key': 'value'}"}) == "{'key': 'value'}"
