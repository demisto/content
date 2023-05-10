from URLEncode import *


def test_URLEncode():
    """Unit test
    Given
    - url to encode.
    When
    - call URLEncode transformer.
    Then
    - validate The encoded url.
    """
    res = main({'value': 'https://www.google.com/'})
    assert res == 'https%3A//www.google.com/'


def test_URLEncode_encoded_input():
    """Unit test
    Given
    - encoded url.
    When
    - call URLEncode transformer.
    Then
    - validate The url didnt changed since it was already encoded.
    """
    res = main({'value': 'https%3A//www.google.com/'})
    assert res == 'https%3A//www.google.com/'


def test_URLEncode_partial_encoded_input():
    """Unit test
    Given
    - partial encoded url.
    When
    - call URLEncode transformer.
    Then
    - validate all the url is now encoded.
    """
    res = main({'value': 'https%3A//www.google.com/url@to@encode'})
    assert res == 'https%3A//www.google.com/url%40to%40encode'
