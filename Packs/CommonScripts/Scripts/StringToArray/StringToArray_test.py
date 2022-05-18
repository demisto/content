from StringToArray import *


def test_string_to_array():
    """Unit test
    Given
    - url to tranform.
    When
    - call StringToArray transformer.
    Then
    - validate The transformed url.
    """
    res = main({'value': "http://example.com/?score:1,4,time:55"})
    assert res == '["http://example.com/?score:1,4,time:55"]'
