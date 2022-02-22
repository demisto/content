import pytest
from URLSSLVerification import mark_http_as_suspicious


@pytest.mark.parametrize('arg, expected_result', [
    ('false', False),
    ('true', True),
    (None, True)
])
def test_is_http_should_be_suspicious(arg, expected_result):
    assert mark_http_as_suspicious(arg) == expected_result
