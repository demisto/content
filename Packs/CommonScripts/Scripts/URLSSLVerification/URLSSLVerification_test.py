import pytest
from URLSSLVerification import is_http_should_be_suspicious


@pytest.mark.parametrize('arg, expected_result', [
    ('false', False),
    ('true', True),
    (None, True)
])
def test_is_http_should_be_suspicious(arg, expected_result):
    assert is_http_should_be_suspicious(arg) == expected_result
