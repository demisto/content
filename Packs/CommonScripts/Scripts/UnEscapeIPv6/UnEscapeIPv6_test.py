import pytest
from UnEscapeIPv6 import clearing_the_address_from_unrelated_characters


@pytest.mark.parametrize(
    "addresses, expected",
    [
        ('(::1234)', '::1234'),
        (' ::1234 ', '::1234'),
        ('`::1234', '::1234'),
        ('::1234)', '::1234')
    ]
)
def test_clearing_the_address_from_unrelated_characters(addresses, expected):
    result = clearing_the_address_from_unrelated_characters(addresses)

    assert result == expected
