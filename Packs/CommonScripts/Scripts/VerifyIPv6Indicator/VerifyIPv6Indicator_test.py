from VerifyIPv6Indicator import is_valid_ipv6_address
import pytest


@pytest.mark.parametrize(
    "address, expected",
    [
        ('12::34::56', False),
        ('1:2:3:4:5:6:7:8', True),
        ('1:2:3:4::5::7', False),
        ('1::3:4:5:6:7:8', True),
        ('1::2::3::4::5::6::7::8', False),
        ('1abc:2abc::4de:1', True)


    ]
)
def test_set_limit(address, expected):
    ipv6_address = is_valid_ipv6_address(address)
    assert ipv6_address == expected
