from VerifyIPv6Indicator import is_valid_ipv6_address, main
import pytest


@pytest.mark.parametrize(
    "address, expected",
    [
        ('12::34::56', None),
        ('1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7:8'),
        ('1:2:3:4::5::7', None),
        ('1::3:4:5:6:7:8', '1::3:4:5:6:7:8'),
        ('1::2::3::4::5::6::7::8', None),
        ('1abc:2abc::4de:1', '1abc:2abc::4de:1')


    ]
)
def test_set_limit(address, expected):
    ipv6_address = is_valid_ipv6_address(address)
    assert ipv6_address == expected