import pytest

import demistomock as demisto
from VerifyIPv6Indicator import is_valid_ipv6_address, main


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


def test_main(mocker):
    """
    Given:
        - MAC Address as input
    When:
        - Running the script
    Then:
        - Ensure the MAC address is caught as invalid IPv6 and returns empty string
    """
    mocker.patch.object(demisto, 'args', return_value={'input': '00:16:45:00:46:91'})
    mocker.patch.object(demisto, 'results')
    main()
    demisto.results.assert_called_with('')
