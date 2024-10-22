import pytest
from hypothesis import HealthCheck, given, settings, strategies

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


@pytest.mark.parametrize(
    "address, expected",
    [
        ('00:16:45:00:46:91', ''),
        ('"1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7:8'),
    ]
)
def test_main(mocker, address, expected):
    """
    Given:
        - MAC Address as input
    When:
        - Running the script
    Then:
        - Ensure the MAC address is caught as invalid IPv6 and returns array with empty string
    """
    mocker.patch.object(demisto, 'args', return_value={'input': address})
    mocker.patch.object(demisto, 'results')
    main()
    demisto.results.assert_called_with([expected])


@pytest.mark.skip(reason="Flaky test, issue #41552")
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(strategies.ip_addresses(v=6))
def test_valid_ip_address(mocker, ipv6):
    """
    Given:
        - IPv6 address
    When:
        - Running the script
    Then:
        - Ensure the IPv6 address is returned in an array
    """
    mocker.patch.object(demisto, 'args', return_value={'input': str(ipv6)})
    mocker.patch.object(demisto, 'results')
    main()
    demisto.results.assert_called_with([str(ipv6)])
