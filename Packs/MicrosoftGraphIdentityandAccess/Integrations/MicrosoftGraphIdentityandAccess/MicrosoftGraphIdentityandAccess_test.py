import pytest
import MicrosoftGraphIdentityandAccess

ipv4 = {'@odata.type': '#microsoft.graph.iPv4CidrRange','cidrAddress': '12.34.221.11/22'} # noqa
ipv6 = {'@odata.type': '#microsoft.graph.iPv6CidrRange','cidrAddress': '2001:0:9d38:90d6:0:0:0:0/63'} # noqa


@pytest.mark.parametrize("ips,expected", [("12.34.221.11/22,2001:0:9d38:90d6:0:0:0:0/63", [ipv4, ipv6]),
                                          ("12.34.221.11/22,12.34.221.11/22", [ipv4, ipv4]),
                                          ("2001:0:9d38:90d6:0:0:0:0/63,2001:0:9d38:90d6:0:0:0:0/63", [ipv6, ipv6])])
def test_ms_ip_string_to_list(ips, expected):
    """
    Given:
    -   Ips in a string

    When:
    -   Convetting them to an ip list.

    Then:
    - Ensure that the list we get is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.ms_ip_string_to_list(ips) == expected
