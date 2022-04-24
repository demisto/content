import pytest
from CommonServerPython import *
import MicrosoftGraphIdentityandAccess

ipv4 = {'@odata.type': '#microsoft.graph.iPv4CidrRange','cidrAddress': '12.34.221.11/22'}
ipv6 = {'@odata.type': '#microsoft.graph.iPv6CidrRange','cidrAddress': '2001:0:9d38:90d6:0:0:0:0/63'}
@pytest.mark.parametrize("ips,expected", [("12.34.221.11/22,2001:0:9d38:90d6:0:0:0:0/63", [ipv4, ipv6]),
                                          ("12.34.221.11/22,12.34.221.11/22", [ipv4, ipv4]),
                                          ("2001:0:9d38:90d6:0:0:0:0/63,2001:0:9d38:90d6:0:0:0:0/63", [ipv6, ipv6])])
def test_ms_ip_string_to_list(ips, expected):
    """
    Given:
    -   is_event_level (bool): whether this is a dict of event. False is for attribute level.
        ATTRIBUTE_TAG_LIMIT: list includes a dict of MISP tags.

    When:
    -   parsing a reputation response from MISP.

    Then:
    - Ensure that the Tag section is limited to include only name and id.
    """

    assert MicrosoftGraphIdentityandAccess.ms_ip_string_to_list(ips) == expected


