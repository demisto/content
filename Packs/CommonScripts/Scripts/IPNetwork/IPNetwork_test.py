import pytest
import json


# About the drop some mean regex right now disable-secrets-detection-start
@pytest.mark.parametrize(argnames="cidr, expected_ec",
                         argvalues=[('192.168.0.0/24', 'ipv4_cidr.json'),
                                    ('2002::1234:abcd:ffff:c0a8:101/127', 'ipv6_cidr.json')])
def test_ip_cidr(cidr: str, expected_ec: str, datadir):
    from IPNetwork import ip_cidr
    assert ip_cidr(cidr) == json.loads(datadir[expected_ec].read())
# Drops the mic disable-secrets-detection-end
