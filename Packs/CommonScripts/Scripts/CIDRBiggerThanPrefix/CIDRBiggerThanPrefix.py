import ipaddress

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def cidr_network_addresses_lower_from_const(ip_cidr: str, max_prefix: str) -> bool:
    """ Check if a given CIDR prefix is bigger (lower number prefix) than the given input.

    Args:
        ip_cidr(str): IP/CIDR/IPv6/CIDRv6, e.g. 192.168.0.0/24, 2002::1234:abcd:ffff:c0a8:101/127 # disable-secrets-detection
        max_prefix(str): The maximum allowed as a prefix of the CIDR.

    Returns:
        bool: True if given CIDR has more hosts (lower prefix number) than max prefix.
    """

    ip_cidr_obj = ipaddress.ip_network(address=ip_cidr, strict=False)
    if ip_cidr_obj.prefixlen < int(max_prefix):
        return True
    return False


def main():
    ip_cidrs = argToList(demisto.args()['left'])
    max_prefix = demisto.args()['right']
    for cidr in ip_cidrs:
        is_lower = cidr_network_addresses_lower_from_const(ip_cidr=cidr,
                                                           max_prefix=max_prefix)
        demisto.results(is_lower)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
