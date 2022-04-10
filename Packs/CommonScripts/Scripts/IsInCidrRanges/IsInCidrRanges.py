import ipaddress

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    """ Check if given IP (or IPs) address is part of a given CIDR (or a list of CIDRs).

    Args:
        ip_addresses (str): A list of IPs/IPv6s
        cidr_range_list (str): A list of CIDRs to be checked against.

    Returns:
        bool: True if given IP is part of given CIDR range.
    """

    ip_addresses = argToList(demisto.args()['left'])
    cidr_range_list = argToList(demisto.args()['right'])

    for ip in ip_addresses:
        for cidr in cidr_range_list:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                demisto.results(True)
                return

        demisto.results(False)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
