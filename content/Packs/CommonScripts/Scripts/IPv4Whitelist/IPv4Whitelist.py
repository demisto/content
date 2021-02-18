import demistomock as demisto
from CommonServerPython import *

from netaddr import IPAddress, IPNetwork


def main():
    ip_addresses = argToList(demisto.args()['value'])
    cidr_range_list = argToList(demisto.args()['cidr_ranges'])

    included_addresses = []

    for ip_address in ip_addresses:
        ip = IPAddress(ip_address)

        for cidr_range in cidr_range_list:
            if ip in IPNetwork(cidr_range):
                included_addresses.append(ip_address)

    if not included_addresses:
        demisto.results(None)
    else:
        demisto.results(included_addresses)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
