import demistomock as demisto
from CommonServerPython import *

from netaddr import IPAddress, IPNetwork


def main():
    ip_addresses = argToList(demisto.args()['value'])
    cidr_range_list = argToList(demisto.args()['cidr_ranges'])

    excluded_addresses = []

    for ip_address in ip_addresses:
        found = False
        ip = IPAddress(ip_address)

        for cidr_range in cidr_range_list:
            if ip in IPNetwork(cidr_range):
                found = True

        if not found:
            excluded_addresses.append(ip_address)

    if not excluded_addresses:
        demisto.results(None)
    else:
        demisto.results(excluded_addresses)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
