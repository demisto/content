import demistomock as demisto
from CommonServerPython import *

from netaddr import IPAddress, IPNetwork


def main():
    ip_address = demisto.args()['left']
    cidr_range_list = argToList(demisto.args()['right'])

    for cidr in cidr_range_list:
        if IPAddress(ip_address) in IPNetwork(cidr):
            demisto.results(True)
            return

    demisto.results(False)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
