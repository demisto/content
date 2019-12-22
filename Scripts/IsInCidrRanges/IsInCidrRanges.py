import demistomock as demisto
from CommonServerPython import argToList

from netaddr import IPAddress, IPNetwork


def main():
    ip = demisto.args()['left']
    cidr_list = argToList(demisto.args()['right'])

    for cidr in cidr_list:
        if IPAddress(ip) in IPNetwork(cidr):
            demisto.results(True)
            return

    demisto.results(False)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
