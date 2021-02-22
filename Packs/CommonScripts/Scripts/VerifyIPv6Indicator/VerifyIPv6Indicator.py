import demistomock as demisto
from CommonServerPython import *
import ipaddress


def is_valid_ipv6_address(address):
    try:
        ipaddress.IPv6Address(address)
        return True
    except ValueError:
        return False


def main():
    the_input = demisto.args().get('input')

    the_input = argToList(the_input)
    entries_list = []

    for item in the_input:
        if is_valid_ipv6_address(item):
            entries_list.append(item)
        else:
            continue

    if entries_list:
        demisto.results(entries_list)
    else:
        demisto.results([])


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
