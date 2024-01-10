import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import ipaddress


def validate_cidr(cidr: str):
    """
    Validates CIDR format.
    """
    try:
        ipaddress.ip_network(cidr)

    except ValueError as e:
        demisto.debug(f'Skipping "{cidr}": {e}')
        return False

    return True


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

    try:

        not_in_range = True

        for ip in ip_addresses:

            try:
                ip = ipaddress.ip_address(ip)

            except ValueError as e:
                demisto.debug(f'Skipping "{ip}": {e}')
                continue

            not_in_range = all(ip not in ipaddress.ip_network(cidr) for cidr in cidr_range_list if validate_cidr(cidr))

        demisto.results(not_in_range)

    except Exception as e:
        return_error(f'Failed to execute IsNotInCidrRange_copy. Error: {str(e)}')


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
