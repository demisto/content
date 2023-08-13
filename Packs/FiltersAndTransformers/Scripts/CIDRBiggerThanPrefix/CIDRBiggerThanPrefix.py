import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ipaddress


def cidr_network_addresses_lower_from_const(ip_cidr: str, max_prefix: int) -> bool:
    """ Check if a given CIDR prefix is bigger (lower number prefix) than the given input.

    Args:
        ip_cidr(str): IP/CIDR/IPv6/CIDRv6, e.g. 192.168.0.0/24, 2002::1234:abcd:ffff:c0a8:101/127 # disable-secrets-detection
        max_prefix(int): The maximum allowed as a prefix of the CIDR.

    Returns:
        bool: True if given CIDR has more hosts (lower prefix number) than max prefix.
    """

    try:
        ip_cidr_obj = ipaddress.ip_network(address=ip_cidr, strict=False)

    except ValueError as e:
        # If one of the inputs is not a valid CIDR it will be logged and return False
        demisto.debug(f'Skipping "{ip_cidr}": {e}')
        return False

    else:
        return ip_cidr_obj.prefixlen < max_prefix


def main():
    ip_cidrs = argToList(demisto.args()['left'])
    max_prefix = demisto.args()['right']

    try:

        max_prefix = int(max_prefix)  # Fails if input is not an integer

        for cidr in ip_cidrs:
            is_lower = cidr_network_addresses_lower_from_const(ip_cidr=cidr,
                                                               max_prefix=max_prefix)
            demisto.results(is_lower)

    except Exception as e:
        return_error(f'Failed to execute CIDRBiggerThanPrefix. Error: {str(e)}')


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
