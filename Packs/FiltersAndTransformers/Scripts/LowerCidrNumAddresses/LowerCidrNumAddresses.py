# STD packages
import ipaddress
# Local imports
from CommonServerPython import *

# The following script check if given IPv4 CIDR availble addresses is lower from a given number.


def cidr_network_addresses_lower_from_const(ip_cidr: str, max_num_addresses: str) -> bool:
    """ Decide if num_adddresses const is lower than availble addresses in IPv4 or IPv6 cidr

    Args:
        ip_cidr(str): IP/CIDR, e.g. 192.168.0.0/24, 2002::1234:abcd:ffff:c0a8:101/127 # disable-secrets-detection
        max_num_addresses(str): number of addresses to be lower than.

    Returns:
        bool: True if num of availbe addresses is lower than const num_addresses
    """
    ip_cidr_obj = ipaddress.ip_network(address=ip_cidr, strict=False)
    if ip_cidr_obj.num_addresses < int(max_num_addresses):
        return True
    return False


def main():
    ip_cidrs = argToList(demisto.args()['left'])
    max_num_addresses = demisto.args()['right']
    for cidr in ip_cidrs:
        is_lower = cidr_network_addresses_lower_from_const(ip_cidr=cidr,
                                                           max_num_addresses=max_num_addresses)
        demisto.results(is_lower)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
