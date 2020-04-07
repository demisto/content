# STD packages
import ipaddress
# Local imports
from CommonServerPython import *


def cidr_network_addresses_greater_from_const(ip_cidr: str, min_num_addresses: str) -> bool:
    """ Decide if num_adddresses const is greater than availble addresses in IPv4 or IPv6 cidr

    Args:
        ip_cidr(str): IP/CIDR, e.g. 192.168.0.0/24, 2002::1234:abcd:ffff:c0a8:101/127 # disable-secrets-detection
        min_num_addresses(str): number of addresses to be lower than.

    Returns:
        bool: True if num of availbe addresses is greater than const num_addresses
    """
    ip_cidr_obj = ipaddress.ip_network(address=ip_cidr, strict=False)
    if ip_cidr_obj.num_addresses > int(min_num_addresses):
        return True
    return False


def main():
    ip_cidrs = argToList(demisto.args()['left'])
    min_num_addresses = argToList(demisto.args()['right'])[0]
    for cidr in ip_cidrs:
        is_lower = cidr_network_addresses_greater_from_const(ip_cidr=cidr,
                                                             min_num_addresses=min_num_addresses)
        demisto.results(is_lower)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
