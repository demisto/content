# STD imports
import ipaddress
from typing import Dict, Tuple

import demistomock as demisto
from CommonServerPython import *

# Local imports


def ip_cidr(cidr: str) -> Dict[str, str]:
    """ Gather info regarding the supplied network

    Args:
        cidr(str): IPv4/CIDR or IPv6/CIDR

    Returns:
        dict: Entry context of single network
    """
    try:
        ip_network = ipaddress.ip_network(cidr, strict=False)
        internal_ec = {
            'CIDR': cidr,
            'Version': ip_network.version,
            'Private': ip_network.is_private,
            'Max_prefix_len': ip_network.max_prefixlen,
            'Num_addresses': ip_network.num_addresses,
            'Broadcast_address': str(ip_network.broadcast_address),
            'First_address': str(ip_network[0]),
            'Last_address': str(ip_network[-1])
        }
        return internal_ec
    except ValueError:
        return {}


def cidr_command(args: Dict[str, str]) -> Tuple[str, dict, str]:
    """ Perform command on given IP/CIDR

    Args:
        args: argument from command runnning in demisto

    Returns:

    """
    cidr_list = argToList(args.get('cidr'))
    ec = {'Network': [ip_cidr(cidr) for cidr in cidr_list]}
    markdown = tableToMarkdown(name=f'CIDR - {args.get("cidr")}',
                               t=ec.get('Network'),
                               removeNull=True)

    return (
        markdown,
        ec,
        ""
    )


def main():
    try:
        return_outputs(*cidr_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute IPNetwork script. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
