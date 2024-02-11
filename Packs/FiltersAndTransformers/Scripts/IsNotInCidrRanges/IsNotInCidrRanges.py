import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import ipaddress


def validate_cidr(cidr: str) -> bool:
    """
    Validates if the input string is in CIDR format.

    Args:
        cidr (str): The string to be validated.

    Returns:
        bool: True if the string is a valid CIDR, False otherwise.

    Raises:
        ValueError: If the string is not a valid CIDR.
    """
    try:
        ipaddress.ip_network(cidr)

    except ValueError as e:
        demisto.debug(f'Skipping "{cidr}": {e}')
        return False

    return True


def process_ips(ip_addresses: list[str], cidr_range_list: list[str]) -> bool:
    """
    Check if given IP (or IPs) address is part of a given CIDR (or a list of CIDRs).

    Args:
        ip_addresses (List[str]): A list of IPs/IPv6s
        cidr_range_list (List[str]): A list of CIDRs to be checked against.

    Returns:
        bool: True if given IP is part of given CIDR range.
    """
    not_in_range_list = []
    for ip in ip_addresses:
        try:
            ip_address = ipaddress.ip_address(ip)
        except ValueError as e:
            demisto.debug(f'Skipping "{ip}": {e}')
            continue

        not_in_range_list.append(
            all(
                ip_address not in ipaddress.ip_network(cidr)
                for cidr in cidr_range_list
                if validate_cidr(cidr)
            )
        )

    return all(not_in_range_list)


def main():  # pragma: no cover
    ip_addresses = argToList(demisto.args()["left"])
    cidr_range_list = argToList(demisto.args()["right"])

    try:
        return_results(process_ips(ip_addresses, cidr_range_list))
    except Exception as e:
        return_error(f"Failed to execute IsNotInCidrRange. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
