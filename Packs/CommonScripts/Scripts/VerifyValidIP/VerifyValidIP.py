import demistomock as demisto
from CommonServerPython import *

import ipaddress


def is_valid_ip_address(ip: str) -> bool:
    """
    Check if the given string is a valid IP address (IPv4 or IPv6).

    Args:
        ip (str): The IP address string to validate

    Returns:
        bool: True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def create_readable_output(ips, results) -> str:
    """
    Create a human-readable output table of IP validation results.

    Args:
        results (list[bool]): List of validation results
        ips (list[str]): List of original IP addresses

    Returns:
        str: Markdown-formatted table showing IP and validation status
    """

    markdown = "| IP | Valid |\n|---|---|\n"
    for ip, result in zip(ips, results):
        markdown += f"| {ip} | {result} |\n"

    return markdown


def create_outputs(ips, results) -> dict:
    """
    Create outputs dictionary with proper context structure.

    Args:
        ips (list[str]): List of IP addresses
        results (list[bool]): List of validation results

    Returns:
        dict: Dictionary with VerifyValidIP key containing list of IP validation results
    """

    ip_results = []
    for ip, valid in zip(ips, results):
        ip_results.append({"IP": ip, "Valid": valid})

    return {"VerifyValidIP": ip_results}


def main() -> None:
    """
    Main function that validates a list of IP addresses.

    Gets input from demisto args, validates each IP address,
    and returns a list of boolean results.
    """
    the_input = demisto.args().get("input")
    ips = argToList(the_input)
    results: list[bool] = []

    for ip in ips:
        demisto.info(f"Validating IP: {ip}")
        is_valid = is_valid_ip_address(ip)
        results.append(is_valid)
        demisto.info(f"IP {ip} is {'valid' if is_valid else 'invalid'}")

    return_results(
        CommandResults(
            readable_output=create_readable_output(ips, results),
            outputs=create_outputs(ips, results),
        )
    )


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
