import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
import subprocess
import traceback
from typing import Any


''' STANDALONE FUNCTION '''


def dig_result(server: str, name: str):
    """Run Dig command on the server and get A record for the specified host

    Args:
        server (str): server to run the dig command on
        name (str): host to run the dig command on

    Raises:
        ValueError: on failure to find A record

    Returns:
        Dict[str, Any]: dictionary representing the dig result
    """
    try:
        if server:
            server = f"@{server}"
            dig_output = subprocess.check_output(
                ['dig', server, name, '+short', '+identify'], stderr=subprocess.STDOUT, universal_newlines=True
            )

            if not dig_output:
                raise ValueError("Couldn't find A record for:\n" + name)

            resolved_addresses, dns_server = regex_result(dig_output, reverse_lookup=False)

            return {"name": name, "resolvedaddresses": resolved_addresses, "nameserver": dns_server}

        else:
            dig_output = subprocess.check_output(
                ['dig', name, '+short', '+identify'], stderr=subprocess.STDOUT, universal_newlines=True
            )

            if not dig_output:
                raise ValueError("Couldn't find A record for:\n" + name)

            resolved_addresses, dns_server = regex_result(dig_output, reverse_lookup=False)

            return {"name": name, "resolvedaddresses": resolved_addresses, "nameserver": dns_server}

    except subprocess.CalledProcessError as e:
        return_error(e.output)


def reverse_dig_result(server: str, name: str):
    """Run Dig command on the server and get PTR record for the specified IP

    Args:
        server (str): server to run the dig command on
        name (str): host to run the dig command on

    Raises:
        ValueError: on failure to find PTR record

    Returns:
        Dict[str, Any]: dictionary representing the dig result
    """
    try:
        if server:
            server = f"@{server}"
            dig_output = subprocess.check_output(
                ['dig', server, '+answer', '-x', name, '+short', '+identify'], stderr=subprocess.STDOUT, universal_newlines=True
            )

            if not dig_output:
                raise ValueError("Couldn't find PTR record for:\n" + name)

            resolved_addresses, dns_server = regex_result(dig_output, reverse_lookup=True)

            return {"name": name, "resolveddomain": resolved_addresses, "nameserver": dns_server}

        else:
            dig_output = subprocess.check_output(
                ['dig', '+answer', '-x', name, '+short', '+identify'], stderr=subprocess.STDOUT, universal_newlines=True
            )

            if not dig_output:
                raise ValueError("Couldn't find PTR record for:\n" + name)

            resolved_addresses, dns_server = regex_result(dig_output, reverse_lookup=True)

            return {"name": name, "resolveddomain": resolved_addresses, "nameserver": dns_server}

    except subprocess.CalledProcessError as e:
        return_error(e.output)


def regex_result(dig_output: str, reverse_lookup: bool):
    """Helper function to parse the dig output

    Args:
        dig_output (str): dig command output
        reverse_lookup (bool): whether to run a reverse lookup

    Raises:
        ValueError: on failure to find results

    Returns:
        (list[str],str): tuple of the resolved addresses and the dns server
    """
    # regex phrase to catch a number between 0 to 255
    num_0_255 = r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
    try:
        if not reverse_lookup:
            regex_results_ip = re.findall(rf'\b(?:{num_0_255}(?:\[\.\]|\.)){{3}}{num_0_255}\b', dig_output)
            if not regex_results_ip:
                raise ValueError("Couldn't find results:\n")
            resolved_addresses = regex_results_ip[::2]
            dns_server = regex_results_ip[1]
        else:
            regex_results_domain = re.findall(
                rf'\b^[\S]+|(?:{num_0_255}(?:\[\.\]|\.)){{3}}{num_0_255}\b', dig_output)
            if not regex_results_domain:
                raise ValueError("Couldn't find results:\n")
            resolved_addresses = regex_results_domain[0]
            dns_server = regex_results_domain[1]
    except Exception as e:
        return_error(str(e))
    return resolved_addresses, dns_server


''' COMMAND FUNCTION '''


def dig_command(args: dict[str, Any]) -> CommandResults:
    """Run Dig command on the server and get A record for the specified host

    Args:
        args (Dict[str, Any]): arguments for the command

    Returns:
        CommandResults: XSOAR command results
    """
    server = args.get('server', None)
    name = args.get('name', None)
    reverse_lookup = argToBoolean(args.get("reverseLookup"))

    if reverse_lookup:
        result = reverse_dig_result(server, name)
    else:
        result = dig_result(server, name)

    return CommandResults(
        outputs_prefix='digresults',
        outputs=result,
        ignore_auto_extract=True
    )


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    try:
        return_results(dig_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Dig. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
