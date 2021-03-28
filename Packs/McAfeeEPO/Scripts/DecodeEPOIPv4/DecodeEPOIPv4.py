
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''


def decimal_to_ip(decimal: str) -> str:
    ipv4_address = float(decimal) + 2147483647 + 1
    octet1 = ipv4_address / 16777216
    ipv4_address = ipv4_address % 16777216
    octet2 = ipv4_address / 65536
    ipv4_address = ipv4_address % 65536
    octet3 = ipv4_address / 256
    ipv4_address = ipv4_address % 256
    octet4 = ipv4_address
    return f"{int(octet1)}.{int(octet2)}.{int(octet3)}.{int(octet4)}"


''' COMMAND FUNCTION '''


def decimal_to_ip_command(args: Dict[str, Any]) -> str:

    decimal = args.get('value') or args.get('decimal')
    if not decimal:
        raise ValueError('decimal value not specified')

    return decimal_to_ip(decimal)


''' MAIN FUNCTION '''


def main():
    try:
        return_results(decimal_to_ip_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
