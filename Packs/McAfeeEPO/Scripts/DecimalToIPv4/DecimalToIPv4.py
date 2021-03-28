
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''


def decimal_to_ip(decimal: str) -> Dict[str, str]:
    ipv4_address = ""
    for i in range(4):
        ip1 = ""
        for j in range(8):
            ip1 = str(decimal % 2) + ip1
            decimal = decimal >> 1
        ipv4_address = str(int(ip1, 2)) + "." + ipv4_address
    return {"ipv4": ipv4_address.strip(".")}


''' COMMAND FUNCTION '''


def decimal_to_ip_command(args: Dict[str, Any]) -> CommandResults:

    decimal = int(args.get('decimal', None))
    if not decimal:
        raise ValueError('decimal value not specified')

    result = decimal_to_ip(decimal)

    return CommandResults(
        outputs_prefix='ConvertedIPv4',
        outputs_key_field='',
        outputs=result,
    )


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
