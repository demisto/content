
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ipaddress
import traceback


''' COMMAND FUNCTION '''


def return_address_binary_command(args: Dict[str, Any]) -> CommandResults:

    ip_address = args.get('ip_address', None)

    ip_binary = str(ipaddress.ip_address(ip_address).__format__('b'))

    binary_object = {
        "address": ip_address,
        "binary": ip_binary
    }

    readable_output = tableToMarkdown(t=binary_object, name='Subnet Binary')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Binary',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=binary_object
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(return_address_binary_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute IPCalcReturnSubnetBinary. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
