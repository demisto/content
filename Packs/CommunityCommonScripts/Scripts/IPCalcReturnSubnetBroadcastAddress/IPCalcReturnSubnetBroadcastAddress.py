
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ipaddress
import traceback


''' COMMAND FUNCTION '''


def return_subnet_broadcast_address_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    broadcast_address = format(ipaddress.IPv4Network(subnet, strict=False).broadcast_address)

    readable_output = tableToMarkdown(headers='Address:', t=broadcast_address, name='Broadcast Address')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Address',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=broadcast_address,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(return_subnet_broadcast_address_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute IPCalcReturnSubnetBroadcastAddress. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
