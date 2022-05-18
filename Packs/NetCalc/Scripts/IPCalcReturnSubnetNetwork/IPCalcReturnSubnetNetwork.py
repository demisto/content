
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ipaddress
import traceback


''' COMMAND FUNCTION '''


def return_subnet_network_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    network = format(ipaddress.IPv4Network(subnet, strict=False).network_address)

    readable_output = tableToMarkdown(headers='Network:', t=network, name='Subnet Network')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Network',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=network,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(return_subnet_network_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute IPCalcReturnSubnetNetwork. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
