
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ipcalc
import traceback


''' COMMAND FUNCTION '''


def return_subnet_addresses_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    addresses = []

    for x in ipcalc.Network(subnet):
        addresses.append(str(x))

    readable_output = tableToMarkdown(headers='IP Addresses:', t=addresses, name='List Addresses')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Address',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=addresses,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(return_subnet_addresses_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute IPCalcReturnSubnetAddresses. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
