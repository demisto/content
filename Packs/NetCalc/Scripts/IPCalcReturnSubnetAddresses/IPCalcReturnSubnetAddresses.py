
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ipaddress
import traceback


''' COMMAND FUNCTION '''


def return_subnet_addresses_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)
    address_objects = ipaddress.IPv4Network(subnet, strict=False).hosts()

    addresses = []

    for address_object in address_objects:
        addresses.append(format(address_object))

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
