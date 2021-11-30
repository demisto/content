
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ipaddress
import traceback


''' COMMAND FUNCTION '''


def return_address_info_command(args: Dict[str, Any]) -> CommandResults:

    ip_address = args.get('ip_address', None)

    address_info = 'unspecified'

    if ipaddress.ip_address(ip_address).is_multicast:
        address_info = 'multicast'
    elif ipaddress.ip_address(ip_address).is_private:
        address_info = 'private'
    elif ipaddress.ip_address(ip_address).is_global:
        address_info = 'global'
    elif ipaddress.ip_address(ip_address).is_reserved:
        address_info = 'reserved'
    elif ipaddress.ip_address(ip_address).is_loopback:
        address_info = 'loopback'
    elif ipaddress.ip_address(ip_address).is_link_local:
        address_info = 'link_local'
    elif ipaddress.ip_address(ip_address). is_unspecified:
        address_info = 'unspecified'

    info_object = {
        "address": ip_address,
        "allocation": address_info
    }

    readable_output = tableToMarkdown(t=info_object, name='Iana Allocation')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Allocation',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=info_object
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(return_address_info_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute IPCalcReturnSubnetIANAAllocation. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
