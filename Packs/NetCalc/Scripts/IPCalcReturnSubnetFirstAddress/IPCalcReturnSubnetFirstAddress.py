
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ipcalc
import traceback


''' COMMAND FUNCTION '''


def return_subnet_first_address_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    if not subnet:
        raise ValueError('subnet not specified')

    first_address = str(ipcalc.Network(subnet).host_first())

    readable_output = tableToMarkdown(headers='Address:', t=first_address, name='First Address')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Address',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=first_address,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(return_subnet_first_address_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute IPCalcReturnSubnetFirstAddress. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
