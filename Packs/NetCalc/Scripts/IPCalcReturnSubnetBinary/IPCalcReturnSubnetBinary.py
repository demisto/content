
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ipcalc
import traceback


''' COMMAND FUNCTION '''


def return_subnet_binary_command(args: Dict[str, Any]) -> CommandResults:

    subnet = args.get('subnet', None)

    if not subnet:
        raise ValueError('subnet not specified')

    subnet_binary = str(ipcalc.Network(subnet).bin())

    binary_object = {
        "subnet": subnet,
        "binary": subnet_binary
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
        return_results(return_subnet_binary_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute IPCalcReturnSubnetBinary. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
