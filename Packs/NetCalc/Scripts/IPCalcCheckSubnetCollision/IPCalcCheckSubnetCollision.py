
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ipaddress
import traceback


''' COMMAND FUNCTION '''


def return_check_collision_command(args: Dict[str, Any]) -> CommandResults:

    subnet1 = ipaddress.IPv4Network(args.get('subnet_one', None), strict=False)
    subnet2 = ipaddress.IPv4Network(args.get('subnet_two', None), strict=False)

    collision_result = subnet1.overlaps(subnet2)

    collision_object = {
        "subnet1": format(subnet1),
        "subnet2": format(subnet2),
        "collision": collision_result
    }

    readable_output = tableToMarkdown(t=collision_object, name='Collision Check')

    return CommandResults(
        outputs_prefix='IPCalc.IP.Collision',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=collision_object,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(return_check_collision_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute IPCalcCheckSubnetCollision. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
