
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ipcalc
import traceback


''' COMMAND FUNCTION '''


def return_check_collision_command(args: Dict[str, Any]) -> CommandResults:

    subnet1 = args.get('subnet_one', None)
    subnet2 = args.get('subnet_two', None)

    if not subnet1 or not subnet2:
        raise ValueError('Collision subnets are not specified')

    collision_result = str(ipcalc.Network(subnet1).check_collision(subnet2))

    collision_object = {
        "subnet1": subnet1,
        "subnet2": subnet2,
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
