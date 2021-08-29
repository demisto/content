
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''


# TODO: REMOVE the following dummy function:
def add_objects_to_list(listname: str, object: Dict, match_id: str, allowdups: bool) -> Dict[str, str]:

    return {"dummy": dummy}


''' COMMAND FUNCTION '''


# TODO: REMOVE the following dummy command function
def add_objects_to_list_command(args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the standalone function and get the raw response
    result = add_objects_to_list(dummy)

    return CommandResults(
        outputs_prefix='AddDictToList',
        outputs_key_field='',
        outputs=result,
    )
# TODO: ADD additional command functions that translate XSOAR inputs/outputs


''' MAIN FUNCTION '''


def main():
    try:
        # TODO: replace the invoked command function with yours
        return_results(basescript_dummy_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute AddDictToList. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
