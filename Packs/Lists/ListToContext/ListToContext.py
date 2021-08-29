
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''


def list_to_context(list_name: str) -> List:

    res = demisto.executeCommand('getList', {'listName': list_name})
    if (
        not isinstance(res, list)
        or 'Contents' not in res[0]
        or not isinstance(res[0]['Contents'], str)
        or res[0]['Contents'] == 'Item not found (8)'
    ):
        raise ValueError(f'Cannot retrieve list {list_name}')

    list_data: List = []
    data = res[0]['Contents']
    if data and len(data) > 0:
        list_data = data

    return list_data


''' COMMAND FUNCTION '''


def list_to_context_command(args: Dict[str, Any]) -> CommandResults:

    list_name = args.get('listName', None)
    if not list_name:
        raise ValueError('list not specified')

    result = list_to_context(list_name=list_name)

    print (result)

    return CommandResults(
        outputs_prefix='ListContent',
        outputs_key_field='',
        outputs=result,
    )
# TODO: ADD additional command functions that translate XSOAR inputs/outputs


''' MAIN FUNCTION '''


def main():
    try:
        # TODO: replace the invoked command function with yours
        return_results(list_to_context_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute AddDictToList. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
