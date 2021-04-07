"""RemoveKeyFromList
Removes a Key from a JSON-backed List
"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''


def remove_key_from_list(list_name: str, key_name: str) -> str:
    res = demisto.executeCommand('getList', {'listName': list_name})
    if (
        not isinstance(res, list)
        or 'Contents' not in res[0]
        or not isinstance(res[0]['Contents'], str)
        or res[0]['Contents'] == 'Item not found (8)'
    ):
        raise ValueError(f'Cannot retrieve list {list_name}')

    list_data: Dict = {}
    data: str = res[0]['Contents']
    if data and len(data) > 0:
        try:
            list_data = json.loads(data)
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'List does not contain valid JSON data: {e}')

    elem = list_data.pop(key_name, None)
    if not elem:
        return f'Key {key_name} not found in list {list_name}, cannot remove.'

    demisto.executeCommand('setList', {'listName': list_name, 'listData': json.dumps(list_data)})
    return f'Successfully removed key {key_name} from list {list_name}.'


''' COMMAND FUNCTION '''


def remove_key_from_list_command(args: Dict[str, Any]) -> CommandResults:

    list_name = args.get('listName', None)
    if not list_name:
        raise ValueError('listName must be specified')

    key_name = args.get('keyName', None)
    if not key_name:
        raise ValueError('keyName must be specified')

    # Call the standalone function and get the raw response
    result = remove_key_from_list(list_name, key_name)

    return CommandResults(
        readable_output=result
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(remove_key_from_list_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute RemoveKeyFromList. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
