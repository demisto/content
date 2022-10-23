import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from typing import Dict, Any
import traceback


def grid_field_setup(keys: Optional[Any], vals: dict) -> List[Dict[str, Any]]:
    """Returns a list of dictionaries based on the key/values provided.
    :type keys: ``str``
    :type vals: ``dict``
    :param keys: comma separated values used for keys (columns)
    :param vals: dictionary of the value assigned to keys
    :return: list of dictionaries
    """
    if keys:
        key_list = keys.split(',')
    num_entries = len(key_list)
    res_list = []
    temp = {}
    count = 0
    while count < num_entries:
        tkey = 'val' + str(count + 1)
        temp[key_list[count]] = vals[tkey]
        count += 1
    res_list.append(temp)

    return res_list


''' COMMAND FUNCTION '''


def grid_field_setup_command(args: Dict[str, Any]) -> CommandResults:
    keys = args.get('keys')
    context_path = args.get('context_path')
    # list of all val keys
    valkeys = sorted([k for k in args.keys() if k.startswith('val')])

    # dictionary or all vals
    vals = {}
    for i, val in enumerate(valkeys, start=1):
        vals[f'val{i}'] = args.get(f'val{i}')

    # error is keys and value numbers don't align
    if len(argToList(keys)) > len(valkeys):
        raise ValueError('number of keys and values needs to be the same')

    # Call the standalone function and get the raw response
    result = grid_field_setup(keys, vals)

    return CommandResults(
        outputs_prefix=context_path,
        outputs_key_field='',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(grid_field_setup_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute GridFieldSetup. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
