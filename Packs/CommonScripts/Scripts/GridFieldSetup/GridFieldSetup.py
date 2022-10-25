import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from typing import Dict, Any


def grid_field_setup(keys: str, vals: dict, res_list: list) -> list[str]:
    """Returns a list of dictionaries based on the key/values provided.
    :type keys: ``str``
    :type vals: ``dict``
    :type res_list: ``list``
    :param keys: comma separated values used for keys (columns)
    :param vals: dictionary of the value assigned to keys
    :param res_list: list of current entries in gridfield (or blank list)
    :return: list of dictionaries
    """
    key_list = argToList(keys)
    num_entries = len(key_list)
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
    overwrite = args.get('overwrite')
    gridfield = args.get('gridfield')

    # logic here to check if empty result and set default list
    orig = demisto.alerts()[0].get('CustomFields').get(gridfield)
    if not orig or overwrite == "true":
        orig = []

    # list of all val keys
    valkeys = sorted([k for k in args.keys() if k.startswith('val')])

    # dictionary or all vals
    vals = {}
    for i, val in enumerate(valkeys, start=1):
        vals[f'val{i}'] = args.get(f'val{i}')

    # error is keys and value numbers don't align
    if len(argToList(keys)) != len(vals.keys()):
        raise ValueError('number of keys and values needs to be the same')

    # Call the standalone function and get the raw response
    result = grid_field_setup(keys, vals, orig)

    results = demisto.executeCommand("setIncident", {args.get('gridfield'): result})

    return results


''' MAIN FUNCTION '''


def main():
    try:
        return_results(grid_field_setup_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute GridFieldSetup. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
