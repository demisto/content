import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def grid_field_setup(keys: list[str], vals: dict, res_list: list) -> list[str]:
    """Returns a list of dictionaries based on the key/values provided.
    :type keys: ``str``
    :type vals: ``dict``
    :type res_list: ``list``
    :param keys: comma separated values used for keys (columns)
    :param vals: dictionary of the value assigned to keys
    :param res_list: list of current entries in gridfield (or blank list)
    :return: list of dictionaries
    """
    temp = {}
    for i, key in enumerate(keys, start=1):
        if vals[f'val{i}'] == "TIMESTAMP":
            temp[key] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            temp[key] = vals[f'val{i}']
    res_list.append(temp)

    return res_list


''' COMMAND FUNCTION '''


def grid_field_setup_command(args: dict[str, str]) -> CommandResults:
    keys = argToList(args.pop('keys', []))
    overwrite = args.pop('overwrite', False)
    gridfield = args.pop('gridfield', None)

    # logic here to check if empty result and set default list
    fields = demisto.incidents()[0].get('CustomFields')
    if not fields:
        raise ValueError('no Custom Fields present')
    orig = fields.get(gridfield)
    if not orig or argToBoolean(overwrite):
        orig = []

    # dictionary or all vals
    vals = {k: v for k, v in args.items() if k.startswith('val')}

    # error is keys and value numbers don't align
    if len(keys) != len(vals):
        raise ValueError('number of keys and values needs to be the same')

    # Call the standalone function and get the raw response
    result = grid_field_setup(keys, vals, orig)

    results = demisto.executeCommand("setIncident", {gridfield: result})

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
