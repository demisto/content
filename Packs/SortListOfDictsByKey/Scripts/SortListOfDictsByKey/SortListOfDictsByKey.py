import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Sort a list of dictionaries by any key of the dictionaries. Can sort in reverse if set to true.
"""


def sort_list_of_dicts_by_key(args: Dict[str, Any]) -> CommandResults:

    _list = args.get('value', None)
    key = args.get('key', None)
    reverse_flag = argToBoolean(args.get('reverse', False))

    if not _list:
        raise ValueError('List not provided')

    _list.sort(key=lambda x: x[key], reverse=reverse)

    return CommandResults(
        outputs_prefix='Sorted List',
        outputs_key_field='SortedList',
        outputs=_list,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(sort_list_of_dicts_by_key(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute SortListOfDictsByKey. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
