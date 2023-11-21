import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback


def get_range_command(indexes: List[str], val: List[Any]) -> List[Any]:
    """
         Filter list with a given range.
         Args:
             indexes (list): indexes to filter.
             val (list): list to filter .
         Returns:
             filtered list.
     """
    result = []
    for index in indexes:
        if '-' in str(index):
            start, end = index.split('-')
            start = int(start) if start else 0
            end = int(end) if end else len(val)
            for element in val[start:end + 1]:
                result.append(element)
        else:
            result.append(val[int(index)])
    return result


def main():
    try:
        args = demisto.args()
        val = safe_load_json(args.get('value', ''))
        indexes = argToList(args.get('range', ''))
        return_results(results=get_range_command(indexes, val))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GetRange. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
