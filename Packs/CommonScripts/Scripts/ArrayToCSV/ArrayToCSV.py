from typing import Iterable
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from traceback import format_exc


def arr_to_csv_command(array: Iterable) -> CommandResults:
    csv = ','.join(array)
    return CommandResults(
        readable_output=csv
    )


def main():  # pragma: no cover
    args = demisto.args()
    array = argToList(args.get('value'))
    try:
        results = arr_to_csv_command(array=array)
        return_results(results)
    except Exception as e:
        demisto.error(format_exc())
        return_error(f'ArrToCSV command failed. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
