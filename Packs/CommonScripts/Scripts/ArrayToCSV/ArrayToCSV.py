import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from traceback import format_exc


def arr_to_csv_command(array: list[str] | str) -> str:
    csv = ','.join(array)
    return csv


def main():     # pragma: no cover
    args = demisto.args()
    array = argToList(args.get('value'))
    try:
        return_results(arr_to_csv_command(array=array))
    except Exception as e:
        demisto.error(format_exc())
        return_error(f'ArrToCSV command failed. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
