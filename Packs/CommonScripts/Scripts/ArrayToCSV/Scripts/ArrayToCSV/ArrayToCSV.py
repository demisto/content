import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def arr_to_csv(array):
    csv = ','.join(array)
    return_results(csv)


def arr_to_csv_command(array) -> CommandResults:
    res = arr_to_csv(array=array)
    return CommandResults(
        readable_output=res
    )


def main():
    args = demisto.args()
    array = args.get('value')
    try:
        results = arr_to_csv_command(array=array)
        return_results(results)
    except Exception as e:
        demisto.debug('Ooops, Something aint working!')
        LOG.print_log()
        demisto.debug(e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
