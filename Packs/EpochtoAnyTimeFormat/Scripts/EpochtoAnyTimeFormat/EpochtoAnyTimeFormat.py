import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback
import datetime as dt


''' STANDALONE FUNCTION '''


def epoch_to_datetime(epoch_value, format_value):

    converted_datetime = dt.datetime.utcfromtimestamp(epoch_value).strftime(format_value)

    return converted_datetime


''' COMMAND FUNCTION '''


def epoch_to_datetime_command(args):

    epoch_value = int(args.get('value'))
    format_value = str(demisto.getArg('format'))

    if not epoch_value:
        raise ValueError('Epoch time not specified. Please provide an Epoch/Unix value')

    results = epoch_to_datetime(epoch_value, format_value)

    return results


''' MAIN FUNCTION '''


def main():
    try:
        return_results(epoch_to_datetime_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
