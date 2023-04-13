import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from typing import Dict, Any
import traceback


# TODO: ADD additional command functions that translate XSOAR inputs/outputs


''' MAIN FUNCTION '''


def get_sliced_data(list_data, initial_range, end_range):

    sliced_data = list_data[initial_range:end_range]

    return sliced_data


def main():
    try:
        initial_range = int(demisto.args()['InitialRange'])
        end_range = int(demisto.args()['EndRange'])
        list_data = argToList(demisto.args()['value'])
        return_results(get_sliced_data(list_data, initial_range, end_range))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
