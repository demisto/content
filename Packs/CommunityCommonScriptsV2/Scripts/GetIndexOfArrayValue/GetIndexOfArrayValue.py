import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from typing import Dict, Any
import traceback



''' MAIN FUNCTION '''


def main():
    try:
        array_val = demisto.args()['array_value']
        json_data = argToList(demisto.args()['value'])
        element_index=json_data.index(array_val)
        demisto.results(element_index)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')
''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

