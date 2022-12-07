import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def clear_dest_tab():
    execute_command('setIncident', {'selectdestinationtab': ' '})


def main():
    try:
        clear_dest_tab()

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
