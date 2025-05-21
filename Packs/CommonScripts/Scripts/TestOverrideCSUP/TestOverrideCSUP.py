"""Base Script for Cortex XSIAM
This is an empty script with some basic structure according
to the code conventions.
MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback


def main():
    try:
        args = demisto.args()
        my_bool = args.get('my_arg')
        # Tests that the argToBoolean func is called from the CSUP instead of the CSP for system scripts
        res = argToBoolean(my_bool)
        return_results(res)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()