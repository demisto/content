""" Widget script for calculating "Who Broke Master" Stats

"""

import demistomock as demisto
from CommonServerPython import *

import traceback


''' MAIN FUNCTION '''


def main():
    try:
        return_results(TrendWidget(30, 25))
    except Exception as exc:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute WidgetQuarterlyIntegrations. Error: {str(exc)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
