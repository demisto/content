""" Widget script for calculating "Who Broke Master" Stats

"""

import traceback

import demistomock as demisto
from CommonServerPython import *

# MAIN FUNCTION #


def main():
    try:
        return_results(TrendWidget(30, 25))
    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute WidgetQuarterlyIntegrations. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
