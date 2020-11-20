""" Widget script for calculating "Who Fixed Master" Stats

"""

import demistomock as demisto
from CommonServerPython import *

import traceback
import random


''' COMMAND FUNCTION '''


def create_bar_widget() -> BarColumnPieWidget:
    widget = BarColumnPieWidget()
    random_ranges = {
        'Yaakovi': {'start': 10, 'stop': 25},
        'Kozakish': {'start': 0, 'stop': 5},
        'Itay': {'start': 5, 'stop': 15},
        'Andrew': {'start': 0, 'stop': 5},
        'Hod': {'start': 0, 'stop': 10},
        'Shahaf': {'start': 0, 'stop': 5},
    }

    for user, random_range in random_ranges.items():
        widget.add_category(user, max(0, random.randrange(**random_range)))

    return widget


''' MAIN FUNCTION '''


def main():
    try:
        widget = create_bar_widget()
        return_results(widget)
    except Exception as exc:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute WidgetWhoFixedMasterStats. Error: {str(exc)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
