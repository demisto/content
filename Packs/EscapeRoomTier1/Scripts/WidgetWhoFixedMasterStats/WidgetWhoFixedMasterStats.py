""" Widget script for calculating "Who Fixed Master" Stats

"""

import random
import traceback

import demistomock as demisto
from CommonServerPython import *

# COMMAND FUNCTION #


def create_bar_widget() -> BarColumnPieWidget:
    widget = BarColumnPieWidget()
    random_ranges = {
        'Eli': {'start': 10, 'stop': 25},
        'Itay': {'start': 5, 'stop': 10},
        'Jochman': {'start': 0, 'stop': 5},
        'Shahaf': {'start': 0, 'stop': 5},
        'Yaakovi': {'start': 5, 'stop': 15},
    }

    for user, random_range in random_ranges.items():
        widget.add_category(user, max(0, random.randrange(**random_range)))

    return widget


# MAIN FUNCTION #


def main():
    try:
        widget = create_bar_widget()
        return_results(widget)
    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute WidgetWhoFixedMasterStats. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
