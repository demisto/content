""" Widget script for calculating "Who Broke Master" Stats

"""

import traceback

import demistomock as demisto
from CommonServerPython import *

# COMMAND FUNCTION #


def create_bar_widget() -> BarColumnPieWidget:
    widget = BarColumnPieWidget()
    task_time_mapping = {
        'Integrations': 6,
        'Bugs': 3,
        'Contributions': 3,
        'Dev-Tasks': 3,
    }

    for task, time_period in task_time_mapping.items():
        widget.add_category(task, time_period)

    return widget


# MAIN FUNCTION #


def main():
    try:
        widget = create_bar_widget()
        return_results(widget)
    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute WidgetContentDevTimeCycle. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
