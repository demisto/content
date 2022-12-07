import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_tab_names(source_layout):
    layout_data = demisto.incident()['CustomFields']['layoutdata']
    filterlist = ['War Room', 'Work Plan', 'Evidence Board', 'Canvas']
    tabs = [layout.get('tabs') for layout in layout_data if layout.get('name') == source_layout]
    tab_options = [tab.get('name') for tab in tabs[0] if tab.get('name') not in filterlist]
    return tab_options


def display_source_tab(args):
    source_layout = args.get('source_layout')
    result = get_tab_names(source_layout)
    demisto.results({'hidden': False, 'options': result})


def main():
    incident = demisto.incident()
    args = demisto.args()
    if args.get('source_layout') is None:
        args.update(
            {'source_layout': incident.get('CustomFields', {}).get('sourcelayout', '')}
        )

    try:
        display_source_tab(args)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Script. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
