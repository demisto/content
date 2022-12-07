import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def filter_source_names(copy_type):
    layout_data = demisto.incident()['CustomFields']['layoutdata']
    source_options = [layout.get('name') for layout in layout_data if layout.get('type') == copy_type]
    return source_options


def display_source_layout(args):
    source_type = args.get('source_type')
    result = filter_source_names(source_type)
    demisto.results({'hidden': False, 'options': result})


def main():
    incident = demisto.incident()
    args = demisto.args()
    # sets script args to custom field values for when the scripts are used via a layout/field display
    try:
        incident = demisto.incident()
        args = demisto.args()
        if args.get('source_type') is None:
            args.update(
                {'source_type': incident.get('CustomFields', {}).get('selectcopytype', 'incident')}
            )
        display_source_layout(args)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
