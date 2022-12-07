import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def clear_source_layout():
    execute_command('setIncident', {'sourcelayout': ''})


def clear_source_tab():
    execute_command('setIncident', {'selectsourcetab': ''})


def clear_source_section():
    execute_command('setIncident', {'selectsourcesection': ''})


def clear_dest_layout():
    execute_command('setIncident', {'destinationlayout': ''})


def clear_dest_tab():
    execute_command('setIncident', {'selectdestinationtab': ''})


def clear_dest_section():
    execute_command('setIncident', {'selectdestinationsection': ''})


def main():
    try:
        clear_source_layout()
        clear_source_tab()
        clear_source_section()
        clear_dest_layout()
        clear_dest_tab()
        clear_dest_section()
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
