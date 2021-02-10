import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()
        args['queryType'] = 'Users'
        args['reultType'] = 'Top10'
        res = demisto.executeCommand('XDRIncidentWidgetBase', args)
        if isError(res):
            return_error(f'Error occured while trying to execute XDRIncidentWidgetBase script: {get_error(res)}')
        return_results(res)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute XDRIncidentWidgetBase. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
