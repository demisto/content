import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()
        args['queryType'] = 'Hosts'
        args['reultType'] = 'DistinctCount'
        res = demisto.executeCommand('XDRIncidentWidgetBase', args)
        return_results(res)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute XDRIncidentWidgetBase. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
