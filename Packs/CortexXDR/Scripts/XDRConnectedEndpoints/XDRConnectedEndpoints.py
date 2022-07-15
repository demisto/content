import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()
        last_seen_gte = args.get('from')
        last_seen_lte = args.get('to')

        get_endpoints_args = {'status': 'connected'}

        if last_seen_gte:
            get_endpoints_args['last_seen_gte'] = last_seen_gte
        if last_seen_lte and last_seen_lte != '0001-01-01T00:00:00Z':
            get_endpoints_args['last_seen_lte'] = last_seen_lte

        res = demisto.executeCommand('xdr-get-endpoints-by-status', get_endpoints_args)
        if isError(res):
            return_error(f'Error occurred while trying to get XDR endpoints: {get_error(res)}')

        count = list(res[0].get('EntryContext').values())[0].get('count')
        return_results(count)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute XDRConnectedEndpoints. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
