import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()
        last_seen_gte = args.get('fromDate')
        last_seen_lte = args.get('toDate')
        limit = args.get('limit', '100')

        get_endpoints_args = {'limit': limit}

        if last_seen_gte:
            get_endpoints_args['last_seen_gte'] = last_seen_gte
        if last_seen_lte and last_seen_lte != '0001-01-01T00:00:00Z':
            get_endpoints_args['last_seen_lte'] = last_seen_lte

        res = demisto.executeCommand('xdr-get-endpoints', get_endpoints_args)
        if isError(res):
            return_error(f'Error occurred while trying to get XDR endpoints: {get_error(res)}')
        endpoints = res[0]['Contents']

        connected_endpoints = 0
        for endpoint in endpoints:
            if endpoint.get('endpoint_status') == 'CONNECTED':
                connected_endpoints = connected_endpoints + 1

        return_results(str(connected_endpoints))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute XDRConnectedEndpoints. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
