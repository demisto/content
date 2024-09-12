import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def convert_unix_to_human_readable(timestamp):
    hr_timestamp = demisto.executeCommand("TimeStampToDate", {"value": timestamp})[0]['Contents']
    return hr_timestamp

def get_all_endpoints(xdr_query_args):
    # Get all XDR endpoints
    endpoints = []
    should_term_loop = False
    # Loop until we reach end of endpoint results (blank page returned)
    while should_term_loop is False:
        page_res = demisto.executeCommand("xdr-get-endpoints", xdr_query_args)
        if is_error(page_res):
            return_error(get_error(page_res))
        else:
            page_res = page_res[0]['Contents']
        # Results returned - Increment page and keep looping
        if len(page_res) > 0:
            endpoints += page_res
            xdr_query_args['page'] += 1
        # No results returned - No more endpoints to get - End while loop
        else:
            should_term_loop = True

    # List of timestamp-converted endpoints to store to context (if endpoint_status arg provided, keep given status only)
    conv_endpoints = []

    # Iterate through endpoints and convert timestamps to human-readable format
    for endpoint in endpoints:
        # Convert Unix epoch timestamps to human-readable format
        endpoint['last_seen'] = convert_unix_to_human_readable(endpoint['last_seen'])
        if 'first_seen' in endpoint and 'install_date' in endpoint:
            endpoint['first_seen'] = convert_unix_to_human_readable(endpoint['first_seen'])
            endpoint['install_date'] = convert_unix_to_human_readable(endpoint['install_date'])

        # Add to output list
        conv_endpoints.append(endpoint)
    return conv_endpoints

def main():
    try:
        args = demisto.args()
        # Initialize args for XDR get endpoints query
        xdr_query_args = {}
        provided_status = args.get('endpoint_status', '')

        if 'last_seen_lte' in args:
            xdr_query_args['last_seen_lte'] = args.get('last_seen_lte', '')
        if 'last_seen_gte' in args:
            xdr_query_args['last_seen_gte'] = args.get('last_seen_gte', '')
        xdr_query_args['status'] = provided_status
        xdr_query_args['platform'] = args.get('platform', '')
        xdr_query_args['group_name'] = args.get('group_name', '')
        # Start with first page of results
        xdr_query_args['page'] = 0

        result_endpoints = get_all_endpoints(xdr_query_args)

        # Format outputs
        context = {
            f'PaloAltoNetworksXDR.{provided_status.title()}Endpoint': result_endpoints,
            f'PaloAltoNetworksXDR.{provided_status.title()}EndpointsCount': len(result_endpoints),
        }
        res = (
            tableToMarkdown('Endpoints', result_endpoints),
            context,
            result_endpoints
        )
        return_outputs(*res)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute XDRGetAllEndpointsHumanReadableTimestamps. Error: {str(ex)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
