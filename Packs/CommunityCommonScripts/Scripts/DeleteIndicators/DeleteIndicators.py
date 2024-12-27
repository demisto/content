import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()
        query = args.get('indicator_query', None)
        indicator_vals = args.get('indicator_values', None)
        indicator_ids = args.get('indicator_ids', None)
        do_not_whitelist = not argToBoolean(args.get('exclude', False))
        reason = args.get('exclusion_reason', '')

        # Ensure only one argument is supplied for the list of indicators to delete
        if (not query and not indicator_vals and not indicator_ids) or \
           ((query and indicator_vals) or (query and indicator_ids) or (indicator_vals and indicator_ids)):
            return_error("Exactly ONE of the following arguments is required: indicator_query, indicator_values, or indicator_ids")

        if query:
            search_query = query
        elif indicator_vals:
            search_query = f"value:({re.sub(',', ' ', indicator_vals)})"
        elif indicator_ids:
            search_query = f"id:({re.sub(',', ' ', indicator_ids)})"

        res = execute_command("deleteIndicators", {
            "query": search_query,
            "doNotWhitelist": do_not_whitelist,
            "reason": reason
        })
        if is_error(res):
            raise Exception(res)
        else:
            return_results(res)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute DeleteIndicators. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
