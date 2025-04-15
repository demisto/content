import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()
        query = args.get('indicator_query', None)
        indicator_vals = argToList(args.get('indicator_values', None))
        indicator_ids = argToList(args.get('indicator_ids', None))
        do_not_whitelist = not argToBoolean(args.get('exclude', False))
        reason = args.get('exclusion_reason', '')

        # Ensure only one argument is supplied for the list of indicators to delete
        args = [query, indicator_vals, indicator_ids]
        if sum(bool(arg) for arg in args) != 1:
            return_error(
                "Invalid input: Exactly ONE of the following arguments must be provided: "
                "'indicator_query', 'indicator_values', or 'indicator_ids'."
            )

        if query:
            search_query = query
        elif indicator_vals:
            search_query = f"value:({' '.join(indicator_vals)})"
        elif indicator_ids:
            search_query = f"id:({' '.join(indicator_ids)})"
        else:
            search_query = ""
            demisto.debug(f"didn't match any condition. Initializing {search_query=}")

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
