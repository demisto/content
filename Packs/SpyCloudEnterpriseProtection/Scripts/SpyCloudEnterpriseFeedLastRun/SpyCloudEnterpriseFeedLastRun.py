from CommonServerPython import *  # noqa: F401

""" MAIN FUNCTION """


def main():
    try:
        search_result = demisto.executeCommand(
            "SearchIncidentsV2", {"query": "SpyCloud Watchlist Incident Job"}
        )
        if search_result[0].get("Contents"):
            data = search_result[0].get("Contents")[0].get("Contents").get("data")
            last_run = arg_to_datetime(data[-1].get("created"))
            if last_run:
                flag = len(data) > 1 and last_run.date() == get_current_time().date()

            return_results(CommandResults(outputs={"LastRun": {"islastRun": flag}}))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
