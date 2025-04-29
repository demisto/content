from time import sleep

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CoreXQLApiModule import *

urllib3.disable_warnings()


def shorten_text(text: str) -> str:
    parts = text.split()
    if len(parts) == 2:
        return f"{parts[0]}{parts[1][0].lower()}"
    return text  # Return original if not exactly two words


def search_for_indicator(args: dict):
    time_frame: str = args.get("time_frame", "7 days")
    data_set: str = args.get("data_set", "xdr_data")
    indicator: str = args["indicator"]
    query_name: str = args["query_name"]

    time_frame_for_query: str = shorten_text(time_frame)
    query: str = f'config timeframe = {time_frame_for_query} | search "{indicator}" dataset = {data_set}'

    res = demisto.executeCommand(command="xdr-xql-generic-query", args={"query": query, "query_name": query_name})
    query_id = res[0]["Metadata"]["pollingArgs"]["query_id"]
    while res[0]["Contents"]["status"] == "PENDING":
        demisto.results("Query is still running, it may take a little while...")
        sleep(30)
        res = demisto.executeCommand(command="xdr-xql-get-query-results", args={"query_id": query_id})
    return_results(res)


def main():
    try:
        search_for_indicator(demisto.args())
    except Exception as e:
        return_error("Error occurred while executing search_for_indicator. Exception info:\n" + str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
