import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    indicator_query = demisto.args().get("query")
    indicator_seen_days = int(demisto.args().get("seenDays"))

    if demisto.args().get("columns"):
        indicator_columns = [x.strip() for x in demisto.args().get("columns").split(",")]
    else:
        indicator_columns = ["id", "indicator_type", "value", "score", "timestamp",
                             "relatedIncCount", "sourceBrands", "expirationStatus", "expiration", "modified"]

    # body for the indicator request
    indicator_body = {
        "all": True,
        "filter": {
            "query": indicator_query,
            "sort": [{
                "field": "calculatedTime",
                "asc": False
            }],
            "period": {
                "by": "day",
                "fromValue": indicator_seen_days
            }
        },
        "columns": indicator_columns
    }

    # generate the file
    res = demisto.executeCommand("demisto-api-post", {"uri": "/indicators/batch/exportToCsv",
                                                      "body": indicator_body})[0]["Contents"]["response"]

    # download the file and return to the war room
    file = demisto.executeCommand("demisto-api-get", {"uri": f"/indicators/csv/{res}"})[0]["Contents"]["response"]
    demisto.results(fileResult(res, file))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
