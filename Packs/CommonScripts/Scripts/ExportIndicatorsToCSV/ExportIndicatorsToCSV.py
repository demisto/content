import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    indicator_query = demisto.args().get("query")
    seen_days = arg_to_number(demisto.args().get("seenDays", "7"))
    columns_arg = demisto.args().get("columns")
    if columns_arg:
        indicator_columns = [x.strip() for x in columns_arg.split(",")]
    else:
        indicator_columns = [
            "id",
            "indicator_type",
            "value",
            "score",
            "timestamp",
            "relatedIncCount",
            "sourceBrands",
            "expirationStatus",
            "expiration",
            "modified",
        ]

    # body for the indicator request
    indicator_body = {
        "all": True,
        "filter": {
            "query": indicator_query,
            "sort": [{"field": "calculatedTime", "asc": False}],
            "period": {"by": "day", "fromValue": seen_days},
        },
        "columns": indicator_columns,
    }

    # generate the file
    res = demisto.executeCommand("core-api-post", {"uri": "/indicators/batch/exportToCsv", "body": indicator_body})[0][
        "Contents"
    ]["response"]

    # download the file and return to the war room
    file = demisto.executeCommand("core-api-get", {"uri": f"/indicators/csv/{res}"})[0]["Contents"]["response"]
    demisto.results(fileResult(res, file))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
