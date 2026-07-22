import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def queryWidget(uri):
    stats = demisto.executeCommand(
        "core-api-post",
        {
            "uri": uri,
            "body": {
                "size": 31,
                "dataType": "incidents",
                "query": "",
                "dateRange": {"period": {"byFrom": "months", "fromValue": 6}},
                "widgetType": "line",
                "params": {"groupBy": ["occurred(w)"], "timeFrame": "weeks"},
            },
        },
    )
    if is_demisto_version_ge("8.0.0"):
        res = stats[0]["Contents"]["response"]["groups"]
    else:
        res = stats[0]["Contents"]["response"]

    data = {"Type": 17, "ContentsFormat": "line", "Contents": {"stats": res, "params": {"timeFrame": "weeks"}}}
    return data


ctx = demisto.context()
dataFromCtx = ctx.get("widgets")

if not dataFromCtx:
    # version 8
    if is_demisto_version_ge("8.0.0"):
        uri = "/xsoar/v2/statistics/widgets/query"
        res = queryWidget(uri)
        return_results(res)

    else:
        incident = demisto.incidents()[0]
        accountName = incident.get("account")
        accountName = f"acc_{accountName}/" if accountName != "" else ""
        uri = f"{accountName}statistics/widgets/query"
        res = queryWidget(uri)
        return_results(res)

else:
    data = {
        "Type": 17,
        "ContentsFormat": "line",
        "Contents": {"stats": dataFromCtx["IncidentsCreatedWeekly"], "params": {"timeFrame": "weeks"}},
    }
    demisto.results(data)
