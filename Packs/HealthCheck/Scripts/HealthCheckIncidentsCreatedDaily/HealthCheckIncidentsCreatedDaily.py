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
                "dateRange": {"period": {"byFrom": "days", "fromValue": 30}},
                "widgetType": "line",
                "params": {"groupBy": ["occurred(d)"], "timeFrame": "days"},
            },
        },
    )
    if is_demisto_version_ge("8.0.0"):
        res = stats[0]["Contents"]["response"]["groups"]
    else:
        res = stats[0]["Contents"]["response"]

    data = {"Type": 17, "ContentsFormat": "line", "Contents": {"stats": res, "params": {"timeFrame": "days"}}}
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
        "Contents": {"stats": dataFromCtx["IncidentsCreatedDaily"], "params": {"timeFrame": "days"}},
    }
    demisto.results(data)
