import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ctx = demisto.context()
dataFromCtx = ctx.get("widgets")
if not dataFromCtx:
    incident = demisto.incidents()[0]
    accountName = incident.get('account')
    accountName = f"acc_{accountName}/" if accountName != "" else ""

    stats = demisto.executeCommand(
        "demisto-api-post",
        {
            "uri": f"{accountName}statistics/widgets/query",
            "body": {
                "size": 31,
                "dataType": "incidents",
                "query": "",
                "dateRange": {
                    "period": {
                        "byFrom": "days",
                        "fromValue": 30
                    }
                },
                "widgetType": "line",
                "params": {
                    "groupBy": [
                        "occurred(d)",
                        "null"
                    ],
                    "timeFrame": "days"
                },
            },
        })

    res = stats[0]["Contents"]["response"]
    data = {
        "Type": 17,
        "ContentsFormat": "line",
        "Contents": {
            "stats": res,
            "params": {
                "timeFrame": "days"
            }
        }
    }
    demisto.results(data)
else:
    data = {
        "Type": 17,
        "ContentsFormat": "line",
        "Contents": {
            "stats": dataFromCtx['IncidentsCreatedDaily'],
            "params": {
                "timeFrame": "days"
            }
        }
    }
    demisto.results(data)
