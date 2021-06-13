import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


stats = demisto.executeCommand(
    "demisto-api-post",
    {
        "uri": "/statistics/widgets/query",
        "body": {
            "size": 13,
            "dataType": "incidents",
            "query": "",
            "dateRange": {
                "period": {
                    "byFrom": "months",
                    "fromValue": 12
                }
            },
            "widgetType": "line",
            "params": {
                "groupBy": [
                    "occurred(m)",
                    "null"
                ],
                "timeFrame": "months"
            },
        },
    })

res = stats[0]["Contents"]["response"]

buildNumber = demisto.executeCommand("DemistoVersion", {})[0]['Contents']['DemistoVersion']['buildNumber']
if int(buildNumber) >= 618657:
    # Line graph:
    data = {
        "Type": 17,
        "ContentsFormat": "line",
        "Contents": {
            "stats": res,
            "params": {
                "timeFrame": "months"
            }
        }
    }

else:
    # Bar graph:
    output = []
    for entry in res:
        output.append({"name": entry["name"], "data": entry["data"]})

    data = {
        "Type": 17,
        "ContentsFormat": "bar",
        "Contents": {
            "stats": output,
            "params": {
                "layout": "horizontal"
            }
        }
    }

demisto.results(data)
