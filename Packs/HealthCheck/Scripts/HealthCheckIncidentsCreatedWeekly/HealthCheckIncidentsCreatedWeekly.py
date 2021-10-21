import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()[0]
accountName = incident.get('account')
accountName = f"acc_{accountName}" if accountName != "" else ""

stats = demisto.executeCommand(
    "demisto-api-post",
    {
        "uri": f"{accountName}/statistics/widgets/query",
        "body": {
            "size": 30,
            "dataType": "incidents",
            "query": "",
            "dateRange": {
                "period": {
                    "byFrom": "months",
                    "fromValue": 6
                }
            },
            "widgetType": "line",
            "params": {
                "groupBy": [
                    "occurred(w)",
                    "null"
                ],
                "timeFrame": "weeks"
            },
        },
    })

res = stats[0]["Contents"]["response"]

buildNumber = demisto.executeCommand("DemistoVersion", {})[0]['Contents']['DemistoVersion']['buildNumber']
# in local development instances, the build number will be "REPLACE_THIS_WITH_CI_BUILD_NUM"
buildNumber = f'{buildNumber}' if buildNumber != "REPLACE_THIS_WITH_CI_BUILD_NUM" else "618658"

if int(buildNumber) >= 618657:
    # Line graph:
    data = {
        "Type": 17,
        "ContentsFormat": "line",
        "Contents": {
            "stats": res,
            "params": {
                "timeFrame": "weeks"
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
