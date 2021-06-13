import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


config_json = demisto.executeCommand("demisto-api-get", {"uri": "/system/config"})[0]["Contents"]["response"]
partition = "/"
if config_json.get("sysConf").get("disk.partitions.to.monitor", None):
    partition = config_json.get("sysConf").get("disk.partitions.to.monitor", None)

stats = demisto.executeCommand(
    "demisto-api-post",
    {
        "uri": "/statistics/widgets/query",
        "body": {
            "size": 1440,
            "dataType": "system",
            "params": {
                "timeFrame": "minutes"
            },
            "query": f"disk.usedPercent.{partition}",
            "dateRange": {
                "period": {
                    "byFrom": "hours",
                    "fromValue": 24
                }
            },
            "widgetType": "line"
        }
    })

res = stats[0]["Contents"]["response"]
output = []
counter = 0
higher = 0

buildNumber = demisto.executeCommand("DemistoVersion", {})[0]['Contents']['DemistoVersion']['buildNumber']
if int(buildNumber) >= 618657:
    # Line graph:
    for entry in res:
        higher = max(entry["data"][0], higher)
        if counter % 2 == 0:
            output.append({"name": counter, "data": [higher]})
            higher = 0
        counter += 1

data = {
    "Type": 17,
    "ContentsFormat": "line",
    "Contents": {
        "stats": output,
        "params": {
            "timeFrame": "minutes",
            "format": "HH:mm",
            "layout": "vertical"
        }
    }
}

demisto.results(data)
