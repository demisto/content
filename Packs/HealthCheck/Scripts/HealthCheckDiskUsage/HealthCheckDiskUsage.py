import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


RESOLUTION = ["Free up Disk Space with Data Archiving: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
              "cortex-xsoar-admin/manage-data/free-up-disc-space-with-data-archiving"]


def analyzeData(res):
    addActions = []

    if res[len(res) - 1]['data'][0] > 90:
        addActions.append({'category': 'Disk usage analysis', 'severity': 'High',
                           'description': "Disk usage has reached 90%", "resolution": f"{RESOLUTION[0]}"})
    elif res[len(res) - 1]['data'][0] > 80:
        addActions.append({'category': 'Disk usage analysis', 'severity': 'Medium',
                           'description': "Disk usage has reached 80%", "resolution": f"{RESOLUTION[0]}"})
    elif res[len(res) - 1]['data'][0] > 70:
        addActions.append({'category': 'Disk usage analysis', 'severity': 'Low',
                           'description': "Disk usage has reached 70%", "resolution": f"{RESOLUTION[0]}"})
    if (res[len(res) - 1]['data'][0] - res[0]['data'][0]) > 1:
        addActions.append({'category': 'Disk usage analysis', 'severity': 'High',
                           'description': "Disk usage was increased significantly in the last 24 hours",
                           "resolution": f"{RESOLUTION[0]}"})
    return addActions


incident = demisto.incidents()[0]
args = demisto.args()
isWidget = argToBoolean(args.get('isWidget', True))
widgetType = "number" if isWidget is True else "line"


partition = "/"
if incident['CustomFields']["serverconfiguration"]:
    for entry in incident['CustomFields']["serverconfiguration"]:
        if entry.get('key', "") == 'disk.partitions.to.monitor':
            partition = entry['value']


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
            "widgetType": widgetType
        }
    })

res = stats[0]["Contents"]["response"]

data = {
    "Type": 17,
    "ContentsFormat": widgetType,
    "Contents": {
        "stats": res,
        "params": {
            "currencySign": "%",
            "signAlignment": "right",
            "colors": {
                "isEnabled": True,
                "items": {
                    "#00CD33": {"value": -1},
                    "#FAC100": {"value": 60},
                    "#FF1B15": {"value": 80}
                },
                "type": "above"
            }
        }
    }
}

if isWidget is True:
    demisto.results(data)
else:
    addActions = analyzeData(res)
    results = CommandResults(
        readable_output="analyzeCPUUsage Done",
        outputs_prefix="actionableitems",
        outputs=addActions)

    return_results(results)
