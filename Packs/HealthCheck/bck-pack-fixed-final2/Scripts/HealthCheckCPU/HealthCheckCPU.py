import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def analyzeData(res):
    lowFound = 0
    medFound = 0
    highFound = 0
    lowRes = False
    medRes = False
    highRes = False

    for item in res:
        if not lowRes:
            if item['data'][0] >= 70:
                lowFound += 1
                if lowFound >= 60:
                    lowRes = True
            else:
                lowFound = 0

        if not medRes:
            if item['data'][0] >= 30:
                medFound += 1
                if medFound >= 5:
                    medRes = True
            else:
                medFound = 0

        if not highRes:
            if item['data'][0] >= 90:
                highFound += 1
                if highFound >= 1:
                    highRes = True
            else:
                highFound = 0

    if lowRes or medRes or highRes:
        addActions = []

        if highRes:
            addActions.append({'category': 'CPU analysis', 'severity': 'High', 'description': "CPU has reached 90%"})

        if medRes:
            addActions.append({'category': 'CPU analysis', 'severity': 'Medium',
                               'description': "CPU has reached 80% for 10 minutes"})

        if lowRes:
            addActions.append({'category': 'CPU analysis', 'severity': 'Low',
                               'description': "CPU has reached 70% for 30 minutes"})
        return addActions
    else:
        return None


# Main
args = demisto.args()
isWidget = argToBoolean(args.get('isWidget', True))
stats = demisto.executeCommand(
    "demisto-api-post",
    {
        "uri": "/statistics/widgets/query",
        "body": {
            "size": 1440,
            "dataType": "system",
            "params": {
                "timeFrame": "minutes",
                "format": "HH:mm",
            },
            "query": "cpu.usedPercent",
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
if isWidget == True:
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

    else:
        # Bar graph:
        now = datetime.utcnow()
        then = now - timedelta(days=1)
        for entry in res:
            higher = max(entry["data"][0], higher)
            if counter % 60 == 0:
                then = then + timedelta(hours=1)
                name = then.strftime("%H:%M")
                output.append({"name": name, "data": [higher]})
                higher = 0
            counter += 1

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
else:
    addActions = analyzeData(res)
    results = CommandResults(
        readable_output="analyzeCPUUsage Done",
        outputs_prefix="actionableitems",
        outputs=addActions)

    return_results(results)
