import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


RESOLUTION = [
    "Performance Tuning of Cortex XSOAR Server: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
    "cortex-xsoar-admin/cortex-xsoar-overview/performance-tuning-of-cortex-xsoar-server"
]
XSOARV8_HTML_STYLE = "color:#FFBE98;text-align:center;font-size:150%;>"


def analyzeData(res):
    lowFound = 0
    medFound = 0
    lowRes = False
    medRes = False
    highRes = False

    for item in res:
        if not lowRes:
            if item["data"][0] >= 70:
                lowFound += 1
                if lowFound >= 30:
                    lowRes = True
            else:
                lowFound = 0

        if not medRes:
            if item["data"][0] >= 80:
                medFound += 1
                if medFound >= 10:
                    medRes = True
            else:
                medFound = 0

        if not highRes and item["data"][0] >= 90:
            highRes = True
    if lowRes or medRes or highRes:
        addActions = []

        if highRes:
            addActions.append(
                {
                    "category": "Memory analysis",
                    "severity": "High",
                    "description": "Memory has reached 90%",
                    "resolution": f"{RESOLUTION[0]}",
                }
            )

        if medRes:
            addActions.append(
                {
                    "category": "Memory analysis",
                    "severity": "Medium",
                    "description": "Memory has reached 80% for 10 minutes",
                    "resolution": f"{RESOLUTION[0]}",
                }
            )

        if lowRes:
            addActions.append(
                {
                    "category": "Memory analysis",
                    "severity": "Low",
                    "description": "Memory has reached 70% for 30 minutes",
                    "resolution": f"{RESOLUTION[0]}",
                }
            )
        return addActions
    else:
        return None


# Main
if is_demisto_version_ge("8.0.0"):
    msg = "Not Available for XSOAR v8"
    html = f"<h3 style={XSOARV8_HTML_STYLE}{str(msg)}</h3>"
    demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})
    sys.exit()
incident = demisto.incidents()[0]
accountName = incident.get("account")
accountName = f"acc_{accountName}/" if accountName != "" else ""

args = demisto.args()
isWidget = argToBoolean(args.get("isWidget", True))
stats = demisto.executeCommand(
    "core-api-post",
    {
        "uri": f"{accountName}/statistics/widgets/query",
        "body": {
            "size": 1440,
            "dataType": "system",
            "params": {
                "timeFrame": "minutes",
                "format": "HH:mm",
            },
            "query": "memory.usedPercent",
            "dateRange": {"period": {"byFrom": "hours", "fromValue": 24}},
            "widgetType": "line",
        },
    },
)

res = stats[0]["Contents"]["response"]
output = []
counter = 0
higher = 0

if isWidget is True:
    ctx = demisto.context()
    dataFromCtx = ctx.get("widgets")
    if not dataFromCtx:
        for entry in res:
            higher = max(entry["data"][0], higher)
            if counter % 2 == 0:
                output.append({"name": counter, "data": [higher]})
                higher = 0
            counter += 1

        data = {
            "Type": 17,
            "ContentsFormat": "line",
            "Contents": {"stats": output, "params": {"timeFrame": "minutes", "format": "HH:mm", "layout": "vertical"}},
        }
        demisto.results(data)
    else:
        data = {
            "Type": 17,
            "ContentsFormat": "line",
            "Contents": {
                "stats": dataFromCtx["MemoryUsage"],
                "params": {"timeFrame": "minutes", "format": "HH:mm", "layout": "vertical"},
            },
        }
        demisto.results(data)
else:
    addActions = analyzeData(res)

    results = CommandResults(
        readable_output="analyzeCPUUsage Done", outputs_prefix="HealthCheck.ActionableItems", outputs=addActions
    )

    return_results(results)
