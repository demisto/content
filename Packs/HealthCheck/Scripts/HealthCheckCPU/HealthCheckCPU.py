import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


RESOLUTION = (
    "Performance Tuning of Cortex XSOAR Server: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
    "cortex-xsoar-admin/cortex-xsoar-overview/performance-tuning-of-cortex-xsoar-server"
)
XSOARV8_HTML_STYLE = "color:#FFBE98;text-align:center;font-size:150%;>"


def analyze_data(res):
    lowFound = 0
    medFound = 0
    highFound = 0
    lowRes = False
    medRes = False
    highRes = False

    for item in res:
        if not lowRes:
            if item["data"][0] >= 70:
                lowFound += 1
                if lowFound >= 60:
                    lowRes = True
            else:
                lowFound = 0

        if not medRes:
            if item["data"][0] >= 30:
                medFound += 1
                if medFound >= 5:
                    medRes = True
            else:
                medFound = 0

        if not highRes:
            if item["data"][0] >= 90:
                highFound += 1
                if highFound >= 1:
                    highRes = True
            else:
                highFound = 0

    if lowRes or medRes or highRes:
        addActions = []

        if highRes:
            addActions.append(
                {"category": "CPU analysis", "severity": "High", "description": "CPU has reached 90%", "resolution": RESOLUTION}
            )

        if medRes:
            addActions.append(
                {
                    "category": "CPU analysis",
                    "severity": "Medium",
                    "description": "CPU has reached 80% for 10 minutes",
                    "resolution": RESOLUTION,
                }
            )

        if lowRes:
            addActions.append(
                {
                    "category": "CPU analysis",
                    "severity": "Low",
                    "description": "CPU has reached 70% for 30 minutes",
                    "resolution": RESOLUTION,
                }
            )
        return addActions
    else:
        return None


def main(args):
    if is_demisto_version_ge("8.0.0"):
        msg = "Not Available for XSOAR v8"
        html = f"<h3 style={XSOARV8_HTML_STYLE}{str(msg)}</h3>"
        demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})
        sys.exit()
    incident = demisto.incidents()[0]
    account_name = incident.get("account")
    account_name = f"acc_{account_name}/" if account_name != "" else ""

    is_widget = argToBoolean(args.get("isWidget", True))
    res = execute_command(
        "core-api-post",
        {
            "uri": f"{account_name}statistics/widgets/query",
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
                        "fromValue": 24,
                    }
                },
                "widgetType": "line",
            },
        },
    )

    stats = res["response"]
    output = []
    counter = 0
    higher = 0
    if is_widget is True:
        ctx = demisto.context()
        dataFromCtx = ctx.get("widgets")
        if not dataFromCtx:
            for entry in stats:
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

            return data
        else:
            # Fetching data from context to widget
            data = {
                "Type": 17,
                "ContentsFormat": "line",
                "Contents": {
                    "stats": dataFromCtx["CPUUsage"],
                    "params": {"timeFrame": "minutes", "format": "HH:mm", "layout": "vertical"},
                },
            }
            return data
    else:
        add_actions = analyze_data(stats)
        results = CommandResults(
            readable_output="analyzeCPUUsage Done", outputs_prefix="HealthCheck.ActionableItems", outputs=add_actions
        )

        return results


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    return_results(main(demisto.args()))
