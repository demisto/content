import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


RESOLUTION = (
    "Free up Disk Space with Data Archiving: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
    "cortex-xsoar-admin/manage-data/free-up-disc-space-with-data-archiving"
)
XSOARV8_HTML_STYLE = "color:#FFBE98;text-align:center;font-size:150%;>"


def analyze_data(res):
    add_actions = []
    disk_usage = res[-1]["data"][0]
    disk_usage_thresholds = {
        90: "High",
        80: "Medium",
        70: "Low",
    }

    for threshold, severity in disk_usage_thresholds.items():
        if disk_usage > threshold:
            add_actions.append(
                {
                    "category": "Disk usage analysis",
                    "severity": severity,
                    "description": f"Disk usage has reached {threshold}%",
                    "resolution": RESOLUTION,
                }
            )
            break

    if (disk_usage - res[0]["data"][0]) > 1:
        add_actions.append(
            {
                "category": "Disk usage analysis",
                "severity": "High",
                "description": "Disk usage was increased significantly in the last 24 hours",
                "resolution": RESOLUTION,
            }
        )

    return add_actions


def main(args):
    if is_demisto_version_ge("8.0.0"):
        msg = "Not Available for XSOAR v8"
        html = f"<h3 style={XSOARV8_HTML_STYLE}{str(msg)}</h3>"
        demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})
        sys.exit()
    incident = demisto.incident()
    account_name = incident.get("account")
    account_name = f"acc_{account_name}" if account_name != "" else ""

    is_widget = argToBoolean(args.get("isWidget", True))
    widget_type = "number" if is_widget else "line"

    partition = "/"
    for entry in dict_safe_get(incident, ["CustomFields", "xsoarserverconfiguration"], []):  # type: ignore
        if entry.get("key", "") == "disk.partitions.to.monitor":
            partition = entry["value"]

    res = execute_command(
        "core-api-post",
        {
            "uri": f"{account_name}/statistics/widgets/query",
            "body": {
                "size": 1440,
                "dataType": "system",
                "params": {"timeFrame": "minutes"},
                "query": f"disk.usedPercent.{partition}",
                "dateRange": {
                    "period": {
                        "byFrom": "hours",
                        "fromValue": 24,
                    }
                },
                "widgetType": widget_type,
            },
        },
    )

    stats = res["response"]
    data = {
        "Type": 17,
        "ContentsFormat": widget_type,
        "Contents": {
            "stats": stats,
            "params": {
                "currencySign": "%",
                "signAlignment": "right",
                "colors": {
                    "isEnabled": True,
                    "items": {
                        "#00CD33": {"value": -1},
                        "#FAC100": {"value": 60},
                        "#FF1B15": {"value": 80},
                    },
                    "type": "above",
                },
            },
        },
    }

    if is_widget:
        ctx = demisto.context()
        dataFromCtx = ctx.get("widgets")
        if not dataFromCtx:
            return data
        else:
            data = {
                "Type": 17,
                "ContentsFormat": widget_type,
                "Contents": {
                    "stats": dataFromCtx["DiskUsagePerCentage"],
                    "params": {
                        "currencySign": "%",
                        "signAlignment": "right",
                        "colors": {
                            "isEnabled": True,
                            "items": {
                                "#00CD33": {"value": -1},
                                "#FAC100": {"value": 60},
                                "#FF1B15": {"value": 80},
                            },
                            "type": "above",
                        },
                    },
                },
            }
            return None
    else:
        add_actions = analyze_data(stats)
        return CommandResults(
            readable_output="analyzeCPUUsage Done", outputs_prefix="HealthCheck.ActionableItems", outputs=add_actions
        )


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    return_results(main(demisto.args()))
