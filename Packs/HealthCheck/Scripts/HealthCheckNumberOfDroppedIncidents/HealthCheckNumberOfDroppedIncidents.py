import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from datetime import datetime, timedelta


def buildWidget(totalDropped):
    data = {
        "Type": 17,
        "ContentsFormat": "number",
        "Contents": {
            "stats": totalDropped,
            "params": {
                "timeFrame": "minutes",
                "colors": {
                    "isEnabled": True,
                    "items": {"#D13C3C": {"value": 15}},
                },
            },
        },
    }

    return data


def createActionItem(totalDropped):
    actionItems = []

    if totalDropped > thresholds["NumberOfDroppedIncidents"]:
        actionItems.append(
            {
                "category": "Incidents Analysis",
                "severity": "Low",
                "description": "Too many dropped incidents",
                "resolution": "Consider tuning the defined query to avoid fetching unneeded incidents",
            }
        )
    return CommandResults(
        readable_output="HealthCheckFileSysLog Done", outputs_prefix="HealthCheck.ActionableItems", outputs=actionItems
    )


incident = demisto.incidents()[0]
accountName = incident.get("account")
accountName = f"acc_{accountName}/" if accountName != "" else ""

args = demisto.args()
Thresholds = {"NumberOfDroppedIncidents": 2000}
thresholds = args.get("Thresholds", Thresholds)
isWidget = argToBoolean(args.get("isWidget", True))
daysAgo = datetime.today() - timedelta(days=30)

demisto_version: str = get_demisto_version().get("version")
if not demisto_version:
    return_error("Could not get the version of XSOAR")

if demisto_version.startswith("6"):  # xsoar 6
    stats = demisto.executeCommand(
        "core-api-post",
        {
            "uri": f"{accountName}settings/audits",
            "body": {"size": 10000, "query": "type:notcreated and modified:>%s" % str(daysAgo.strftime("%Y-%m-%d"))},
        },
    )

    if is_error(stats):
        return_error(f"error occurred when trying to retrieve the audit logs using {args=}, error: {stats}")

    totalDropped = stats[0]["Contents"]["response"]["total"]
    if isWidget is True:
        data = buildWidget(totalDropped)
        return_results(data)
    else:
        results = createActionItem(totalDropped)
        return_results(results)

else:  # XSOAR V8
    uri = "/public_api/v1/audits/management_logs"
    page_num = 1
    size = 100
    body = {
        "request_data": {
            "search_from": page_num,
            "search_to": size,
            "filters": [
                {"field": "sub_type", "operator": "in", "value": ["NotCreated - Incident"]},
            ],
        }
    }

    args = {"uri": uri, "body": body}
    stats = demisto.executeCommand("core-api-post", args)
    totalDropped = stats[0]["Contents"]["response"]["reply"]["total_count"]
    if is_error(stats):
        return_error(f"error occurred when trying to retrieve the audit logs using {args=}, error: {stats}")

    if isWidget is True:
        data = buildWidget(totalDropped)
        return_results(data)
    else:
        results = createActionItem(totalDropped)
        return_results(results)
