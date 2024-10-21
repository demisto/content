import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime

DESCRIPTION = "{} busy workers has reached {} of total workers"

RESOLUTION = (
    "Performance Tuning of Cortex XSOAR Server: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
    "cortex-xsoar-admin/cortex-xsoar-overview/performance-tuning-of-cortex-xsoar-server"
)
XSOARV8_HTML_STYLE = "color:#FFBE98;text-align:center;font-size:150%;>"


def analyze_data(res):
    workers_thresholds = {
        0.9: "High",
        0.8: "Medium",
        0.5: "Low",
    }
    for threshold, severity in workers_thresholds.items():
        if res["Busy"] > res["Total"] * threshold:
            return [
                {
                    "category": "Workers analysis",
                    "severity": severity,
                    "description": DESCRIPTION.format(res["Busy"], threshold),
                    "resolution": RESOLUTION[0],
                }
            ]

    return []


def nano_to_secs(table):
    for entry in table:
        secs = int(entry["Duration"] / 1000000000)
        if secs < 60:
            entry["Duration"] = str(secs) + " Seconds"
        else:
            minutes = int(secs / 60)
            mod_sec = secs % 60
            entry["Duration"] = f"{str(minutes)} Minutes and {mod_sec} seconds"


def format_time(table):
    for entry in table:
        startedAt = datetime.strptime(entry["StartedAt"][:-4], "%Y-%m-%dT%H:%M:%S.%f")
        entry["StartTime"] = startedAt.strftime("%Y-%m-%d %H:%M:%S")


def format_details(table):
    for entry in table:
        details = entry["Details"]
        getdetails = re.compile(
            r'task \[(?P<taskid>[\d]+)\]\s\[(?P<taskname>[\w\d\s!@#$%^&*()_+-={}]+)], playbook\s \
            \[(?P<pbname>[\w\d\s!@#$%^&*()_+-={}]+)],\sinvestigation\s\[(?P<investigationid>[\d]+)\]')
        all_images = [m.groups() for m in getdetails.finditer(details)]
        for item in all_images:
            newdetails = {"TaskID": item[0], "TaskName": item[1], "PlaybookName": item[2], "InvestigationID": item[3]}
        entry["TaskID"] = newdetails["TaskID"]
        entry["TaskName"] = newdetails["TaskName"]
        entry["PlaybookName"] = newdetails["PlaybookName"]
        entry["InvestigationID"] = newdetails["InvestigationID"]


def main(args):
    if is_demisto_version_ge("8.0.0"):
        msg = "Not Available for XSOAR v8"
        html = f"<h3 style={XSOARV8_HTML_STYLE}{str(msg)}</h3>"
        demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})
        sys.exit()
    incident = demisto.incident()
    account_name = incident.get("account")
    account_name = f"acc_{account_name}/" if account_name != "" else ""

    is_widget = argToBoolean(args.get("isWidget", True))
    if is_widget is True:
        workers = demisto.executeCommand("core-api-get", {"uri": f"{account_name}workers/status"})[0]["Contents"]

        if not workers["response"]["ProcessInfo"]:
            table = [{"Details": "-", "Duration": "-", "StartedAt": "-"}]
        else:
            table = workers["response"]["ProcessInfo"]
            nano_to_secs(table)
            format_time(table)
            format_details(table)
        md = tableToMarkdown(
            "Workers Status", table, headers=["InvestigationID", "PlaybookName", "TaskID", "TaskName", "StartTime", "Duration"]
        )

        dmst_entry = {
            "Type": entryTypes["note"],
            "Contents": md,
            "ContentsFormat": formats["markdown"],
            "HumanReadable": md,
            "ReadableContentsFormat": formats["markdown"],
            "EntryContext": {"workers": table},
        }

        return dmst_entry
    else:
        workers = demisto.executeCommand("core-api-get", {"uri": f"{account_name}workers/status"})[0]["Contents"]
        demisto.executeCommand(
            "setIncident",
            {"healthcheckworkerstotal": workers["response"]["Total"], "healthcheckworkersbusy": workers["response"]["Busy"]},
        )
        add_actions = analyze_data(workers["response"])

        results = CommandResults(
            readable_output="HealthCheckWorkers Done", outputs_prefix="HealthCheck.ActionableItems", outputs=add_actions
        )

    return results


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    return_results(main(demisto.args()))
