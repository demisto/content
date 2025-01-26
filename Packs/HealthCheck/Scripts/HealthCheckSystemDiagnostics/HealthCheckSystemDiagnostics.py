import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from operator import itemgetter
import re

DESCRIPTION = [
    "Large incidents were found",
    "Large Workplans were found",
    "Large investigation context data larger than 1 MB was found, that ,ay slow down playbook execution",
    "Large playbook tasks are used, storing a large amount of data to task inputs and outputs",
]

RESOLUTION = [
    "consider to use quiet mode in task settings and Playbook Settings: https://xsoar.pan.dev/docs/playbooks/playbook-settings",
    "Avoid storing unnecessary data to context",
]


def LargeIncidents(account_name):
    largeIncidents = demisto.executeCommand("core-api-get", {"uri": f"{account_name}diagnostics/incidentsSize"})[0]["Contents"]
    return largeIncidents["response"]


def BigWorkplans(account_name):
    bigWorkplans = demisto.executeCommand("core-api-get", {"uri": f"{account_name}diagnostics/bigworkplans"})[0]["Contents"]
    return bigWorkplans["response"]


def BigContext(account_name):
    bigContext = demisto.executeCommand("core-api-get", {"uri": f"{account_name}diagnostics/invContextSize"})[0]["Contents"]
    return bigContext["response"]


def BigTasks(account_name):
    bigTasks = demisto.executeCommand("core-api-get", {"uri": f"{account_name}diagnostics/bigtasks"})[0]["Contents"]
    return bigTasks["response"][0]["tasksList"]


def FormatSize(size):
    power = 1000
    n = 0
    power_labels = {0: "", 1: "KB", 2: "MB", 3: "GB"}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"


def format_time(time):
    dateOnly = time.split("T")[0]
    return dateOnly


def FormatTableAndSet(data, dataSource):
    newFormat = []
    for entry in data:
        newEntry = {}
        newEntry["incidentid"] = entry["id"]
        if dataSource == "largeIncidents":
            newEntry["size"] = FormatSize(entry["size"])
            newEntry["info"] = "Large Incident"
            newEntry["date"] = format_time(entry["modified"])
            newFormat.append(newEntry)
        elif dataSource == "bigWorkplans":
            newEntry["size"] = FormatSize(entry["workplanSizeBytes"])
            newEntry["info"] = "Big Workplan"
            newEntry["date"] = format_time(entry["created"])
            newFormat.append(newEntry)
        elif dataSource == "bigContext":
            newEntry["size"] = FormatSize(entry["size"])
            newEntry["info"] = "Big Context"
            newEntry["date"] = format_time(entry["modified"])
            newFormat.append(newEntry)
        elif dataSource == "bigTasks":
            taskId = re.match(r"(?P<incidentid>\d+)##(?P<taskid>[\d+])##(?P<pbiteration>-\d+|\d+)", entry["taskId"])
            if taskId is not None:
                newEntry["details"] = (
                    f"Playbook:{entry['playbookName']},\n TaskName:{entry['taskName']},\n TaskID:{taskId['taskid']}"
                )
                newEntry["size"] = FormatSize(entry["taskSize"])
                newEntry["incidentid"] = entry["investigationId"]
                newFormat.append(newEntry)
        else:
            continue
    return newFormat


incident = demisto.incident()
account_name = incident.get("account")
account_name = f"acc_{account_name}/" if account_name != "" else ""


SystemDiagnosticsResults = {
    "largeIncidents": LargeIncidents(account_name),
    "bigWorkplans": BigWorkplans(account_name),
    "bigContext": BigContext(account_name),
    "bigTasks": BigTasks(account_name),
}

out = []
bigTasksNewFormat = []
for key, value in SystemDiagnosticsResults.copy().items():
    if key != "bigTasks":
        res = FormatTableAndSet(value, key)
        SystemDiagnosticsResults[key] = res
        out.extend(res)
    else:
        bigTasksNewFormat = FormatTableAndSet(value, key)

actionableItems = []
if SystemDiagnosticsResults["largeIncidents"]:
    actionableItems.append(
        {"category": "DB Analysis", "severity": "High", "description": DESCRIPTION[0], "resolution": RESOLUTION[0]}
    )

if SystemDiagnosticsResults["bigWorkplans"]:
    actionableItems.append(
        {"category": "DB Analysis", "severity": "High", "description": DESCRIPTION[1], "resolution": RESOLUTION[0]}
    )

if SystemDiagnosticsResults["bigContext"]:
    actionableItems.append(
        {"category": "DB Analysis", "severity": "High", "description": DESCRIPTION[2], "resolution": RESOLUTION[1]}
    )

if SystemDiagnosticsResults["bigTasks"]:
    actionableItems.append(
        {"category": "DB Analysis", "severity": "High", "description": DESCRIPTION[3], "resolution": RESOLUTION[0]}
    )

sorted_out = sorted(out, key=itemgetter("incidentid"))
demisto.executeCommand("setIncident", {"healthchecklargeinvestigations": sorted_out})
demisto.executeCommand("setIncident", {"healthcheckinvestigationswithlargeinputoutput": bigTasksNewFormat})


results = CommandResults(
    readable_output="HealthCheck System Diagnostics Done", outputs_prefix="dbstatactionableitems", outputs=actionableItems
)

return_results(results)
