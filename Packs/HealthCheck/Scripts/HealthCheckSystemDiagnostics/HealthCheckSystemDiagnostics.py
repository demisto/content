import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from operator import itemgetter
import re


def LargeIncidents(account_name):
    largeIncidents = demisto.executeCommand("demisto-api-get", {"uri": f"{account_name}diagnostics/incidentsSize"})[0]['Contents']
    return largeIncidents['response']


def BigWorkplans(account_name):
    bigWorkplans = demisto.executeCommand("demisto-api-get", {"uri": f"{account_name}diagnostics/bigworkplans"})[0]['Contents']
    # print(bigWorkplans['response'])
    return bigWorkplans['response']


def BigContext(account_name):
    bigContext = demisto.executeCommand("demisto-api-get", {"uri": f"{account_name}diagnostics/invContextSize"})[0]['Contents']
    return bigContext['response']


def BigTasks(account_name):
    bigTasks = demisto.executeCommand("demisto-api-get", {"uri": f"{account_name}diagnostics/bigtasks"})[0]['Contents']
    return bigTasks['response'][0]['tasksList']


def FormatSize(size):
    # 2**10 = 1024
    #power = 2**10
    power = 1000
    n = 0
    power_labels = {0: '', 1: 'KB', 2: 'MB', 3: 'GB'}
    while size > power:
        size /= power
        n += 1
    return "{:.2f} {}".format(size, power_labels[n])


def format_time(time):
    time = datetime.strptime(time[:-4], '%Y-%m-%dT%H:%M:%S.%f')
    newTimeFormat = time.strftime("%Y-%m-%d")
    return newTimeFormat


def FormatTableAndSet(data, dataSource, incident):
    # print(dataSource)
    # print(data)

    newFormat = []
    for entry in data:
        newEntry = {}
        newEntry['incidentid'] = entry['id']
        if dataSource == "largeIncidents":
            newEntry['size'] = FormatSize(entry['size'])
            newEntry['info'] = "Large Incident"
            newEntry['date'] = format_time(entry['modified'])
            newFormat.append(newEntry)
        elif dataSource == "bigWorkplans":
            newEntry['size'] = FormatSize(entry['workplanSizeBytes'])
            newEntry['info'] = "Big Workplan"
            newEntry['date'] = format_time(entry['created'])
            newFormat.append(newEntry)
        elif dataSource == "bigContext":
            newEntry['size'] = FormatSize(entry['size'])
            newEntry['info'] = "Big Context"
            newEntry['date'] = format_time(entry['modified'])
            newFormat.append(newEntry)
        elif dataSource == "bigTasks":
            taskId = re.match(r"(?P<incidentid>\d+)##(?P<taskid>[\d+])##(?P<pbiteration>-\d+|\d+)", entry['taskId'])
            # print(taskId)
            newEntry['details'] = f"Playbook:{entry['playbookName']},\nTaskName:{entry['taskName']},\n TaskID:{taskId['taskid']}"
            newEntry['size'] = FormatSize(entry['taskSize'])
            newEntry['incidentid'] = entry['investigationId']
            newFormat.append(newEntry)
        else:
            continue
    return newFormat


incident = demisto.incident()
account_name = incident.get('account')
account_name = f"acc_{account_name}/" if account_name != "" else ""


SystemDiagnosticsResults = []


SystemDiagnosticsResults = {
    "largeIncidents": LargeIncidents(account_name),
    "bigWorkplans": BigWorkplans(account_name),
    "bigContext": BigContext(account_name),
    "bigTasks": BigTasks(account_name)
}
#print(json.dumps(SystemDiagnosticsResults, indent = 4))
out = []
for key in SystemDiagnosticsResults.keys():
    if key != "bigTasks":
        res = FormatTableAndSet(SystemDiagnosticsResults[key], key, incident)
        SystemDiagnosticsResults[key] = res
        out.extend(res)
    else:
        bigTasksNewFormat = FormatTableAndSet(SystemDiagnosticsResults[key], key, incident)
print(out)
sorted_out = sorted(out, key=itemgetter('incidentid'))
demisto.executeCommand("setIncident", {"healthchecklargeinvestigations": sorted_out})
demisto.executeCommand("setIncident", {"healthcheckinvestigationswithlargeinputoutput": bigTasksNewFormat})
