import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
query = args["query"]

totalIncidents = []
incidentsOutput = []
totalFailedIncidents = []
pager = 0
getIncidents = True
numberofFailed = 0
numberofErrors = 0
totalNumbers = []
while getIncidents:
    getIncidents = demisto.executeCommand("getIncidents", {"query": query, "page": pager})
    incidents = getIncidents[0]["Contents"]["data"]
    totalIncidents.extend(incidents)
    pager += 1
    if len(incidents) < 100:
        getIncidents = False

for incident in totalIncidents:
    tasks = demisto.executeCommand("demisto-api-post", {"uri": "investigation/" + str(incident["id"]) + "/workplan/tasks", "body": {
                                   "states": ["Error"], "types": ["regular", "condition", "collection"]}})[0]["Contents"]["response"]
    if tasks:
        for task in tasks:
            entries = {}
            entries["Incident ID"] = incident["id"]
            entries["Playbook Name"] = task["ancestors"][0]
            entries["Task Name"] = task["task"]["name"]
            entries["Error Entry ID"] = task["entries"]
            entries["Number of Errors"] = len(task["entries"])
            entries["Task ID"] = task["id"]
            entries["Incident Created Date"] = incident["created"].replace("T", " ")
            #entries["Incident Created Date"] = incident["created"].split("T")[0]
            entries["Command Name"] = task["task"]["scriptId"].replace('|||', '')
            entries["Incident Owner"] = incident["owner"]
            if task["task"]["description"]:
                entries["Command Description"] = task["task"]["description"]
            incidentsOutput.append(entries)
            numberofFailed = numberofFailed + 1
            numberofErrors = numberofErrors + entries["Number of Errors"]
numbers = {}
numbers["total of failed incidents"] = numberofFailed
numbers["Number of total errors"] = numberofErrors
totalFailedIncidents.append(numbers)

demisto.results({
    'Type': entryTypes['note'],
    'Contents': incidentsOutput,
    'ContentsFormat': formats['json'],
    'ReadableContentsFormat': formats['markdown'],
    'HumanReadable': tableToMarkdown("GetFailedTasks:", incidentsOutput, ["Incident Created Date", "Incident ID", "Task Name", "Task ID", "Playbook Name", "Command Name", "Error Entry ID"]),
    'EntryContext': {
        "GetFailedTasks": incidentsOutput,
        "NumberofFailedIncidents": totalFailedIncidents
    }
})
