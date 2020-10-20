import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    query = args.get("query")

    page_number = 0
    number_of_failed = 0
    number_of_errors = 0
    total_incidents = []
    incidents_output = []
    total_failed_incidents = []

    while True:
        get_incidents_result = demisto.executeCommand("getIncidents", {"query": query, "page": page_number})

        incidents_data = get_incidents_result[0]["Contents"]["data"]
        if incidents_data:
            total_incidents.extend(incidents_data)
        else:
            incidents_data = []

        page_number += 1

        if len(incidents_data) < 100:
            break

    for incident in total_incidents:
        tasks = demisto.executeCommand(
            "demisto-api-post",
            {
                "uri": f'investigation/{str(incident["id"])}/workplan/tasks',
                "body": {
                    "states": ["Error"],
                    "types": ["regular", "condition", "collection"]
                }
            }
        )[0]["Contents"]["response"]

        if tasks:
            for task in tasks:
                entry = {
                    "Incident ID": incident.get("id"),
                    "Playbook Name": task.get("ancestors", [''])[0],
                    "Task Name": task.get("task", {}).get("name"),
                    "Error Entry ID": task.get("entries"),
                    "Number of Errors": len(task.get("entries", [])),
                    "Task ID": task.get("id"),
                    "Incident Created Date": incident.get("created", '').replace("T", " "),
                    "Command Name": task.get("task", {}).get("scriptId", '').replace('|||', ''),
                    "Incident Owner": incident["owner"]
                }
                if task.get("task", {}).get("description"):
                    entry["Command Description"] = task.get("task", {}).get("description")

                incidents_output.append(entry)

                number_of_failed = number_of_failed + 1
                number_of_errors = number_of_errors + entry["Number of Errors"]

    total_failed_incidents.append({
        'total of failed incidents': number_of_failed,
        'Number of total errors': number_of_errors
    })

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': incidents_output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("GetFailedTasks:", incidents_output,
                                         ["Incident Created Date", "Incident ID", "Task Name", "Task ID", "Playbook Name",
                                          "Command Name", "Error Entry ID"]),
        'EntryContext': {
            "GetFailedTasks": incidents_output,
            "NumberofFailedIncidents": total_failed_incidents
        }
    })


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
