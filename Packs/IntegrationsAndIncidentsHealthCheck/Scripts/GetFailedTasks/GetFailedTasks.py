from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_failed_tasks_output(tasks: list, incident: dict):
    """
        Converts the failing task objects of an incident to context outputs.

        Args:
            tasks (list): List of failing tasks.
            incident (dict): An incident object.

        Returns:
            tuple of context outputs and total amount of related error entries
    """
    if not tasks:
        return [], 0

    task_outputs = []
    number_of_error_entries = 0

    for task in tasks:
        error_entries = task.get("entries", [])
        entry = {
            "Incident ID": incident.get("id"),
            "Playbook Name": task.get("ancestors", [''])[0],
            "Task Name": task.get("task", {}).get("name"),
            "Error Entry ID": error_entries,
            "Number of Errors": len(error_entries),
            "Task ID": task.get("id"),
            "Incident Created Date": incident.get("created", ''),
            "Command Name": task.get("task", {}).get("scriptId", '').replace('|||', ''),
            "Incident Owner": incident["owner"]
        }
        if task.get("task", {}).get("description"):
            entry["Command Description"] = task.get("task", {}).get("description")

        number_of_error_entries += len(error_entries)
        task_outputs.append(entry)

    return task_outputs, number_of_error_entries


def get_incident_data(incident: dict):
    """
        Returns the failing task objects of an incident.

        Args:
            incident (dict): An incident object.

        Returns:
            tuple of context outputs and total amount of related error entries
    """

    response = demisto.internalHttpRequest(
        method='POST',
        uri=f'investigation/{str(incident["id"])}/workplan/tasks',
        body={
            "states": ["Error"],
            "types": ["regular", "condition", "collection"],
        }
    )

    if response and response.get('statusCode') == 200:
        tasks = json.loads(response.get('body', '{}'))
    else:
        demisto.error(f'Failed running POST query to /investigation/{str(incident["id"])}/workplan/tasks.\n{str(response)}')
        return [], 0

    task_outputs, tasks_error_entries_number = get_failed_tasks_output(tasks, incident)
    if task_outputs:
        return task_outputs, tasks_error_entries_number
    else:
        return [], 0


def main():
    args = demisto.args()
    query = args.get("query")
    max_incidents = arg_to_number(args.get("max_incidents")) or 300
    max_incidents = min(max_incidents, 1000)

    number_of_failed_incidents = 0
    number_of_error_entries = 0
    incidents_output = []  # type: Any
    total_failed_incidents = []

    start_time = time.time()

    get_incidents_result = demisto.executeCommand("getIncidents", {"query": query,
                                                                   "size": max_incidents,
                                                                   })
    incidents_data = get_incidents_result[0]["Contents"]["data"]
    total_incidents = incidents_data if incidents_data else []

    demisto.debug(f'got {len(total_incidents)} incidents using {max_incidents} limit. '
                  f'Elapsed time: {time.time() - start_time}')

    for incident in total_incidents:
        task_outputs, incident_error_entries_num = get_incident_data(incident)

        if task_outputs:
            incidents_output.extend(task_outputs)
            number_of_failed_incidents += 1
            number_of_error_entries += incident_error_entries_num

    total_failed_incidents.append({
        'total of failed incidents': number_of_failed_incidents,
        'Number of total errors': number_of_error_entries,
    })
    if not incidents_output:
        incidents_output = {}

    return_results(CommandResults(
        raw_response=incidents_output,
        readable_output=tableToMarkdown("GetFailedTasks:", incidents_output,
                                        ["Incident Created Date", "Incident ID", "Task Name", "Task ID",
                                         "Playbook Name",
                                         "Command Name", "Error Entry ID"]),
        outputs={
            "GetFailedTasks": incidents_output,
            "NumberofFailedIncidents": total_failed_incidents,
        }
    ))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
