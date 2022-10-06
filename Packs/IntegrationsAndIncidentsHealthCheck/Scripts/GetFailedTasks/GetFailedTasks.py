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


def get_incident_tasks_using_rest_api_instance(incident: dict, rest_api_instance: str):
    """
        Returns the failing task objects of an incident using the given rest API instance.

        Args:
            incident (dict): An incident object.
            rest_api_instance (str): A Demisto REST API instance name to use for fetching task details.

        Returns:
            List of the tasks given from the response.
    """
    response = demisto.executeCommand(
        "demisto-api-post",
        {
            "uri": f'investigation/{str(incident["id"])}/workplan/tasks',
            "body": {
                "states": ["Error"],
                "types": ["regular", "condition", "collection"],
            },
            "using": rest_api_instance,
        }
    )

    if is_error(response):
        error = f'Failed retrieving tasks for incident ID {incident["id"]}.\n \
           Make sure that the API key configured in the Demisto REST API integration \
is one with sufficient permissions to access that incident.\n' + get_error(response)
        raise Exception(error)

    return response[0]["Contents"]["response"]


def get_incident_tasks_using_internal_request(incident: dict):
    """
        Returns the failing task objects of an incident using an internal HTTP request.

        Args:
            incident (dict): An incident object.

        Returns:
            List of the tasks given from the response.
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
        tasks = []

    return tasks


def get_incident_data(incident: dict, rest_api_instance: str = None):
    """
        Returns the failing task objects of an incident.
        The request is done using a Demisto Rest API instance if given,
        otherwise it will be done using the demisto.internalHttpRequest method.

        Args:
            incident (dict): An incident object.
            rest_api_instance (str): A Demisto REST API instance name to use for fetching task details.

        Returns:
            tuple of context outputs and total amount of related error entries
    """

    tasks = get_incident_tasks_using_rest_api_instance(incident, rest_api_instance) if rest_api_instance \
        else get_incident_tasks_using_internal_request(incident)

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
    rest_api_instance = args.get("rest_api_instance")

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
        task_outputs, incident_error_entries_num = get_incident_data(incident, rest_api_instance)

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
