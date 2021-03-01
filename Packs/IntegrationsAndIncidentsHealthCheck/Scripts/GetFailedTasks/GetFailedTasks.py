from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BRAND = "Demisto REST API"
PAGE_SIZE = 1000


def get_rest_api_instance_to_use():
    """
        This function checks if there are more than one instance of demisto rest api.

        Returns:
            Demisto Rest Api instance to use
    """
    all_instances = demisto.getModules()
    number_of_rest_api_instances = 0
    rest_api_instance_to_use = None
    for instance_name in all_instances:
        if all_instances[instance_name]['brand'] == BRAND and all_instances[instance_name]['state'] == 'active':
            rest_api_instance_to_use = instance_name
            number_of_rest_api_instances += 1
        if number_of_rest_api_instances > 1:
            return_error("GetFailedTasks: This script can only run with a single instance of the Demisto REST API. "
                         "Specify the instance name in the 'rest_api_instance' argument.")
    return rest_api_instance_to_use


def get_tenant_name():
    """
        Gets the tenant name from the server url.

        Returns:
         tenant name.
    """
    server_url = demisto.executeCommand("GetServerURL", {})[0].get('Contents')
    tenant_name = ''
    if '/acc_' in server_url:
        tenant_name = server_url.split('acc_')[-1]

    return tenant_name


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


def get_incident_data(incident: dict, tenant_name: str, rest_api_instance_to_use: str):
    """
        Returns the failing task objects of an incident.

        Args:
            incident (dict): An incident object.
            tenant_name (str): The tenant of the incident.
            rest_api_instance_to_use (str): A Demisto REST API instance name to use for fetching task details.

        Returns:
            tuple of context outputs and total amount of related error entries
    """
    if tenant_name:
        uri = f'acc_{tenant_name}/investigation/{str(incident["id"])}/workplan/tasks'
    else:
        uri = f'investigation/{str(incident["id"])}/workplan/tasks'

    response = demisto.executeCommand(
        "demisto-api-post",
        {
            "uri": uri,
            "body": {
                "states": ["Error"],
                "types": ["regular", "condition", "collection"],
            },
            "using": rest_api_instance_to_use,
        }
    )

    if is_error(response):
        raise Exception(get_error(response))

    tasks = response[0]["Contents"]["response"]

    task_outputs, tasks_error_entries_number = get_failed_tasks_output(tasks, incident)
    if task_outputs:
        return task_outputs, tasks_error_entries_number
    else:
        return [], 0


def main():
    args = demisto.args()
    query = args.get("query")
    limit = arg_to_number(args.get("max_incidents"))
    rest_api_instance = args.get("rest_api_instance")
    rest_api_instance_to_use = get_rest_api_instance_to_use() if not rest_api_instance else rest_api_instance

    tenant_name = get_tenant_name()

    page_number = 0
    number_of_failed_incidents = 0
    number_of_error_entries = 0
    total_incidents: list = []
    incidents_output = []  # type: Any
    total_failed_incidents = []

    start_time = time.time()
    while True:
        get_incidents_result = demisto.executeCommand("getIncidents", {"query": query,
                                                                       "page": page_number,
                                                                       "size": PAGE_SIZE,
                                                                       })

        incidents_data = get_incidents_result[0]["Contents"]["data"]
        if incidents_data:
            total_incidents.extend(incidents_data)
        else:
            incidents_data = []

        page_number += 1

        if len(incidents_data) < PAGE_SIZE:
            # no more results
            break

        if limit and len(total_incidents) > limit:
            # over the limit
            total_incidents = total_incidents[:limit]
            break

    demisto.debug(f'got {len(total_incidents)} incidents using {page_number} pages. '
                  f'Elapsed time: {time.time() - start_time}')

    for incident in total_incidents:
        task_outputs, incident_error_entries_num = get_incident_data(
            incident,
            tenant_name,
            rest_api_instance_to_use,
        )
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
