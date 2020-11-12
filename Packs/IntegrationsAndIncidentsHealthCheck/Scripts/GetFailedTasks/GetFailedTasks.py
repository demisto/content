import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BRAND = "Demisto REST API"


def get_rest_api_instance_to_use(rest_api_instance_from_arg):
    """
        This function checks if there are more than one instance of demisto rest api.
        Args:
            rest_api_instance_from_arg (str) : rest api instance name

        Returns:
            Demisto Rest Api instance to use
    """
    allInstances = demisto.getModules()
    number_of_rest_api_instances = 0
    rest_api_instance_to_use = None
    for instance_name in allInstances:
        if allInstances[instance_name]['brand'] == BRAND:
            rest_api_instance_to_use = instance_name
            number_of_rest_api_instances += 1
    if number_of_rest_api_instances > 1:
        return_error("GetFailedTasks: This script can only run with a single instance of the Demisto REST API. "
                     "Specify the instance name in the 'rest_api_instance' argument.")
    elif number_of_rest_api_instances == 1:
        return rest_api_instance_to_use
    else:
        # in there are no rest api instances
        return rest_api_instance_from_arg


def main():
    args = demisto.args()
    query = args.get("query")
    account = args.get("account_name", '')
    rest_api_instance = args.get("rest_api_instance")
    rest_api_instance_to_use = get_rest_api_instance_to_use(rest_api_instance)

    page_number = 0
    number_of_failed = 0
    number_of_errors = 0
    total_incidents = []
    incidents_output: list = [{}]
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
        if account:
            uri = f'acc_{account}/investigation/{str(incident["id"])}/workplan/tasks'
        else:
            uri = f'investigation/{str(incident["id"])}/workplan/tasks'

        tasks = demisto.executeCommand(
            "demisto-api-post",
            {
                "uri": uri,
                "body": {
                    "states": ["Error"],
                    "types": ["regular", "condition", "collection"]
                },
                "using": rest_api_instance_to_use
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
                                         ["Incident Created Date", "Incident ID", "Task Name", "Task ID",
                                          "Playbook Name",
                                          "Command Name", "Error Entry ID"]),
        'EntryContext': {
            "GetFailedTasks": incidents_output,
            "NumberofFailedIncidents": total_failed_incidents
        }
    })


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
