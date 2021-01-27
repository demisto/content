import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BRAND = "Demisto REST API"


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
        :return: tenant name.
        :rtype: ``str``
    """
    server_url = demisto.executeCommand("GetServerURL", {})[0].get('Contents')
    tenant_name = ''
    if '/acc_' in server_url:
        tenant_name = server_url.split('acc_')[-1]

    return tenant_name


def main():
    args = demisto.args()
    query = args.get("query")
    rest_api_instance = args.get("rest_api_instance")
    rest_api_instance_to_use = get_rest_api_instance_to_use() if not rest_api_instance else rest_api_instance

    tenant_name = get_tenant_name()

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
                    "types": ["regular", "condition", "collection"]
                },
                "using": rest_api_instance_to_use
            }
        )
        if is_error(response):
            raise Exception(get_error(response))

        tasks = response[0]["Contents"]["response"]

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
