import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


BRAND = "Core REST API"


def get_rest_api_instance_to_use():
    """
        This function checks if there are more than one instance of Core REST API.

        Returns:
            Core REST API instance to use
    """
    all_instances = demisto.getModules()
    number_of_rest_api_instances = 0
    rest_api_instance_to_use = None
    for instance_name in all_instances:
        if all_instances[instance_name]['brand'] == BRAND and all_instances[instance_name]['state'] == 'active':
            rest_api_instance_to_use = instance_name
            number_of_rest_api_instances += 1
        if number_of_rest_api_instances > 1:
            raise DemistoException(
                "This script can only run with a single instance of the Core REST API. "
                "Specify the instance name in the 'rest_api_instance' argument."
            )
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


def get_failed_tasks_output(tasks: list, incident: dict, custom_scripts_map_id_and_name: dict[str, str] = {}):
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
        command = task.get("task", {}).get("scriptId", '')

        command_id = None
        brand_name = None

        if "|||" in command:
            parts = command.split("|||")
            command_id = parts[-1]
            brand_name = parts[0] or None
        else:
            command_id = command

        if task.get("continueOnError", False):
            if task.get("continueOnErrorType", "Continue") == "errorPath":
                error_handling = "Error Path"
                next_task = task.get("nextTasks", {}).get("#error#", [])
            else:
                error_handling = "Continue"
                next_task = task.get("nextTasks", {}).get("#none#", [])

            if not next_task:
                error_handling = error_handling + " (No Next Task)"
        else:
            error_handling = "Stop Playbook"

        entry = {
            "Incident ID": incident.get("id"),
            "Playbook Name": task.get("ancestors", [''])[0],
            "Task Name": task.get("task", {}).get("name"),
            "Error Entry ID": error_entries,
            "Number of Errors": len(error_entries),
            "Task ID": task.get("id"),
            "Incident Created Date": incident.get("created", ''),
            "Command Name": custom_scripts_map_id_and_name.get(command_id, command_id),
            "Brand Name": brand_name,
            "Incident Owner": incident["owner"],
            "Error Handling": error_handling
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
            rest_api_instance (str): A Core REST API instance name to use for fetching task details.

        Returns:
            List of the tasks given from the response.
    """
    uri = f'investigation/{str(incident["id"])}/workplan/tasks'

    response = demisto.executeCommand(
        "core-api-post",
        {
            "uri": uri,
            "body": {
                "states": ["Error"],
                "types": ["regular", "condition", "collection", "playbook"],
            },
            "using": rest_api_instance,
        }
    )

    if is_error(response):
        error = (
            f"Failed retrieving tasks for incident ID {incident['id']}.\n"
            "Make sure that the API key configured in the Core REST API integration "
            f"is one with sufficient permissions to access that incident.\n{get_error(response)}"
        )
        raise DemistoException(error)

    raw_response = response[0]["Contents"]["response"]
    filtered_response = filter_playbooks_failures(raw_response)

    return filtered_response


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
            "types": ["regular", "condition", "collection", "playbook"],
        }
    )

    if response and response.get('statusCode') == 200:
        raw_response = json.loads(response.get('body', '{}'))
        tasks = filter_playbooks_failures(raw_response)

    else:
        demisto.error(f'Failed running POST query to /investigation/{str(incident["id"])}/workplan/tasks.\n{str(response)}')
        tasks = []

    return tasks


def get_custom_scripts_map_id_and_name(rest_api_instance: str | None = None) -> dict[str, str]:
    uri = "automation/search"
    body = {"query": "system:F"}

    scripts = []
    if rest_api_instance:
        demisto.debug(f"Retrieving custom scripts map using REST API instance: {rest_api_instance}")
        response = demisto.executeCommand(
            "core-api-post",
            {
                "uri": uri,
                "body": body,
                "using": rest_api_instance,
            }
        )

        if is_error(response):
            demisto.error(f"Failed retrieving custom scripts map.\n{get_error(response)}")
        else:
            scripts = response[0]["Contents"]["response"].get("scripts", [])

    else:
        demisto.debug("Retrieving custom scripts map using internal HTTP request")
        response = demisto.internalHttpRequest(
            method="POST",
            uri=uri,
            body=body
        )

        if response and response.get('statusCode') == 200:
            scripts = json.loads(response.get('body', '{}')).get("scripts", [])
        else:
            demisto.error(f'Failed running POST query to {uri}.\n{str(response)}')

    custom_scripts_map_id_and_name = {
        script["id"]: script["name"]
        for script in scripts
    }
    demisto.debug(f"Retrieve the following map: {custom_scripts_map_id_and_name}")
    return custom_scripts_map_id_and_name


def get_rest_api_instance(rest_api_instance: str | None) -> str | None:
    # Define with which rest api instance to use or use internal http request
    if rest_api_instance:
        demisto.debug(f"Using REST API instance: {rest_api_instance}, that provided as an argument.")
    else:
        try:
            get_incident_tasks_using_internal_request({"id": 0})
            demisto.debug("Using internal HTTP request to retrieve incident tasks.")
        except ValueError:
            # using rest api call if using_internal_request fails on the following error:
            # ValueError: dial tcp connect: connection refused
            rest_api_instance = get_rest_api_instance_to_use()
            demisto.debug(f"Using REST API instance: {rest_api_instance} to retrieve incident tasks.")
            if not rest_api_instance:
                raise DemistoException('Could not find which Rest API instance to use, '
                                       'Please specify the rest_api_instance argument.')
    return rest_api_instance


def get_incident_data(incident: dict, custom_scripts_map_id_and_name: dict[str, str], rest_api_instance: str | None = None):
    """
        Returns the failing task objects of an incident.
        The request is done using a Core REST API instance if given,
        otherwise it will be done using the demisto.internalHttpRequest method.

        Args:
            incident (dict): An incident object.
            rest_api_instance (str): A Core REST API instance name to use for fetching task details.

        Returns:
            tuple of context outputs and total amount of related error entries
    """
    if rest_api_instance:
        tasks = get_incident_tasks_using_rest_api_instance(incident, rest_api_instance)
    else:
        tasks = get_incident_tasks_using_internal_request(incident)

    task_outputs, tasks_error_entries_number = get_failed_tasks_output(tasks, incident, custom_scripts_map_id_and_name)
    if task_outputs:
        return task_outputs, tasks_error_entries_number
    else:
        return [], 0


def filter_playbooks_failures(response: list | None) -> list | None:
    """
    Filters out tasks of type "playbook" from the response if their name appears
    in the ancestors of any other task in the list. This ensures that only errors
    where the playbook itself failed to start are captured, avoiding duplication
    when errors occur within internal tasks of the playbook.

    Args:
        response (list | None): List of failure tasks.

    Returns:
        The filtered list of tasks. Tasks of type "playbook" whose names appear in the ancestors of other tasks are removed.
    """

    if type(response) is not list:
        return response

    ancestors = set()
    for task in response:
        ancestors.update(task.get("ancestors", []))

    filtered_response = [
        task for task in response
        if not (task.get("type") == "playbook" and task.get("task", {}).get("name") in ancestors)
    ]
    return filtered_response


def main():
    args = demisto.args()
    query = args.get("query")
    max_incidents = arg_to_number(args.get("max_incidents")) or 300
    max_incidents = min(max_incidents, 1000)
    rest_api_instance = args.get("rest_api_instance")
    get_scripts_name = argToBoolean(args.get("get_scripts_name", False))

    number_of_failed_incidents = 0
    number_of_error_entries = 0
    incidents_output = []  # type: Any
    total_failed_incidents = []

    try:
        start_time = time.time()

        get_incidents_result = demisto.executeCommand("getIncidents", {"query": query,
                                                                       "size": max_incidents,
                                                                       })
        incidents_data = get_incidents_result[0]["Contents"]["data"]
        total_incidents = incidents_data if incidents_data else []

        demisto.debug(f'got {len(total_incidents)} incidents using {max_incidents} limit. '
                      f'Elapsed time: {time.time() - start_time}')

        rest_api_instance = get_rest_api_instance(rest_api_instance)

        custom_scripts_map_id_and_name = {}
        if get_scripts_name:
            custom_scripts_map_id_and_name = get_custom_scripts_map_id_and_name(rest_api_instance)

        for incident in total_incidents:
            task_outputs, incident_error_entries_num = get_incident_data(
                incident, custom_scripts_map_id_and_name, rest_api_instance)

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
                                             "Command Name", "Brand Name", "Error Entry ID", "Error Handling"]),
            outputs={
                "GetFailedTasks": incidents_output,
                "NumberofFailedIncidents": total_failed_incidents,
            }
        ))
    except DemistoException as e:
        return_error(f"[GetFailedTasks] Error occurred while running the script, exception info:\n{str(e)}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
