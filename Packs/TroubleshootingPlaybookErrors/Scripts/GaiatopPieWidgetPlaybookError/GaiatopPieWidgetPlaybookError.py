import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import random


def generate_random_hex_color():
    """Generates a random 6-digit hex color code, e.g., '#A3F2B6'."""
    # Generate a random integer between 0 and 0xFFFFFF (16777215)
    random_int = random.randint(0, 0xFFFFFF)
    # Format the integer as a 6-digit hex string with leading zeros
    return f"#{random_int:06X}"


def get_error_data(incidents, rest_api_instance):
    error_data = []
    final_results = []
    for i, incident in enumerate(incidents):
        uri = f'investigation/{str(incident)}/workplan/tasks'
        response = demisto.executeCommand("core-api-post", {
            "uri": uri,
            "body": {
                "states": ["Error"],
                "types": ["regular", "condition", "collection", "playbook"],
            },
            "using": rest_api_instance,
        },
        )[0]['Contents']['response']
        if response:
            error_data.append({
                "IncidentID": incident,
                "TaskID": response[0].get('task', {}).get('id'),
                "TaskName": response[0].get('task', {}).get('name')
            })
    error_data = {"Data": error_data}

    failed_task_list = set(demisto.dt(error_data, "Data.TaskName"))

    for task_name in failed_task_list:
        count = len(demisto.dt(error_data, f"Data(val.TaskName == '{task_name}')"))
        incident_ids = " or ".join(demisto.dt(error_data, f"Data(val.TaskName == '{task_name}').IncidentID"))
        final_results.append({
            "Name": task_name,
            "Data": [count],
            "Color": generate_random_hex_color(),
            "query": f"id:({incident_ids})",
            "dataType": "incidents"
        })
    return final_results


def main():

    from_date = demisto.args().get('from')
    query = f' -status:closed runStatus:error created:>={from_date} '

    rest_api_instance = demisto.executeCommand("getList", {"listName": "Gaiatop_CoreRESTAPIInstance"})[0]['Contents']

    incidents = demisto.executeCommand("SearchIncidentsV2", {
        "query": query,
        "summarizedversion": True,
    })

    incidents = demisto.dt(incidents, "Contents.Contents.data.id")

    if incidents:
        results = get_error_data(incidents, rest_api_instance)
        demisto.results(json.dumps(results))
    else:
        return_results(None)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
