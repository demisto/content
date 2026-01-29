import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
ENDPOINT_URL = "public/v1/inv-playbook/task/execute"


def restart_task(task_id_object_list, max_task):
    restarted_task_count = 0
    output = {"TaskDetails": [], "RestartCount": restarted_task_count}

    for task_object in task_id_object_list:
        if max_task <= restarted_task_count:
            break
        task_object = json.loads(json.dumps(task_object))
        task_id = task_object.get('TaskID')
        incident_id = task_object.get('IncidentID')

        demisto.info(f"Re-opening task with id {task_id} on incident {incident_id}")

        task_reopened = demisto.executeCommand("taskReopen", {
            "id": task_id,
            "incidentId": incident_id
        })[0]['Contents']

        body = {
            "taskinfo": {
                "invId": incident_id,
                "inTaskID": task_id,
            }
        }
        demisto.info(f"Executing task with id {task_id} on incident {incident_id}")
        execute_task = demisto.executeCommand("core-api-post", {
            "uri": ENDPOINT_URL,
            "body": body
        })[0]['Contents']
        restarted_task_count += 1
        output["TaskDetails"].append(task_object)
        output["RestartCount"] = restarted_task_count

    return output


def main():
    args = demisto.args()
    api_instance = args.get("RESTAPIInstanceName")
    task_id_object_list = args.get('TaskIDObject')
    max_task = int(args.get('MaxTasksToRestart'))

    if task_id_object_list:
        result = restart_task(task_id_object_list, max_task)
        return_results(CommandResults(outputs=result, outputs_prefix="TasksRestarted"))

    else:
        return_results("No tasks data to restart")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
