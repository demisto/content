import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_task_id(task_name, failed_incidents_data):
    result = []
    for data in failed_incidents_data:
        if data.get('Task Name') == task_name:
            result.append({
                "TaskID": data.get("Task ID"),
                "IncidentID": data.get("Incident ID")
            })
    return result


def main():
    args = demisto.args()
    task_name = args.get('TaskName')
    failed_incidents_data = demisto.context().get('GetFailedTasks')

    if failed_incidents_data:
        output = get_task_id(task_name, failed_incidents_data)
        return_results(CommandResults(outputs=output, outputs_prefix="TasksDetails"))
    else:
        return_results("No failed tasks found")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
