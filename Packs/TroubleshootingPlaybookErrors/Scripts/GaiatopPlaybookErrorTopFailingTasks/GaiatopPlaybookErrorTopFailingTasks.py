import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections import Counter


def main():
    context = demisto.context().get('GetFailedTasks', {})
    top_failing_task = []
    if context:
        task_name_list = demisto.dt(context, "Task Name")
        count_list = Counter(task_name_list)

        # count_list = {
        #     'event not matched': 6,
        #     'Set List of Rule IDs': 1,
        #     'Get Full Incident Details': 1,
        #     'Types settings': 6,
        #     'Create ServiceNow ticket': 1
        # }

        for i in range(0, 3):
            task_list_values = list(count_list.values())
            max_value = 0
            index_max_value = 0
            task_name = None

            max_value = max(task_list_values)

            index_max_value = task_list_values.index(max_value)
            task_name = list(count_list.keys())[index_max_value]
            top_failing_task.append({"TaskName": task_name, "Count": task_list_values[index_max_value]})

            # top_failing_task[task_name] = task_list_values[index_max_value]
            del count_list[task_name]

        return_results(demisto.executeCommand("JsonToTable", {
            "value": top_failing_task,
            "headers": "TaskName,Count"
        }))

    else:
        return_results("No Failed Tasks Data Found")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
