import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():

    context = demisto.context().get('GetFailedTasks', {})
    failed_task_count = len(demisto.dt(context, "Task Name"))

    if failed_task_count > 50:
        font_color = "#FF9000"
    else:
        font_color = "#00CD33"

    failed_task_count = f"""
        <h1 style=color:{font_color};text-align:center;font-size:800%;> {failed_task_count} </h1>
        <h1 style=color:{font_color};text-align:center;font-size:200%;> Failed Tasks </h1>
    """

    demisto.results({
        "ContentsFormat": formats["html"],
        "Type": entryTypes["note"],
        "Contents": failed_task_count
    })

    # return_results(res)


if __name__ in ("__builtin__", "__main__", "builtins"):
    main()
