import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():

    context = demisto.context()
    task_errors = demisto.dt(context, "NumberofFailedIncidents.Number of total errors")
    task_errors = task_errors[0] if isinstance(task_errors, list) else task_errors

    if task_errors > 50:
        font_color = "#FF9000"
    else:
        font_color = "#00CD33"

    task_errors = f"""
        <h1 style=color:{font_color};text-align:center;font-size:800%;> {task_errors} </h1>
        <h1 style=color:{font_color};text-align:center;font-size:200%;> Errors </h1>
    """

    demisto.results({
        "ContentsFormat": formats["html"],
        "Type": entryTypes["note"],
        "Contents": task_errors
    })


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
