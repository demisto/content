import demistomock as demisto
from CommonServerPython import *


def _get_departing_employees(risk_tags, filter_type):
    tags = risk_tags.split(",") if risk_tags else None
    filter_type = "OPEN" if not filter_type else filter_type
    command_args = {"risktags": tags, "filtertype": filter_type}
    command_result = demisto.executeCommand("code42-highriskemployee-get-all", command_args)
    if not command_result:
        return []

    return command_result[0]["Contents"]


def get_departing_employees():
    res = {"total": 0}
    res_data = []
    risk_tags = demisto.args().get("risktags")
    filter_type = demisto.args().get("filtertype")

    try:
        employees = _get_departing_employees(risk_tags, filter_type)
        res["total"] = len(employees)

        # Get each employee on the High Risk Employee List.
        for employee in employees:
            username = employee["userName"]
            employee_res = {"Username": username}
            res_data.append(employee_res)

        res["data"] = res_data
        demisto.results(res)
    except Exception as e:
        res["total"] = -1
        res["data"] = str(e)

    # Submit final results to Cortex XSOAR
    demisto.results(res)

if __name__ in ("__main__", "__builtin__", "builtins"):
    get_departing_employees()
