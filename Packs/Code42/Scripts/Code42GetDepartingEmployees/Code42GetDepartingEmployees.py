import demistomock as demisto
from CommonServerPython import *


def _get_departing_employees():
    command_result = demisto.executeCommand("code42-departingemployee-get-all", {})
    if not command_result:
        return []

    return command_result[0]["Contents"]


def get_departing_employees():
    res = {"total": 0}
    res_data = []

    try:
        employees = _get_departing_employees()
        res["total"] = len(employees)

        # Get each employee on the Departing Employee List.
        for employee in employees:
            username = employee.get("userName")
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
