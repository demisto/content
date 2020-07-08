import demistomock as demisto
from CommonServerPython import *


def main():
    res = {"total": 0}
    res_data = []

    try:
        employees = demisto.executeCommand("code42-departingemployee-get-all", {})[0]["Contents"]
        res["total"] = len(employees)

        # Get each employee on the Departing Employee List and their total alerts.
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
    main()
