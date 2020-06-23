import demistomock as demisto
from CommonServerPython import *

res = {"total": 0}
res_data = []

try:
    employees = demisto.executeCommand("code42-departingemployee-get-all", {})[0]["Contents"]
    res["total"] = len(employees)

    # Get each employee on the Departing Employee List and their total alerts.
    for employee in employees:
        username = employee["userName"]
        alerts = demisto.executeCommand("code42-alert-search", {"username": username})[0]["Contents"]
        alerts_count = len(alerts)
        employee_res = {"Username": username, "Alerts Count": alerts_count}
        res_data.append(employee_res)

    # Sort such that highest alert counts are first.
    res["data"] = sorted(res_data, key=lambda x: x["Alerts Count"], reverse=True)
    demisto.results(res)
except Exception as e:
    res = {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": "Exception info:\n{0}".format(str(ex))
    }

# Submit final results to Cortex XSOAR
demisto.results(res)
