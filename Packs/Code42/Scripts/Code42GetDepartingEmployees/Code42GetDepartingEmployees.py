import demistomock as demisto
from CommonServerPython import *

res = {"total": 0, "data": []}

try:
    employees = demisto.executeCommand("code42-departingemployee-get-all", {})[0]["Contents"]
    res["total"] = len(employees)

    for employee in employees:
        username = employee["userName"]
        alerts = demisto.executeCommand("code42-alert-search", {"username": username})[0]["Contents"]
        alerts_count = len(alerts)
        if alerts_count:
            employee_res = {"Username": username, "Alerts Count": alerts_count}
            res["data"].append(employee_res)

    demisto.results(res)
except Exception as e:
    demisto.results(e)
