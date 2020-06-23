import demistomock as demisto
from CommonServerPython import *

res = {"total": 0, "data": []}
employees = demisto.executeCommand("code42-departingemployee-get-all", {})[0]["Contents"]
res["total"] = len(employees)

for employee in employees:
    user_id = employee["userId"]



    employee_res = {"Username": employee["userName"]}
    res["data"].append(employee_res)

demisto.results(res)
