import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ctx = demisto.context()
incident = demisto.incidents()[0]

main = {"incident": incident, "ctx": ctx, "widgets": {}}

# Save data from widgets

# HealthCheckIncidentsCreatedMonthly
res = demisto.executeCommand("HealthCheckIncidentsCreatedMonthly", {})[0]["Contents"]
main["widgets"]["IncidentsCreatedMonthly"] = json.loads(res).get("stats")


# HealthCheckIncidentsCreatedWeekly
res = demisto.executeCommand("HealthCheckIncidentsCreatedWeekly", {})[0]["Contents"]
main["widgets"]["IncidentsCreatedWeekly"] = json.loads(res).get("stats")

# HealthCheckIncidentsCreatedDaily
res = demisto.executeCommand("HealthCheckIncidentsCreatedDaily", {})[0]["Contents"]
main["widgets"]["IncidentsCreatedDaily"] = json.loads(res).get("stats")


variables = json.dumps(main).encode("utf-8")
file_entry = fileResult(filename="HealthCheckDataExport.txt", data=variables)
return_results(file_entry)
