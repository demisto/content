import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

ctx = demisto.context()
incident = demisto.incidents()[0]

main = {"incident": incident, "ctx": ctx, "widgets": {}}

# Save data from widgets

if not is_demisto_version_ge("8.0.0"):
    # Disk Usage Percentage
    res = demisto.executeCommand("HealthCheckDiskUsage", {})[0]["Contents"]
    json.loads(res).get("stats")
    main["widgets"]["DiskUsagePerCentage"] = json.loads(res).get("stats")

    # Disk Usage Line
    res = demisto.executeCommand("HealthCheckDiskUsageLine", {})[0]["Contents"]
    json.loads(res).get("stats")
    main["widgets"]["DiskUsagePerLine"] = json.loads(res).get("stats")

    # Memory Usage
    res = demisto.executeCommand("HealthCheckMemory", {})[0]["Contents"]
    json.loads(res).get("stats")
    main["widgets"]["MemoryUsage"] = json.loads(res).get("stats")

    # CPU Usage
    res = demisto.executeCommand("HealthCheckCPU", {})[0]["Contents"]
    main["widgets"]["CPUUsage"] = json.loads(res).get("stats")

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
