import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand("core-api-get", {"uri": "diagnostics/checks"})[0]["Contents"]["response"]

wList = []
wList.append({"Big Workplans > 3 MB": res["checkRuns"]["diagnostic.workplan.big.workplans"]["result"]["metrics"]["total"],
              "Big tasks": res["checkRuns"]["diagnostic.workplan.big.tasks"]["result"]["metrics"],
              "Tasks turned to quiet mode": res["checkRuns"]["diagnostic.workplan.auto.quiet.task"]["result"]["metrics"]})

return_results({"total": len(wList), "data": wList})
