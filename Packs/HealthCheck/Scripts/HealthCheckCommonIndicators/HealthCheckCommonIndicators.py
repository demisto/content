import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
body = {"page": 0, "size": 10, "query": "", "sort": [
    {"field": "relatedIncCount", "asc": False}], "period": {"by": "day", "fromValue": 90}}
indicators = demisto.executeCommand(
    "demisto-api-post", {"uri": "indicators/search", "body": body})[0]["Contents"]["response"]["iocObjects"]
res = []
for indicator in indicators:
    if indicator["relatedIncCount"] > 100:
        res.append({"category": "Indicators", "severity": "Low", "description": "The indicator: \"{}\" was found {} times, you may consider adding it to the exclusion list".format(
            indicator["value"], indicator["relatedIncCount"])})

results = CommandResults(
    readable_output="HealthCheckCommonIndicators Done",
    outputs_prefix="actionableitems",
    outputs=res)

return_results(results)
