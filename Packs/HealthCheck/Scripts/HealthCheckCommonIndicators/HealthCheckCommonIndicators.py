import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


args = demisto.args()
Thresholds = {
    "relatedIndicatorCount": 100,
}

thresholds = args.get('Thresholds', Thresholds)

body = {
    "page": 0,
    "size": 10,
    "query": "",
    "sort": [{
        "field": "relatedIncCount",
        "asc": False
    }],
    "period": {
        "by": "day",
        "fromValue": 90
    }
}

indicators = demisto.executeCommand(
    "demisto-api-post", {"uri": "indicators/search", "body": body})[0]["Contents"]["response"]["iocObjects"]
res = []
DESCRIPTION = [
    "The indicator: \"{}\" was found {} times, you may consider adding it to the exclusion list"
]

RESOLUTION = [
    "You may consider adding it to the exclusion list"
]

for indicator in indicators:
    if indicator["relatedIncCount"] > thresholds["relatedIndicatorCount"]:
        res.append({"category": "Indicators",
                    "severity": "Low",
                    "description": f"{DESCRIPTION[0]}".format(indicator["value"], indicator["relatedIncCount"]),
                    "resolution": f"{RESOLUTION[0]}"
                    })

results = CommandResults(
    readable_output="HealthCheckCommonIndicators Done",
    outputs_prefix="actionableitems",
    outputs=res)

return_results(results)
