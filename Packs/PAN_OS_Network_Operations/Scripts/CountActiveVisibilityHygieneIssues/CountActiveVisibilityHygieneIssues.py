import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


"""
Counts the number of open Visibility Hygiene issues to display in an incident layout.
"""
res = demisto.executeCommand("GetIncidentsByQuery", {
    "query": f"-status:closed -category:job type:\"PAN-OS Network Operations - Visibility Hygiene\""
})
if is_error(res):
    return_error(get_error(res))

incidents = json.loads(res[0]['Contents'])

issue_list = []
for incident in incidents:
    grid_field = incident.get("CustomFields").get("panosnetworkoperationsconfigurationhygieneissues")
    issue_list += grid_field

count = len(issue_list)

data = {
    "Type": 17,
    "ContentsFormat": "number",
    "Contents": {
        "stats": count,
        "params": {
            "layout": "horizontal",
            "name": "Configuration Hygiene Issues",
            "sign": "",
            "colors": {
                "items": {
                    "#00CD33": {"value": -1},
                    "#FF9000": {"value": 0},
                    "#FF1744": {"value": 10},
                }
            },
            "type": "above"
        }
    }
}

# If demisto.args() isn't empty, then this is being invoked as a widget script, in which case simply return the count.
# Also check for currentUser key, which deliniates this as being run within an incident layout
if "currentUser" in demisto.args():
    demisto.results(data)
elif demisto.args():
    demisto.results(count)
else:
    demisto.results(data)
