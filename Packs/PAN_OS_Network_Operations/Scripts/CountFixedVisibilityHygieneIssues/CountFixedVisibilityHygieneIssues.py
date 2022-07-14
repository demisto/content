import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""
Counts the number of open FW Change requests for the platform, if the change management pack is in use.
"""
res = demisto.executeCommand("GetIncidentsByQuery", {
    "query": f"-category:job type:\"PAN-OS Network Operations - Visibility Hygiene\""
})
if is_error(res):
    return_error(get_error(res))

incidents = json.loads(res[0]['Contents'])

issue_list = []
for incident in incidents:
    grid_field = incident.get("CustomFields").get("panosnetworkoperationsfixedconfigurationhygieneissues")
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
                    "#ebebeb": {"value": -1},
                    "#00CD33": {"value": 1},
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
