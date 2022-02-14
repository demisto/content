import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Looks for Hygiene Incidents and returns a duration widget representing how recently it was run."""
# -- This is a way to get around trimming commonserverpython on import
import datetime

try:
    demisto.args()
    pass
except:
    from CommonServerPython import *

current_incident_id = demisto.incidents()[0].get("id")
res = demisto.executeCommand("GetIncidentsByQuery", {
    "query": f"-category:job type:\"PAN-OS Network Operations - Snapshot Comparison\" linkedIncidents:{current_incident_id}"
})
if is_error(res):
    return_error(get_error(res))

new_target = demisto.args().get("target")

incidents = json.loads(res[0]['Contents'])
device_incident_found = False
time_deltas = []
for incident in incidents:
    occurred_time = datetime.datetime.strptime(incident.get("occurred").split(".")[0], "%Y-%m-%dT%H:%M:%S")
    current_time = datetime.datetime.now()
    time_delta = current_time - occurred_time
    time_deltas.append(time_delta.seconds)

if len(time_deltas) == 0:
    shortest_time_delta = 0
else:
    shortest_time_delta = sorted(time_deltas)[0]

data = {
    "Type": 17,
    "ContentsFormat": "duration",
    "Contents": {
        "stats": shortest_time_delta,
        "params": {
            "layout": "horizontal",
            "name": "Last run visibility incident",
            "sign": "@",
            "colors": {
                "items": {
                    "#00CD33": {
                        "value": 10
                    },
                    "#FAC100": {
                        "value": 20
                    },
                    "green": {
                        "value": 40
                    }
                }
            },
            "type": "above"
        }
    }
}

demisto.results(data)
