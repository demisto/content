import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


"""
Searches the Device Incidents for matching devices and returns them. This allows for more granular filtering within use case playbooks.
"""
target = demisto.args().get("target")

res = demisto.executeCommand("GetIncidentsByQuery", {
    "query": f"-status:closed -category:job type:\"PAN-OS Network Operations - Device\" panosnetworkoperationshostname:* {target}"
})
if is_error(res):
    return_error(get_error(res))

incidents = json.loads(res[0]['Contents'])

outputs = []

for device_incident in incidents:
    incident_id = device_incident.get("id")
    incident_name = device_incident.get("name")

    outputs.append({
        "incident_id": incident_id,
        "incident_name": incident_name,
    })

return_results(
    CommandResults(
        outputs_prefix="GetDevicesByQuery",
        outputs=outputs,
        readable_output=tableToMarkdown("Query Result", outputs)
    ))
