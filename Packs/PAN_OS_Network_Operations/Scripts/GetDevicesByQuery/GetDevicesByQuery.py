import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


"""
Searches the Device Incidents for matching devices and returns them. This allows for more granular filtering within use case playbooks.
"""
query = demisto.args().get("query")

res = demisto.executeCommand("GetIncidentsByQuery", {
    "query": f"-status:closed -category:job type:\"PAN-OS Network Operations - Device\" panosnetworkoperationshostname:* {query}"
})
if is_error(res):
    return_error(get_error(res))

incidents = json.loads(res[0]['Contents'])

outputs = []

for device_incident in incidents:
    incident_id = device_incident.get("id")
    custom_fields = device_incident.get("CustomFields")
    device_host_id = custom_fields.get("panosnetworkoperationstarget")
    device_hostname = custom_fields.get("panosnetworkoperationshostname")
    admin_domain = custom_fields.get("panosnetworkoperationsdeviceadministrativedomain")

    outputs.append({
        "hostname": device_hostname,
        "hostid": device_host_id,
        "incident_id": incident_id,
        "admin_domain": admin_domain
    })

return_results(
    CommandResults(
        outputs_prefix="GetDevicesByQuery",
        outputs=outputs,
        readable_output=tableToMarkdown("Query Result", outputs)
    ))
