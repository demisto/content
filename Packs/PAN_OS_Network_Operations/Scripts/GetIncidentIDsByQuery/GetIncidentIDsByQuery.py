import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


"""
Searches for all incidents and returns the matching based on the query
"""
query = demisto.args().get("query")

res = demisto.executeCommand("GetIncidentsByQuery", {
    "query": query
})
if is_error(res):
    return_error(get_error(res))

incidents = json.loads(res[0]['Contents'])

outputs = []

for matched_incident in incidents:
    incident_id = matched_incident.get("id")
    incident_name = matched_incident.get("name")

    outputs.append({
        "incident_id": incident_id,
        "incident_name": incident_name
    })

return_results(
    CommandResults(
        outputs_prefix="GetIncidentIDsByQuery",
        outputs=outputs,
        readable_output=tableToMarkdown("Query Result", outputs)
    ))
