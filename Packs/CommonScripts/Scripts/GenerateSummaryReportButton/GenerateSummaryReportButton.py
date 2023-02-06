import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# get incident id
incident_id = demisto.incidents()[0].get('id')

# generate the Case Report
demisto.results(demisto.executeCommand("generateSummaryReport", {
                "incidentId": incident_id, "name": "Case Report", "type": "pdf"}))
