import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

fetchArgs = {"applicationId": demisto.args()["applicationId"],
             "incidentIds": demisto.args()["incidentIds"]}

incidents = demisto.executeCommand("archer-manually-fetch-incident", fetchArgs)

incidentIds = ""
for incident in incidents:
    incidentData = incident['Contents']
    incidentArgs = {
        "details": incidentData['details'],
        "labels": incidentData['labels'],
        "name": incidentData['name'],
        "occurred": incidentData['occurred'],
        "type": "Archer"
    }
    result = demisto.executeCommand("createNewIncident", incidentArgs)

demisto.results("Fetched according to command.")
