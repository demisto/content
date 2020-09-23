import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()[0]
incidentID = incident.get('id')
custom_fields = incident.get('CustomFields')
LinkedIncident = custom_fields.get('similarincident', [""])[0]

if LinkedIncident:
    linkedlistData= demisto.executeCommand("getIncidents", {'id': LinkedIncident})
    linkedContent = linkedlistData[0].get("Contents",{}).get("data")[0]
    linkedCreatedDate = linkedContent.get("created",{}).split("T")[0]
    linkedIntegrationsData = linkedContent.get("CustomFields").get("integrationstestgrid",{}) #table of the linked incident
    integrationsData = {}
    for row in linkedIntegrationsData:
        integrationsData[row.get("instance")] = row.get("analystnote","")
    mainIntegrationGrid = custom_fields.get("integrationstestgrid") # Main incident table for integrations
    for mainRow in mainIntegrationGrid:
        if not mainRow.get("analystnote"):
            mainRow["analystnote"] = integrationsData.get(mainRow.get('instance'), '')
            if mainRow.get("analystnote"):
                mainRow["analystnote"] = integrationsData.get(mainRow.get('instance'), '') + " (" + str(linkedCreatedDate) + ")"

    linkedIncidentsData = linkedContent.get("CustomFields").get("playbooktaskserrors",{}) #table of the linked incident
    incidentsData = {}
    for row in linkedIncidentsData:
        incidentsData[row.get("incidentid")] = row.get("analystnote","")
    mainIncidentGrid = custom_fields.get("playbooktaskserrors") # Main incident table for incidents
    for mainRow in mainIncidentGrid:
        if not mainRow.get("analystnote"):
            mainRow["analystnote"] = incidentsData.get(mainRow.get('incidentid'), '')
            if mainRow.get("analystnote"):
                mainRow["analystnote"] = incidentsData.get(mainRow.get('incidentid'), '') + " (" + str(linkedCreatedDate) + ")"


demisto.executeCommand("setIncident", {'customFields': {'integrationstestgrid': mainIntegrationGrid}})
demisto.executeCommand("setIncident", {'customFields': {'playbooktaskserrors': mainIncidentGrid}})