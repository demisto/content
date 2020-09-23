from typing import Dict

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()[0]
incidentID = incident.get('id')
custom_fields = incident.get('CustomFields')
LinkedIncident = custom_fields.get('similarincident')

if LinkedIncident:
    newerLink = max(LinkedIncident)
    linkedlistData = demisto.executeCommand("getIncidents", {'id': newerLink})
    linkedContent = linkedlistData[0].get("Contents", {}).get("data")[0]
    linkedCreatedDate = linkedContent.get("created", {}).split("T")[0]
    linkedIntegrationsData = linkedContent.get("CustomFields").get("integrationstestgrid",
                                                                   {})  # table of the linked incident

    integrationsData = {}
    for row in linkedIntegrationsData:
        integrationsData[row.get("instance")] = row.get("analystnote", "")

    mainIntegrationGrid = custom_fields.get("integrationstestgrid")  # Main incident table for integrations
    for mainRow in mainIntegrationGrid:
        if not mainRow.get("analystnote"):
            mainRow["analystnote"] = integrationsData.get(mainRow.get('instance'), '')
            if mainRow.get("analystnote"):
                mainRow["analystnote"] = "(" + str(linkedCreatedDate) + ") " + integrationsData.get(
                    mainRow.get('instance'), '')

    incidentsData: Dict[str, tuple] = {}
    linkedIncidentsData = linkedContent.get("CustomFields").get("playbooktaskserrors",
                                                                {})  # table of the linked incident
    for row in linkedIncidentsData:
        incidentsData[row.get("incidentid")] = (row.get('task_id'), row.get("analystnote", ""))

    mainIncidentGrid = custom_fields.get("playbooktaskserrors")  # Main incident table for incidents
    for mainRow in mainIncidentGrid:
        if mainRow.get('incidentid') not in incidentsData:
            continue

        mainRow['task_id'] = incidentsData[mainRow.get('incidentid')][0]

        if not mainRow.get("analystnote"):
            mainRow["analystnote"] = incidentsData[mainRow.get('incidentid')][1]
            if mainRow.get("analystnote"):
                mainRow["analystnote"] = "(" + str(linkedCreatedDate) + ") " + \
                                         incidentsData[mainRow.get('incidentid')][1]

    demisto.executeCommand("setIncident", {'customFields': {'integrationstestgrid': mainIntegrationGrid}})
    demisto.executeCommand("setIncident", {'customFields': {'playbooktaskserrors': mainIncidentGrid}})
