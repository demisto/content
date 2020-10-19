from typing import Dict

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_grids(custom_fields, linked_incident):
    latest_related_incident_id = max(linked_incident)
    linked_list_data = demisto.executeCommand("getIncidents", {'id': latest_related_incident_id})
    linked_content = linked_list_data[0].get("Contents", {}).get("data")[0]
    linked_created_date = linked_content.get("created", {}).split("T")[0]
    linked_integrations_data = linked_content.get("CustomFields").get("integrationstestgrid",
                                                                      {})  # table of the linked incident

    integrations_data = {}
    for row in linked_integrations_data:
        instance_id = row.get("instance")
        integrations_data[instance_id] = row.get("analystnote", "")

    main_integration_grid = custom_fields.get("integrationstestgrid")  # Main incident table for integrations
    for main_row in main_integration_grid:
        if not main_row.get("analystnote"):
            last_analyst_note = integrations_data.get(main_row.get('instance'), '')
            if last_analyst_note:
                main_row["analystnote"] = f'({str(linked_created_date)}) ' \
                                          f'{integrations_data.get(main_row.get("instance"), "")}'

    incidents_data: Dict[str, tuple] = {}
    linked_incidentsD_data = linked_content.get("CustomFields").get("playbooktaskserrors",
                                                                    {})  # table of the linked incident
    for row in linked_incidentsD_data:
        incidents_data[row.get("incidentid")] = (row.get('task_id'), row.get("analystnote", ""))

    main_incident_grid = custom_fields.get("playbooktaskserrors")  # Main incident table for incidents
    for main_row in main_incident_grid:
        if main_row.get('incidentid') not in incidents_data:
            # Does not appear in the last incident
            continue

        main_row['task_id'] = incidents_data[main_row.get('incidentid')][0]

        if not main_row.get("analystnote"):
            last_analyst_note = incidents_data[main_row.get('incidentid')][1]
            if last_analyst_note:
                main_row["analystnote"] = f'({str(linked_created_date)}) ' \
                                          f'{incidents_data[main_row.get("incidentid")][1]}'

    return main_integration_grid, main_incident_grid


def main():
    incident = demisto.incidents()[0]
    custom_fields = incident.get('CustomFields')
    linked_incident = custom_fields.get('similarincident')

    if linked_incident:
        main_integration_grid, main_incident_grid = create_grids(custom_fields, linked_incident)
        main_incident_grid.sort(key=lambda incident_dict: incident_dict.get('creationdate'),
                                reverse=True)  # sort incident grid by creation date

        demisto.executeCommand("setIncident", {'customFields': {'integrationstestgrid': main_integration_grid}})
        demisto.executeCommand("setIncident", {'customFields': {'playbooktaskserrors': main_incident_grid}})


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
