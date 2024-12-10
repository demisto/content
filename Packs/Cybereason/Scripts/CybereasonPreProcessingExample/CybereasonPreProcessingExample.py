import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_guid_from_system_incident(incident: dict[str, Any]) -> str:
    malop_guid = ''
    for label in incident['labels']:
        if label['type'] == 'GUID':
            malop_guid = label['value']
            break
    return malop_guid


incident = demisto.incidents()
for inc in incident:
    res = True
    malop_guid = get_guid_from_system_incident(inc)
    response = execute_command(
        'getIncidents',
        {'query': f'name:"Cybereason Malop {malop_guid}"'}
    )
    malop_incident = response['data']
    demisto.debug(f"malop incident - {malop_incident}")
    if malop_incident:
        # Malop was already fetched - updating the relevant incident
        res = False
        malop_incident = malop_incident[0]
        entries: list[dict[str, Any]] = []
        entries.append({'Contents': f'Duplicate incident from cybereason: {inc.get("name")}'})
        entries.append({'Type': EntryType.NOTE, 'ContentsFormat': 'json', 'Contents': json.dumps(inc)})
        entries_str = json.dumps(entries)
        execute_command('addEntries', {'id': malop_incident['id'], 'entries': entries_str})
        malop_incident_id = malop_incident['id']
        malop_incident_status = inc['status']
        demisto.debug(f"Updating incident status to : {malop_incident_status}")
        execute_command('setIncident', {'id': malop_incident_id, 'status': malop_incident_status})
