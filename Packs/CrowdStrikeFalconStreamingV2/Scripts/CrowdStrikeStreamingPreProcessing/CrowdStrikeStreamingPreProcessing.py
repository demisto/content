import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import json


def get_host_from_system_incident(incident: dict[str, Any]) -> str:
    host = ''
    for label in incident.get('labels', []):
        if label.get('type', '') == 'System':
            host = label.get('value', '')
    return host


def main():  # pragma: no cover
    res = True
    for inc in demisto.incidents():
        host = get_host_from_system_incident(inc)
        if host:
            sameIncidents0Contents = execute_command(
                'getIncidents',
                {'query': f'labels.value:"{host}" and labels.type:System'}
            )
            # if found sameIncidents found, add this incident data to war room
            sameIncidentsCount = sameIncidents0Contents['total']
            if sameIncidentsCount > 0:
                res = False
                otherIncidents = sameIncidents0Contents['data']
                entries: list[dict[str, Any]] = []
                entries.append({'Contents': f'Duplicate incident from crowdstrike: {inc.get("name")}'})
                entries.append({'Type': EntryType.NOTE, 'ContentsFormat': 'json', 'Contents': json.dumps(inc)})
                entries_str = json.dumps(entries)
                execute_command('addEntries', {'id': otherIncidents[0]['id'], 'entries': entries_str})

    demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
