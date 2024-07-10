import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]


def update_alert_status():
    incident = demisto.incident()
    incident_id = incident['id']
    demisto.debug(f'Post processing incident: {incident_id}')
    demisto.executeCommand('setIncident', {
        'id': incident_id,
        'customFields': {'varonissaasalertstatus': 'closed'}
    })


def main():
    update_alert_status()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
