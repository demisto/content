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
    try:
        update_alert_status()
    except Exception as ex:
        return_error(f'Failed to execute varonis-alert-post-processing. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
