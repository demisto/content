import demistomock as demisto
from CommonServerPython import *
dArgs = demisto.args()
incidents = demisto.incidents()
if incidents:
    incident = incidents[0]

    # Only track the incident if it's an ExtraHop Detection
    if incident.get('type') == 'ExtraHop Detection':

        if incident.get('id') or incident.get('investigationId'):

            args = {
                'incident_id': incident.get('id') or incident.get('investigationId'),
                'detection_id': incident.get('CustomFields', {}).get('detectionid', None),
                'incident_owner': incident.get('owner', None),
                'incident_status': incident.get('status', None),
                'incident_close_reason': incident.get('closeReason', None)
            }

            # Field Trigger value change
            if 'name' in dArgs:
                if dArgs['name'] == 'owner':
                    args['incident_owner'] = dArgs['new']
                elif dArgs['name'] == 'status':
                    args['incident_status'] = dArgs['new']

            track_ticket = demisto.executeCommand("extrahop-ticket-track", args)[0]

            if isError(track_ticket):
                demisto.results(track_ticket)
            else:
                demisto.results({
                    "Type": entryTypes["note"],
                    "ContentsFormat": formats["text"],
                    "Contents": track_ticket['Contents']
                })

        else:
            return_warning("Could not identify the Incident ID or Investigation ID.")
else:
    return_warning("No Incidents to process.")
