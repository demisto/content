from CommonServerPython import *


def get_context(incident_id):
    res = demisto.executeCommand("getContext", {'id': incident_id})
    try:
        return res[0]['Contents'].get('context') or {}
    except Exception:
        return {}


res = demisto.executeCommand("getIncidents", {"query": demisto.args()['incidentsQuery'],
                                              'limit': int(demisto.args()['limit'])})
incidents = res[0]['Contents']['data']
src_context_key = demisto.args()['sourceContextKey']
target_incident_field = demisto.args()['targetIncidentField']
list_separator = demisto.args()['listSeparator']
success_count = 0
failed_count = 0
skipped_count = 0
for i in incidents:
    incident_id = i['id']
    context = get_context(incident_id)
    value = demisto.dt(context, src_context_key)
    if isinstance(value, list) and len(value) > 0:
        if len(value) == 1:
            value = value[0]
        elif isinstance(value[0], basestring):
            value = list_separator.join(value)
    if value and not isinstance(value, list) and not isinstance(value, dict):
        res = demisto.executeCommand("setIncident", {target_incident_field: value, 'id': i['id']})
        if isError(res[0]):
            failed_count += 1
        else:
            success_count += 1
    else:
        skipped_count += 1

if success_count > 0:
    demisto.results("Update incidents: %d success" % success_count)
if skipped_count > 0:
    demisto.results("Skipped %d incidents due to missing value" % skipped_count)
if failed_count > 0:
    demisto.results("Failed to update %d incidents with setIncident error" % failed_count)
