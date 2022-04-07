import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    command_args = {}
    incident = demisto.incident()

    alert_status = args['new']
    alert_status = alert_status.lower().replace(' ', '_')
    command_args['alert_status'] = alert_status

    incident_json = json.loads(incident.get('rawJSON'))
    command_args['alert_id'] = incident_json.get('id')
    command_args['aggregate_alert_id'] = incident_json.get('aggregate_alert_id')

    res = demisto.executeCommand("cybersixgill-update-alert-status", command_args)

    if isError(res[0]):
        return_error('Failed to update Actionable alert status - {}'.format(res[0]['Contents']))
    else:
        demisto.results("Actionable Alert Status Updated successfully.")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
