import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    command_args = {'alert_status': None, 'alert_id': None, 'aggregate_alert_id': None}
    incident = demisto.incident()

    alert_status = args['new']
    alert_status = alert_status.lower().replace(' ', '_')
    command_args['alert_status'] = alert_status

    labels = incident.get('labels', [])
    for label in labels:
        if label.get('type') == 'id':
            command_args['alert_id'] = label.get('value')
        if label.get('type') == 'aggregate_alert_id':
            command_args['aggregate_alert_id'] = label.get('value')

    demisto.info(
        "Update status: alert id - {}, aggregate_alert_id - {}, new status - {}".format(
            command_args.get('alert_id', ''),
            command_args.get('aggregate_alert_id', ''),
            alert_status))
    res = demisto.executeCommand("cybersixgill-update-alert-status", command_args)

    if isError(res[0]):
        return_error('Failed to update Actionable alert status - {}'.format(res[0]['Contents']))
    else:
        demisto.results("Actionable Alert Status Updated successfully.")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
