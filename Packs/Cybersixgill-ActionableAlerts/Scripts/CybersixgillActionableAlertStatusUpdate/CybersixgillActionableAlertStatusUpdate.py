from urllib.parse import parse_qs, urlparse

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()

    command_args = {}

    incident = demisto.incident()

    command_args['alert_status'] = args['new']

    incident_link = incident.get('CustomFields').get('incidentlink')

    command_args['alert_id'] = parse_qs(urlparse(incident_link).fragment)["/?actionable_alert"][0]

    res = demisto.executeCommand("cybersixgill-update-alert-status", command_args)

    if isError(res[0]):
        return_error('Failed to update Actionable alert status - {}'.format(res[0]['Contents']))
    else:
        demisto.results("Actionable Alert Status Updated successfully.")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
