import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


NO_INCIDENT_CLOSED_MSG = '0 incidents marked as duplicates'


def is_incident_not_closed(response):
    """Check if the incident was closed based on the response contents."""
    content = response[0].get('Contents') or response[0].get('contents')
    return content == NO_INCIDENT_CLOSED_MSG


def main():
    current_incident_id = demisto.incidents()[0]['id']
    duplicate_id = demisto.args()['duplicateId']
    res = demisto.executeCommand("linkIncidents", {"incidentId": duplicate_id, "linkedIncidentIDs": current_incident_id,
                                                   "action": "duplicate"})
    raise_error = demisto.args().get('raise_error', False)
    if raise_error and is_incident_not_closed(res):
        return_error('The incident was not closed. Check if the incident is missing a mandatory field by its type.')
    else:
        demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
