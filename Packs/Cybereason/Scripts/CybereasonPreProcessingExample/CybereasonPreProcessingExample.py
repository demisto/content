import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    res = True
    incident = demisto.incidents()[0]
    malop_guid = ''
    for label in incident['labels']:
        if label['type'] == 'guidString':
            malop_guid = label['value']

    response = demisto.executeCommand('getIncidents', {'query': '-status:Closed and malopguid: {}'.format(malop_guid)})
    malop_incident = response[0]['Contents']['data']

    if malop_incident:
        # Malop was already fetched - updating the relevant incident
        res = False
        malop_incident = malop_incident[0]
        incident['id'] = malop_incident['id']
        demisto.executeCommand('setIncident', incident)

    demisto.results(res)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
