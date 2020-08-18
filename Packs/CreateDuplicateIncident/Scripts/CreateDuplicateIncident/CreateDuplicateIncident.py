import json
from datetime import timedelta

import demistomock as demisto
from CommonServerPython import *
from dateutil.parser import parse

incident = demisto.incidents()[0]


def get_labels_map(labels):
    labels_map = []
    for x in labels:
        labels_map.append({x['type']: x['value']})
    return labels_map


old_time = (parse(incident['occurred']) - timedelta(hours=1)).isoformat()  # .strftime("%Y-%m-%dT%H:%M:%S%z")
duplicate_incident = {
    'name': incident['name'],
    'details': incident['details'],
    'severity': incident['severity'],
    'customFields': incident['CustomFields'],
    'labels': get_labels_map(incident['labels']),
    'occurred': old_time
}

res = demisto.executeCommand("createNewIncident", duplicate_incident)
demisto.results(res)
