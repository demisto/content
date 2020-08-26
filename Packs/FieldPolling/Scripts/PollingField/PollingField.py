import re

import demistomock as demisto
from CommonServerPython import *  # noqa: F401

args = demisto.args()
field = args.get('field')
regex = args.get('regex', None)
if regex:
    regex = re.compile(regex)

incident = demisto.incident()
customFields = incident.get('CustomFields')

data = {
    'field': field,
    'exists': False
}

if field in incident:
    if regex:
        if re.match(regex, incident.get(field)):
            data['exists'] = True
    else:
        if len(incident.get(field)) > 0:
            data['exists'] = True

elif field in customFields:
    if regex:
        if re.match(regex, customFields.get(field)):
            data['exists'] = True
    else:
        if len(customFields.get(field)) > 0:
            data['exists'] = True

demisto.results({
    'Type': entryTypes['note'],
    'Contents': data,
    'ContentsFormat': formats['json'],
    'EntryContext': {
        'PollingCheckField(val.field == obj.field)': data
    }
})
