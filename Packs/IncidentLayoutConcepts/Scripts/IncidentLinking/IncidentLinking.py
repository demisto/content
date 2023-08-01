import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
incidentList = []
searchList = []

action = demisto.args().get('action')
# Grab the parent incident ID
if demisto.args().get('parent'):
    parentID = demisto.args()['parent']
else:
    parentID = demisto.incidents()[0]['id']

# Convert the input into a list
if demisto.args()['linkedIncidents']:
    if ',' in demisto.args()['linkedIncidents']:
        incidentList = demisto.args()['linkedIncidents'].split(',')
    else:
        incidentList.append(demisto.args()['linkedIncidents'])
else:
    return_error("Cannot proceed with")
comment = demisto.args()['comment']

# Validate that all incident IDs are correct
res = demisto.executeCommand("getIncidents", {'id': str(parentID) + ',' + ','.join(incidentList)})[0]["Contents"]
# Check if result in empty, cannot proceed
if res['total'] == 0:
    return_error("No valid incident IDs found")
# Convert the results into a usable list
searchList = [item['id'] for item in res['data']]
# Validate if the incident IDs exist.
if not parentID in searchList:
    return_error("Invalid parent ID provided")
if not set(incidentList).issubset(searchList):
    return_error("Invalid child IDs provided")
# Incident update for child
# Grab the existing value of the incidentlinkinggrid field
tmp = []
for item in res['data']:
    # Does it match the child incidents
    if item['id'] in incidentList:
        # Grab the current linked incidents
        tmp = item['CustomFields'].get('incidentlinkinggrid', [])
        if action == 'link':
            # Add the new entry, might need to add validation for duplicate entries
            tmp.append({'id': parentID, 'relationship': 'Child of', 'comment': comment})
        elif action == 'unlink' and tmp != []:
            for idx, content in enumerate(tmp, start=0):
                if content['id'] == parentID:
                    tmp.pop(idx)
        demisto.executeCommand("setIncident", {'id': item['id'], 'incidentlinkinggrid': tmp})
    # Does it match the parent ID
    elif item['id'] == parentID:
        tmp = item['CustomFields'].get('incidentlinkinggrid', [])
        for child in incidentList:
            if action == 'link':
                # Add the new entry, might need to add validation for duplicate entries
                tmp.append({'id': child, 'relationship': 'Parent of', 'comment': comment})
            if action == 'unlink':
                for idx, content in enumerate(tmp, start=0):
                    if child == content['id']:
                        tmp.pop(idx)
        demisto.executeCommand("setIncident", {'id': item['id'], 'incidentlinkinggrid': tmp})
