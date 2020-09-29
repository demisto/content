import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

try:
    incident = demisto.incidents()[0]
    incident_id = incident['id']
    context = demisto.executeCommand('getContext', {'id': incident_id})[0]['Contents']['context']

    ips_to_block = []
    if 'IP' in context:
        [ips_to_block.append(x['Address']) for x in context['IP'] if 'Address' in x and x['Address'] not in ips_to_block]
    else:
        ips_to_block = ['No values found in context']

    demisto.results({"hidden": False, "options": ips_to_block})

except Exception as error:
    demisto.results({"hidden": False, "options": [str(error)]})
