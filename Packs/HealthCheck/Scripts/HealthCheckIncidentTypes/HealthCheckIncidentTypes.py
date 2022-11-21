import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import time
start_time = time.time()
# main()


incident = demisto.incidents()[0]
accountName = incident.get('account')
accountName = f"acc_{accountName}" if accountName else ""

res = demisto.executeCommand(
    "demisto-api-get",
    {
        "uri": f"{accountName}/incidenttype"
    })[0]["Contents"]["response"]


nonLockedTypes = list(filter(lambda x: x.get('locked') == False or x.get('detached') == True, res))
extractAll = list(filter(lambda x: x['extractSettings']['mode'] == 'All', nonLockedTypes))
extractWithNoSettings = list(filter(lambda x: x['extractSettings']['mode']
                             == 'Specific' and x['extractSettings']['fieldCliNameToExtractSettings'] == {}, nonLockedTypes))

table = []
for incidentType in nonLockedTypes:
    newEntry = {}
    extractSettings = incidentType['extractSettings']
    if extractSettings['mode'] == 'All':
        newEntry['incidenttype'] = incidentType['prevName']
        newEntry['detection'] = "Indicators extraction defined on all fields"
        table.append(newEntry)
    elif extractSettings['mode'] == 'Specific' and extractSettings['fieldCliNameToExtractSettings']:
        newEntry['incidenttype'] = incidentType['prevName']
        newEntry['detection'] = "No indicators extraction defined on all fields"
        table.append(newEntry)
    else:
        continue

demisto.executeCommand("setIncident", {"healthcheckautoextractionbasedincidenttype": table})
