import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
res = demisto.executeCommand("GetLargestInvestigations", {"from": "", "to": "", "table_result": "true"})

incidentsbiggerthan1mb = res[0]['Contents']['data']
incidentsbiggerthan10mb = list(filter(lambda x: x['Size(MB)'] > 10, res[0]['Contents']['data']))
incidentswithmorethan500entries = list(filter(lambda x: x['AmountOfEntries'] > 500, res[0]['Contents']['data']))
numberofincidentsbiggerthan1mb = res[0]['Contents']['total']
numberofincidentsbiggerthan10mb = len(list(filter(lambda x: x['Size(MB)'] > 10, res[0]['Contents']['data'])))
numberofincidentswithmorethan500entries = len(list(filter(lambda x: x['AmountOfEntries'] > 500, res[0]['Contents']['data'])))

for table in [incidentsbiggerthan1mb, incidentsbiggerthan10mb, incidentswithmorethan500entries]:
    for entry in table:
        for key in list(entry):
            if key == 'Size(MB)':
                new_key = key.replace("(MB)", "")
                entry[new_key.lower()] = entry.pop(key)
                entry[new_key.lower()] = str(entry[new_key.lower()]) + " MB"
                continue

            entry[key.lower()] = entry.pop(key)

analyzeFields = {
    "incidentsbiggerthan1mb": incidentsbiggerthan1mb,
    "incidentsbiggerthan10mb": incidentsbiggerthan10mb,
    "incidentswithmorethan500entries": incidentswithmorethan500entries,
    "numberofincidentsbiggerthan1mb": numberofincidentsbiggerthan1mb,
    "numberofincidentsbiggerthan10mb": numberofincidentsbiggerthan10mb,
    "numberofincidentswithmorethan500entries": numberofincidentswithmorethan500entries
}

demisto.executeCommand('setIncident', analyzeFields)

actionItems = []

if numberofincidentswithmorethan500entries > 300:
    actionItems.append({'category': 'DB Analysis', 'severity': 'High',
                        'description': "Too many incidents with high number of war room entries were found, consider to use quite mode in task settings"})

if numberofincidentsbiggerthan10mb > 1:
    actionItems.append({'category': 'DB Analysis', 'severity': 'High',
                        'description': "Large incidents were found, consider to use quite mode in task settings and delete context unneeded Context"})

if numberofincidentsbiggerthan1mb > 300:
    actionItems.append({'category': 'DB Analysis', 'severity': 'High',
                        'description': "Too many incidents with bigger than 1 MB were found, consider to use quite mode in task settings and delete Context"})

results = CommandResults(
    outputs_prefix="actionableitems",
    outputs=actionItems)

return_results(results)
