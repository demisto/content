import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateutil.relativedelta

args = demisto.args()
Thresholds = {
    "numberofincidentswithmorethan500entries": 300,
    "numberofincidentsbiggerthan10mb": 1,
    "numberofincidentsbiggerthan1mb": 300,
}
thresholds = args.get('Thresholds', Thresholds)

prevMonth = datetime.today() + dateutil.relativedelta.relativedelta(months=-1)

res = demisto.executeCommand("GetLargestInvestigations", {"from": prevMonth.strftime("%Y-%m-%d"),
                                                          "to": prevMonth.strftime("%Y-%m-%d"),
                                                          "table_result": "true"})

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
    "investigationsbiggerthan1mb": incidentsbiggerthan1mb,
    "investigationsbiggerthan10mb": incidentsbiggerthan10mb,
    "investigationswithmorethan500entries": incidentswithmorethan500entries,
    "numberofinvestigationsbiggerthan1mb": numberofincidentsbiggerthan1mb,
    "numberofinvestigationsbiggerthan10mb": numberofincidentsbiggerthan10mb,
    "numberofinvestigationswithmorethan500entries": numberofincidentswithmorethan500entries
}

demisto.executeCommand('setIncident', analyzeFields)

actionItems = []
DESCRIPTION = [
    "Too many incidents with high number of war room entries were found, consider to use quite mode in task settings",
    "Large incidents were found, consider to use quite mode in task settings and delete context unneeded Context"
]
RESOLUTION = [
    "Playbook Settings: https://xsoar.pan.dev/docs/playbooks/playbook-settings",
    "Extending Context and Ignore Outputs: https://xsoar.pan.dev/docs/playbooks/playbooks-extend-context"
]

if numberofincidentswithmorethan500entries > int(thresholds['numberofincidentswithmorethan500entries']):

    actionItems.append({'category': 'DB Analysis',
                        'severity': 'High',
                        'description': DESCRIPTION[0],
                        'resolution': '{}'.format(RESOLUTION[0])
                        })

if numberofincidentsbiggerthan10mb > thresholds['numberofincidentsbiggerthan10mb']:
    actionItems.append({'category': 'DB Analysis',
                        'severity': 'High',
                        'description': DESCRIPTION[1],
                        'resolution': '{} \n{}'.format(RESOLUTION[0], RESOLUTION[1])
                        })

if numberofincidentsbiggerthan1mb > thresholds['numberofincidentsbiggerthan1mb']:
    actionItems.append({'category': 'DB Analysis',
                        'severity': 'High',
                        'description': DESCRIPTION[1],
                        'resolution': '{} \n{}'.format(RESOLUTION[0], RESOLUTION[1])
                        })

results = CommandResults(
    outputs_prefix="dbstatactionableitems",
    outputs=actionItems)

return_results(results)
