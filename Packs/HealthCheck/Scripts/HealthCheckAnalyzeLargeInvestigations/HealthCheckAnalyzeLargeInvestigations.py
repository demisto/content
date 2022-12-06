import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import dateutil.relativedelta

THRESHOLDS = {
    'numberofincidentswithmorethan500entries': 300,
    'numberofincidentsbiggerthan1mb': 300,
}
DESCRIPTION = [
    'Too many incidents with high number of war room entries were found, consider to use quiet mode in task settings',
    'Large incidents were found, consider to use quiet mode in task settings and delete unneeded Context'
]
RESOLUTION = [
    'Playbook Settings: https://xsoar.pan.dev/docs/playbooks/playbook-settings',
    'Extending Context and Ignore Outputs: https://xsoar.pan.dev/docs/playbooks/playbooks-extend-context'
]


def format_dict_keys(entry: Dict[str, Any]) -> Dict:
    new_entry = {}
    for key, value in entry.items():
        if key == 'Size(MB)':
            new_entry['size'] = f'{value} MB'
        elif key == 'AmountOfEntries':
            new_entry['info'] = f'{value} Entries'
        else:
            new_entry[key.lower()] = value
    new_entry.pop('size(mb)', None)
    return new_entry


def formatToEntriesGrid(table):
    for entry in table:
        entry['amountofentries'] = entry['info']


def main(args):
    thresholds = args.get('Thresholds', THRESHOLDS)
    append = args.get('Append', 'False')
    prev_month = datetime.today() + dateutil.relativedelta.relativedelta(months=-1)
    current_month = datetime.today()
    res = execute_command('GetLargestInvestigations', {
        'from': prev_month.strftime('%Y-%m-%d'),
        'to': current_month.strftime('%Y-%m-%d'),
        'table_result': 'true',
        'ignore_deprecated': 'true'
    })

    incidentsbiggerthan1mb = []
    incidentswithmorethan500entries = []

    for incident in res['data']:
        formatted_incident = format_dict_keys(incident)
        if incident['AmountOfEntries'] >= 500:
            incidentswithmorethan500entries.append(formatted_incident)
            continue
        incidentsbiggerthan1mb.append(formatted_incident)

    numberofincidentsbiggerthan1mb = len(incidentsbiggerthan1mb)
    numberofincidentswithmorethan500entries = len(incidentswithmorethan500entries)
    if incidentswithmorethan500entries:
        formatToEntriesGrid(incidentswithmorethan500entries)

    analyzeFields = {
        'healthchecklargeinvestigations': incidentsbiggerthan1mb,
        'healthchecknumberofinvestigationsbiggerthan1mb': numberofincidentsbiggerthan1mb,
        'healthcheckincidentslargenumberofentries': incidentswithmorethan500entries
    }

    if append == 'False':
        demisto.executeCommand('setIncident', analyzeFields)
    else:
        incident = demisto.incidents()
        prevData = incident[0].get('CustomFields', {}).get('healthchecklargeinvestigations')
        prevData.extend(analyzeFields.get("healthchecklargeinvestigations", []))
        demisto.executeCommand('setIncident', analyzeFields)

    action_items = []
    if numberofincidentswithmorethan500entries > int(thresholds['numberofincidentswithmorethan500entries']):
        action_items.append({
            'category': 'DB Analysis',
            'severity': 'High',
            'description': DESCRIPTION[0],
            'resolution': '{}'.format(RESOLUTION[0]),
        })

    if numberofincidentsbiggerthan1mb > thresholds['numberofincidentsbiggerthan1mb']:
        action_items.append({
            'category': 'DB Analysis',
            'severity': 'High',
            'description': DESCRIPTION[1],
            'resolution': '{}\n{}'.format(RESOLUTION[0], RESOLUTION[1]),
        })

    results = CommandResults(
        outputs_prefix='dbstatactionableitems',
        outputs=action_items)

    return results


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    return_results(main(demisto.args()))
