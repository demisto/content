import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import dateutil.relativedelta

THRESHOLDS = {
    'numberofincidentswithmorethan500entries': 300,
    'numberofincidentsbiggerthan10mb': 1,
    'numberofincidentsbiggerthan1mb': 300,
}
DESCRIPTION = [
    'Too many incidents with high number of war room entries were found, consider to use quite mode in task settings',
    'Large incidents were found, consider to use quite mode in task settings and delete context unneeded Context'
]
RESOLUTION = [
    'Playbook Settings: https://xsoar.pan.dev/docs/playbooks/playbook-settings',
    'Extending Context and Ignore Outputs: https://xsoar.pan.dev/docs/playbooks/playbooks-extend-context'
]


def format_dict_keys(data: List[Dict[str, Any]]) -> List:
    formated_data = []
    for entry in data:
        new_entry = {}
        for key, value in entry.items():
            if key == 'Size(MB)':
                new_entry['size'] = f'{value} MB'
            else:
                new_entry[key.lower()] = value

        formated_data.append(new_entry)
    return formated_data


def main(args):
    thresholds = args.get('Thresholds', THRESHOLDS)
    prev_month = datetime.today() + dateutil.relativedelta.relativedelta(months=-1)

    res = execute_command('GetLargestInvestigations', {
        'from': prev_month.strftime('%Y-%m-%d'),
        'to': prev_month.strftime('%Y-%m-%d'),
        'table_result': 'true',
    })

    res_data = format_dict_keys(res['data'])
    incidentsbiggerthan1mb = res_data
    numberofincidentsbiggerthan1mb = res['total']

    incidentsbiggerthan10mb = [incident for incident in res_data if int(incident['size'].split()[0]) > 10]
    numberofincidentsbiggerthan10mb = len(incidentsbiggerthan10mb)

    incidentswithmorethan500entries = [incident for incident in res_data if incident['amountofentries'] > 500]
    numberofincidentswithmorethan500entries = len(incidentswithmorethan500entries)

    analyze_fields = {
        'healthcheckinvestigationsbiggerthan1mb': incidentsbiggerthan1mb,
        'healthcheckinvestigationsbiggerthan10mb': incidentsbiggerthan10mb,
        'healthcheckinvestigationswithmorethan500entries': incidentswithmorethan500entries,
        'healthchecknumberofinvestigationsbiggerthan1mb': numberofincidentsbiggerthan1mb,
        'healthchecknumberofinvestigationsbiggerthan10mb': numberofincidentsbiggerthan10mb,
        'healthchecknumberofinvestigationswithmorethan500entries': numberofincidentswithmorethan500entries,
    }

    execute_command('setIncident', analyze_fields)

    action_items = []
    if numberofincidentswithmorethan500entries > int(thresholds['numberofincidentswithmorethan500entries']):
        action_items.append({
            'category': 'DB Analysis',
            'severity': 'High',
            'description': DESCRIPTION[0],
            'resolution': '{}'.format(RESOLUTION[0]),
        })

    if numberofincidentsbiggerthan10mb > thresholds['numberofincidentsbiggerthan10mb']:
        action_items.append({
            'category': 'DB Analysis',
            'severity': 'High',
            'description': DESCRIPTION[1],
            'resolution': '{} \n{}'.format(RESOLUTION[0], RESOLUTION[1]),
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
