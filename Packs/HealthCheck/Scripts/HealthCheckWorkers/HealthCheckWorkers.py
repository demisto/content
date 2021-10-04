import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


DESCRIPTION = '{} busy workers has reached {} of total workers'

RESOLUTION = 'Performance Tuning of Cortex XSOAR Server: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/' \
             'cortex-xsoar-admin/cortex-xsoar-overview/performance-tuning-of-cortex-xsoar-server'


def analyze_data(res):
    workers_thresholds = {
        0.9: 'High',
        0.8: 'Medium',
        0.5: 'Low',
    }
    for threshold, severity in workers_thresholds.items():
        if res['Busy'] > res['Total'] * threshold:
            return [{
                'category': 'Workers analysis',
                'severity': severity,
                'description': DESCRIPTION.format(res['Busy'], threshold),
                'resolution': RESOLUTION[0],
            }]

    return []


def main(args):
    incident = demisto.incident()
    account_name = incident.get('account')
    account_name = f"acc_{account_name}/" if account_name != "" else ""

    is_widget = argToBoolean(args.get('isWidget', True))
    if is_widget is True:
        workers = demisto.executeCommand("demisto-api-get", {"uri": f"{account_name}workers/status"})[0]['Contents']

        if not workers['response']['ProcessInfo']:
            table = [{'Details': '-', 'Duration': '-', 'StartedAt': '-'}]
        else:
            table = workers['response']['ProcessInfo']

        md = tableToMarkdown('Workers Status', table, headers=['Details', 'Duration', 'StartedAt'])

        dmst_entry = {'Type': entryTypes['note'],
                      'Contents': md,
                      'ContentsFormat': formats['markdown'],
                      'HumanReadable': md,
                      'ReadableContentsFormat': formats['markdown'],
                      'EntryContext': {'workers': table}}

        return dmst_entry
    else:
        workers = demisto.executeCommand("demisto-api-get", {"uri": "/workers/status"})[0]['Contents']
        demisto.executeCommand("setIncident", {
            'healthcheckworkerstotal': workers['response']['Total'],
            'healthcheckworkersbusy': workers['response']['Busy']
        })
        add_actions = analyze_data(workers['response'])

        results = CommandResults(
            readable_output="HealthCheckWorkers Done",
            outputs_prefix="HealthCheck.ActionableItems",
            outputs=add_actions)

    return results


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    return_results(main(demisto.args()))
