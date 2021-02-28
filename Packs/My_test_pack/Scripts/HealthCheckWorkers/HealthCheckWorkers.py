import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def analyzeData(res):
    addActions = []
    if res['Busy'] > res['Total'] * 0.9:
        addActions.append({'category': 'Workers analysis', 'severity': 'High',
                           'description': f"{res['busy']} buse workers has reached 90% of total workers"})

    if res['Busy'] > res['Total'] * 0.8:
        addActions.append({'category': 'Workers analysis', 'severity': 'Medium',
                           'description': f"{res['busy']} buse workers has reached 80% of total workers"})

    if res['Busy'] > res['Total'] * 0.5:
        addActions.append({'category': 'Workers analysis', 'severity': 'Low',
                           'description': f"{res['busy']} buse workers has reached 50% of total workers"})
    return addActions


args = demisto.args()
isWidget = argToBoolean(args.get('isWidget', True))
if isWidget == True:
    workers = demisto.executeCommand("demisto-api-get", {"uri": "/workers/status"})[0]['Contents']
    table = []

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

    demisto.results(dmst_entry)
else:
    workers = demisto.executeCommand("demisto-api-get", {"uri": "/workers/status"})[0]['Contents']
    addActions = analyzeData(workers['response'])

    results = CommandResults(
        readable_output="HealthCheckWorkers Done",
        outputs_prefix="actionableitems",
        outputs=addActions)

    return_results(results)
