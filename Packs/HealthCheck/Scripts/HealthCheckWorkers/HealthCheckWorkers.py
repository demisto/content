import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


DESCRIPTION = [
    "{res['busy']} busy workers has reached 90% of total workers",
    "{res['busy']} busy workers has reached 80% of total workers",
    "{res['busy']} busy workers has reached 50% of total workers"
]

RESOLUTION = ["Performance Tuning of Cortex XSOAR Server: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
              "cortex-xsoar-admin/cortex-xsoar-overview/performance-tuning-of-cortex-xsoar-server"]


def analyzeData(res):
    addActions = []
    if res['Busy'] > res['Total'] * 0.9:
        addActions.append({'category': 'Workers analysis', 'severity': 'High',
                           'description': DESCRIPTION[0], 'resolution': f"{RESOLUTION[0]}"})

    elif res['Busy'] > res['Total'] * 0.8:
        addActions.append({'category': 'Workers analysis', 'severity': 'Medium',
                           'description': DESCRIPTION[1], 'resolution': f"{RESOLUTION[0]}"})

    elif res['Busy'] > res['Total'] * 0.5:
        addActions.append({'category': 'Workers analysis', 'severity': 'Low',
                           'description': DESCRIPTION[2], 'resolution': f"{RESOLUTION[0]}"})
    return addActions


args = demisto.args()
isWidget = argToBoolean(args.get('isWidget', True))
if isWidget is True:
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
    demisto.executeCommand("setIncident", {
        'workerstotal': workers['response']['Total'],
        'workersbusy': workers['response']['Busy']
    })
    addActions = analyzeData(workers['response'])

    results = CommandResults(
        readable_output="HealthCheckWorkers Done",
        outputs_prefix="actionableitems",
        outputs=addActions)

    return_results(results)
