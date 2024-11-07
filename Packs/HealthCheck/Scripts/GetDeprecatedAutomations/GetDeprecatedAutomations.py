import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

payload = {'query': 'deprecated:T'}
res = demisto.executeCommand("core-api-post", {"uri": "automation/search",
                             "body": json.dumps(payload)})[0]["Contents"]["response"]

if not res['scripts']:
    res['scripts'] = []

wList = []
for item in res['scripts']:
    wList.append({'Name': item['name']})

md = tableToMarkdown('List of Deprecated Automations', wList)
return_results({
    'Contents': wList,
    'ContentsFormat': formats['text'],
    'HumanReadable': md,
    'EntryContext': {'DeprecatedAutomations': [wList]}
})
