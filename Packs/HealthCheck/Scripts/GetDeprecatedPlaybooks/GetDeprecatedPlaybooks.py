import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

payload = {'query': 'deprecated:T'}
res = demisto.executeCommand("core-api-post", {"uri": "playbook/search", "body": json.dumps(payload)})[0]["Contents"]["response"]

if not res['playbooks']:
    res['playbooks'] = []

wList = []
for item in res['playbooks']:
    wList.append({'Name': item['name']})

md = tableToMarkdown('List of Deprecated Playbooks', wList)
return_results({
    'Contents': wList,
    'ContentsFormat': formats['text'],
    'HumanReadable': md,
    'EntryContext': {'DeprecatedPlaybooks': [wList]}
})
