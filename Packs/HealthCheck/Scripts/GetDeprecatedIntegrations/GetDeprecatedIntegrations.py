import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand("core-api-get", {"uri": "contentpacks/installed-expired"})[0]["Contents"]["response"]

wList = []
for item in res:
    if item['deprecated'] is True:
        wList.append({'Name': item['name']})
    if item['integrations']:
        if len(item['integrations']) > 0:
            for val in item['integrations']:
                if 'Deprecated' in val['name']:
                    wList.append({'Name': val['name']})

md = tableToMarkdown('List of Deprecated Integrations', wList)
return_results({
    'Contents': wList,
    'ContentsFormat': formats['text'],
    'HumanReadable': md,
    'EntryContext': {'DeprecatedContentPacks': [wList]}
})
