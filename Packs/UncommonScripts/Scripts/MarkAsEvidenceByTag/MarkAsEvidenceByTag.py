import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

entries = demisto.executeCommand('getEntries', {})
if isError(entries[0]):
    demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'], 'Contents': 'Unable to retrieve entries'})
else:
    ids = []
    for e in entries:
        tags = e.get('Metadata', {}).get('tags')
        if not tags:
            tags = []
        if demisto.getArg('tag') in tags:
            ids.append(e['Metadata']['id'])
    if len(ids) > 0:
        for i in ids:
            demisto.results(demisto.executeCommand("markAsEvidence", {"id": i, "description": demisto.getArg('description')}))
    else:
        demisto.results({'Type': entryTypes['note'], 'ContentsFormat': formats['text'],
                         'Contents': "No entries with '" + demisto.getArg('tag') + "' found"})
