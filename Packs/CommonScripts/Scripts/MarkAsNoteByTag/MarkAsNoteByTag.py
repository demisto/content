import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

entries = demisto.executeCommand('getEntries', {})
if isError(entries[0]):
    demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'], 'Contents': 'Unable to retrieve entries'})
else:
    ids = ''
    for e in entries:
        tags = e.get('Metadata', {}).get('tags')
        if not tags:
            tags = []
        if demisto.getArg('tag') in tags:
            if ids == '':
                ids = e['Metadata']['id']
            else:
                ids += ',' + e['Metadata']['id']
    if ids != '':
        demisto.results(demisto.executeCommand('markAsNote', {'entryIDs': ids}))
    else:
        demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                         'Contents': "No entries with '" + demisto.getArg('tag') + "' found"})
