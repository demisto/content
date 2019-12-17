import demistomock as demisto
from CommonServerPython import *
import os

entries = demisto.executeCommand('getEntries', {'filter': {'categories': ['attachments']}})
ec = []
for e in entries:
    if e.get('File') and e.get('FileMetadata'):
        name, ext = os.path.splitext(e['File'])
        ec.append({
            'Name': e['File'],
            'MD5': e['FileMetadata'].get('md5'),
            'SHA1': e['FileMetadata'].get('sha1'),
            'SHA256': e['FileMetadata'].get('sha256'),
            'SSDeep': e['FileMetadata'].get('ssdeep'),
            'Size': e['FileMetadata'].get('size'),
            'Info': e['FileMetadata'].get('info'),
            'Type': e['FileMetadata'].get('type'),
            'Extension': ext[1:] if ext else '',
            'EntryID': e['ID']
        })
demisto.results({
    'Type': entryTypes['note'],
    'ContentsFormat': formats['json'],
    'Contents': ec,
    'EntryContext': {outputPaths['file']: ec},
    'HumanReadable': 'Done'
})
