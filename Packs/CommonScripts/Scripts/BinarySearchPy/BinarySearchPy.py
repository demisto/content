# Look for various hashes in the incident
# Inspect labels and attachments for hashes and check if we have this process running anywhere using Carbon Black
import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Iterate on all the labels and see which one has hashes
hashRe = re.compile(r'\b[a-fA-F\d]{32}\b', re.I)
hashes = set()
for t in demisto.incidents()[0]['labels']:
    for h in hashRe.finditer(t['value']):
        hashes.add(h.group(0))
# Find hashes in the details
for h in hashRe.finditer(demisto.incidents()[0]['details']):
    hashes.add(h.group(0))
# Get also hashes from files in entries
entries = demisto.executeCommand('getEntries', {})
for entry in entries:
    if entry['File'] and demisto.get(entry, 'FileMetadata.md5'):
        hashes.add(demisto.get(entry, 'FileMetadata.md5'))
res = []
for h in hashes:
    processes = demisto.executeCommand('cb-process', {'query': 'md5:' + h})
    if len(processes) > 0 and processes[0]['Type'] == entryTypes['note'] and processes[0]['ContentsFormat'] == formats['json']:
        process = demisto.get(processes[0], 'Contents.results')
        if process:
            res.append({
                '1. MD5': h,
                '2. Name': demisto.get(process, 'process_name'),
                '3. Hostname': demisto.get(process, 'hostname'),
                '4. Path': demisto.get(process, 'path'),
                '5. Updated': demisto.get(process, 'last_update'),
                '6. Terminated': demisto.get(process, 'terminated')})
if len(res) > 0:
    demisto.results(['yes', {'Type': entryTypes['note'], 'ContentsFormat': formats['table'], 'Contents': res}])
else:
    demisto.results(['no', {'Type': entryTypes['note'], 'ContentsFormat': formats['text'],
                    'Contents': 'No process hashes found'}])
