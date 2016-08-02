# Look for various hashes in the incident
# Inspect labels and attachments for hashes and check the hash reputation
import re

strHashRegex = r'\b[a-fA-F\d]{32}\b'

# Iterate on all the labels and find hashes
hashRe = re.compile(strHashRegex, re.I)
hashes = set()
for t in demisto.incidents()[0]['labels']:
    for h in hashRe.finditer(t['value']):
        hashes.add(h.group(0))

# Find hashes in the details
for h in hashRe.finditer(demisto.incidents()[0]['details']):
    hashes.add(h.group(0))


fileNames = []
if 'fileNames' in demisto.args():
    fileNames = demisto.args()['fileNames'].split(',')

# Also get hashes of files in war room entries
entries = demisto.executeCommand('getEntries', {})
for entry in entries:
    if entry['File'] and demisto.get(entry, 'FileMetadata.md5') and (len(fileNames) == 0 or entry['File'] in fileNames):
        hashes.add(demisto.get(entry, 'FileMetadata.md5'))

badHashes = []
res = []
for h in hashes:
    rep = demisto.executeCommand('file', {'file': h})
    for r in rep:
        if positiveFile(r):
            badHashes.append(h)
            res.append(shortFile(r))

if len(res) > 0:
    res.extend(['yes', 'Found malicious hashes!'])
    currHashes = demisto.get(demisto.context(), 'bad_hashes')
    if currHashes and isinstance(currHashes, list):
        currHashes += [h for h in badHashes if h not in currHashes]
    else:
        currHashes = badHashes
    demisto.setContext('bad_hashes', currHashes)
else:
    res.extend(['No suspicious files found', 'no'])

demisto.results(res)
