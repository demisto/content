import re

md5Regex = r'\b[a-fA-F\d]{32}\b'

res = []
hashes = []

data = demisto.args()['text']

for m in re.finditer(md5Regex, data, re.I):
    h = m.group(0)
    if h not in hashes:
        hashes.append(h)

res.append('MD5s found:\n' + '\n'.join(hashes))
currHashes = demisto.get(demisto.context(), 'md5s')
if currHashes and isinstance(currHashes, list):
    for h in hashes:
        if h not in currHashes:
            currHashes.append(h)
else:
    currHashes = hashes
demisto.setContext('md5s', currHashes)
demisto.results(res)
