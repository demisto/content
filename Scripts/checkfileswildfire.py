import time

fileNames = []
if 'fileNames' in demisto.args():
    fileNames = demisto.args()['fileNames'].split(',')

res = []
uploaded = []
entries = demisto.executeCommand('getEntries', {})
for entry in entries:
    if entry['File'] and demisto.get(entry, 'FileMetadata.md5') and (len(fileNames) == 0 or entry['File'] in fileNames):
        demisto.log('Checking - ' + demisto.get(entry, 'FileMetadata.md5'))
        rep = demisto.executeCommand('wildfire-report', {'md5': demisto.get(entry, 'FileMetadata.md5')})
        for r in rep:
            if positiveFile(r):
                res.append(shortFile(r))
            elif r['Type'] == entryTypes['error'] and '404' in r['Contents']:
                upReply = demisto.executeCommand('wildfire-upload', {'upload': entry['ID']})
                if upReply[0]['Type'] != entryTypes['error']:
                    uploaded.append(demisto.get(entry, 'FileMetadata.md5'))

# Wait for the uploaded files to be processed - 15 min
if len(uploaded) > 0:
    time.sleep(15 * 60)

for u in uploaded:
    rep = demisto.executeCommand('wildfire-report', {'md5': u})
    notFound = False
    for r in rep:
        if positiveFile(r):
            res.append(shortFile(r))

if len(res) > 0:
    res.append('yes')
else:
    res.extend(['No suspicious files found', 'no'])
demisto.results(res)
