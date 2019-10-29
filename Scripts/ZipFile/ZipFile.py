import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import zipfile
from os.path import isfile
import pyminizip
import shutil

try:  # in order to support compression of the file
    compression = zipfile.ZIP_DEFLATED

except Exception:
    compression = zipfile.ZIP_STORED

filePath = None
fileEntryID = ''
zipName = None
password = None
fileEntryID = demisto.args().get('entryID')
if 'zipName' in demisto.args().keys():
    zipName = demisto.args().get('zipName') + '.zip'

if 'password' in demisto.args().keys():
    password = demisto.args().get('password')

if not fileEntryID:
    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': 'You must set an entryID when using the zip script'
    })
    sys.exit(0)

res = demisto.executeCommand('getFilePath', {'id': fileEntryID})

if res[0]['Type'] == entryTypes['error']:
    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': 'Failed to get the file path for entry: ' + fileEntryID + ' the error message was '
                    + res[0]['Contents']
    })
    sys.exit(0)

filePath = res[0]['Contents']['path']
fileCurrentName = res[0]['Contents']['name']

if not zipName:
    zipName = fileCurrentName + '.zip'

if not isfile(filePath):  # in case that the user will send a directory
    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': fileEntryID + 'is not a file. Please recheck your input.'
    })
    sys.exit(0)

# copying the file to current location
shutil.copy(filePath, fileCurrentName)
# zipping the file
if password:
    pyminizip.compress(fileCurrentName, zipName, password, 5)

else:
    zf = zipfile.ZipFile(zipName, mode='w')
    try:
        zf.write(fileCurrentName, compress_type=compression)
        # testing for file integrity
        ret = zf.testzip()
        if ret is not None:
            demisto.results({
                'Type': entryTypes['error'],
                'ContentsFormat': formats['text'],
                'Contents': 'There was a problem with the zipping, file: ' + ret + 'is corrupted'
            })
            sys.exit(0)

    finally:
        zf.close()

with open(zipName, 'rb') as f:
    file_data = f.read()

demisto.results(fileResult(zipName, file_data))
results = [
    {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': {'ZippedFiles': zipName},
        'EntryContext': {
            'ZippedFiles': zipName,
            'File(val.EntryID=="' + fileEntryID + '").zipped': True
        },
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Zipped Files', [{'original name': fileCurrentName, 'zipped file': zipName}])
    }]

demisto.results(results)
