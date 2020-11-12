import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

try:
    maxFileSize = int(demisto.args().get('maxFileSize'))
except Exception:
    maxFileSize = 1024 ** 2

res = demisto.executeCommand('getFilePath', {
    'id': demisto.args()['entryID']
})

try:
    filePath = res[0]['Contents']['path']
except Exception:
    return_error("File was not found")

with open(filePath, mode='r') as f:
    data = f.read(maxFileSize)
    try:
        data = data.decode('unicode_escape').encode('utf-8')
    # unicode_escape might throw UnicodeDecodeError for strings that contain \ char followed by ascii characters
    except UnicodeDecodeError:
        data = data.decode('iso-8859-1').encode('utf-8')

    # Extract indicators (omitting context output, letting auto-extract work)
    indicators_hr = demisto.executeCommand("extractIndicators", {
        'text': data})[0][u'Contents']
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': indicators_hr,
        'HumanReadable': indicators_hr
    })
