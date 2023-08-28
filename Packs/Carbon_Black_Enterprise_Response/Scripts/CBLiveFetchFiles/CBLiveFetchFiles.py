import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


res = []
fileLocations = json.loads(demisto.args()['filelocations'])
for md5 in fileLocations:
    res += demisto.executeCommand('CBLiveGetFile_V2', {'path': fileLocations[md5][0], 'endpoint': fileLocations[md5][1]})
demisto.results(res)
