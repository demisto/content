import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
res = demisto.executeCommand("getList", {"listName": "SOP"})[0]['Contents']
res = json.loads(res)
incidentPhase = demisto.incident()['phase']

demisto.results({
    'Type': entryTypes['note'],
    "Contents": res[incidentPhase],
    'ContentsFormat': formats['json'],
    'HumanReadable': res[incidentPhase],
    'ReadableContentsFormat': formats['markdown']
})
