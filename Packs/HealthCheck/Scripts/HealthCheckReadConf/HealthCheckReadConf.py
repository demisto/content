import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


multitenant = 'False'
multiRepo = 'False'

res = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})
if res[0]['Type'] == entryTypes['error']:
    demisto.results('File not found')

try:
    with open(res[0]['Contents']['path'], 'r') as file:
        data = file.readlines()

        for line in data:
            if '"ProxyMode": true' in line:
                multitenant = 'True'
            if '"remote": {' in line:
                multiRepo = 'True'
        demisto.executeCommand("setIncident", {
            "xsoarmultitenant": multitenant,
            "xsoarmultirepo": multiRepo,
        })


except ValueError:  # includes simplejson.decoder.JSONDecodeError
    demisto.results('Decoding JSON has failed')
