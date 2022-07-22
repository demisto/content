import base64

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Execute command if MISP V2 has an active instance
misp_v2 = False
for instance_name, data in demisto.getModules().items():
    if data.get('brand') == "MISP V2" and data.get('state') == 'active':
        misp_v2 = True
        break
if misp_v2:
    demisto.results(demisto.executeCommand('misp-upload-sample', demisto.args()))
else:
    path = demisto.executeCommand('getFilePath', {'id': demisto.args()['fileEntryID']})
    with open(path[0]['Contents']['path'], 'rb') as f:
        data = f.read()
    encodedFile = base64.b64encode(data)
    args = demisto.args()
    args['filename'] = path[0]['Contents']['name']
    args['fileContent'] = encodedFile

    demisto.results(demisto.executeCommand('internal-misp-upload-sample', args))
