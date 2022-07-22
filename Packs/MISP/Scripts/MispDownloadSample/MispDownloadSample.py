import base64

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Executing command if MISP V2 has an active instance
misp_v2 = False
for instance_name, data in demisto.getModules().items():
    if data.get('brand') == 'MISP V2' and data.get('state') == 'active':
        misp_v2 = True
        break

if misp_v2:
    demisto.results(demisto.executeCommand('misp-download-sample', demisto.args()))
else:
    if not get_hash_type(demisto.args().get('hash')) == 'Unknown':
        res = demisto.executeCommand('internal-misp-download-sample', demisto.args())
        if 'message' in res[0]['Contents'] and res[0]['Contents']['message'] == 'No hits with the given parameters.':
            demisto.results(res[0]['Contents']['message'])
        else:
            filename = res[0]['Contents']['result'][0]['filename']
            fileContent = base64.b64decode(res[0]['Contents']['result'][0]['base64'])
            demisto.results(fileResult(filename, fileContent))
    else:
        return_error('Hash length is invalid.')
