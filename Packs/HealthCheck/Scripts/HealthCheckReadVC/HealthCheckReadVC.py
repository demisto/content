import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


devprod = False
devprodmode = False
ver = False
git = False

res = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})
if res[0]['Type'] == entryTypes['error']:
    demisto.results('File not found')

try:
    with open(res[0]['Contents']['path'], 'r') as file:
        data = file.readlines()

        for line in data:
            result = line.split()
            if ('Remote status: Enabled' in line) or ('Remote: true' in line):
                devprod = True

            if 'Mode:' in line:
                if devprod:
                    demisto.executeCommand("setIncident", {"xsoardevprodmode": result[1]})

            if 'Content mode:' in line:
                if devprod:
                    demisto.executeCommand("setIncident", {"xsoardevprodmode": result[2]})


except ValueError:  # includes simplejson.decoder.JSONDecodeError
    demisto.results('Decoding JSON has failed')

if not devprodmode:
    demisto.executeCommand("setIncident", {"xsoardevprodmode": "False"})

if not devprod:
    demisto.executeCommand("setIncident", {"xsoardevprod": "False"})
    demisto.results('Dev Prod is not enabled')
else:
    try:
        demisto.executeCommand("setIncident", {"xsoardevprod": "True"})

    except ValueError:
        demisto.results('Decoding JSON has failed')
