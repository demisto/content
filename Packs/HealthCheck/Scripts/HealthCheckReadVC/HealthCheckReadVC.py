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
            result = re.findall("\w+", line)
            if ('Remote status: Enabled' in line) or ('Remote: true' in line):
                devprod = True

            if 'Mode:' in line:
                if devprod:
                    demisto.executeCommand("setIncident", {"devprodmode": result[1]})

            if 'Content mode:' in line:
                if devprod:
                    demisto.executeCommand("setIncident", {"devprodmode": result[2]})


except ValueError:  # includes simplejson.decoder.JSONDecodeError
    demisto.results('Decoding JSON has failed')

if not devprodmode:
    demisto.executeCommand("setIncident", {"devprodmode": "False"})

if not (devprod):
    demisto.executeCommand("setIncident", {"devprod": "False"})
    demisto.results('Dev Prod is not enabled')
else:
    try:
        demisto.executeCommand("setIncident", {"devprod": "True"})
        with open(res[0]['Contents']['path'], 'r') as file:
            data = file.readlines()
            for line in data:
                result = re.findall("\w+", line)

                if ('Version:' in line):
                    result = re.findall("\d.*", line)[0]
                    demisto.executeCommand("setIncident", {"devprodgit": result})
                    git = True

                if ver is True and git is False:
                    demisto.executeCommand("setIncident", {"devprodgit": line[:-1]})
                    ver = False
                if ('Git version:' in line) or ('Version:' in line):
                    ver = True

    except ValueError:
        demisto.results('Decoding JSON has failed')
