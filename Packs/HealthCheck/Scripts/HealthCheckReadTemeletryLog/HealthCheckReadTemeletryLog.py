import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


res = demisto.executeCommand('getFilePath', {'id': demisto.args().get('entryID')})
if res[0]['Type'] == entryTypes['error']:
    demisto.executeCommand("setIncident", {'xsoartelemetrystatus': 'Not Enabled'})
    demisto.results('File not found')
else:
    try:
        with open(res[0]['Contents']['path'], 'r') as file:

            if 'notelemetry' in file.read():
                demisto.executeCommand("setIncident", {'xsoartelemetrystatus': 'Not Enabled'})
            else:
                demisto.executeCommand("setIncident", {'xsoartelemetrystatus': 'Enabled'})

    except ValueError:
        demisto.results('Unable to read file.')
