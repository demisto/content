import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


# Constant and mandatory arguments
args = demisto.args()
process_name = args['process']
file_path = args['filepath']

proc = {
    'Name': process_name,
    'Exists': "No"
}

error = None
try:
    res = demisto.executeCommand('accessdata-read-casefile', {"filepath": file_path})
    data = demisto.get(res[0], 'Contents')
    converted = json.loads(xml2json(data.encode("utf-8")))
except Exception as ex:
    error = str(ex)

if (not converted is None) and ('root' in converted) and ('Process' in converted['root']):
    process_list = [process['Name'] for process in converted['root']['Process']]

    if process_name in process_list:
        proc['Exists'] = "Yes"

humanReadable = 'Process "' + proc['Name'] + '" exists: ' + proc['Exists']
if not error is None:
    humanReadable = humanReadable + " Error: {}".format(error)

demisto.results({
    'Type': entryTypes['note'],
    'ContentsFormat': formats['json'],
    'Contents': proc,
    'HumanReadable': humanReadable,
    'EntryContext': {'Accessdata.Process(val && val.Name == obj.Name)': proc}
})
