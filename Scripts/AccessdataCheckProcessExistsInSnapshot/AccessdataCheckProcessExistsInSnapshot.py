import demistomock as demisto
from CommonServerPython import *
# encoding=utf8
import sys
reload(sys)
sys.setdefaultencoding('utf8')

# Constant and mandatory arguments
file_path = demisto.get(demisto.context(), 'Accessdata.Job.Result.SnapshotDetails.File')
res = demisto.executeCommand('accessdata-read-casefile', {"filepath": file_path})
data = demisto.get(res[0], 'Contents')
converted = json.loads(xml2json(data))


process_list = [process['Name'] for process in converted['root']['Process']]

value = "No"
if demisto.args()['process'] in process_list:
    value = "Yes"
proc = {
    'Name': demisto.args()['process'],
    'Exists': value
}

demisto.results({
    'Type': entryTypes['note'],
    'ContentsFormat': formats['json'],
    'Contents': proc,
    'HumanReadable': 'Process "' + proc['Name'] + '" exists: ' + proc['Exists'],
    'EntryContext': {'Accessdata.Process(val && val.Name == obj.Name)': proc}
})
