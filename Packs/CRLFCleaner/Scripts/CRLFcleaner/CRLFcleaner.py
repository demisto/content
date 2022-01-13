import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

emlfile = demisto.args()['EntryID']
EmlFilePath = demisto.getFilePath(emlfile)

with open(EmlFilePath['path'], 'rb') as thisfile:
    newEml = ''
    for line in thisfile.readlines():
        line = line.decode('utf-8', errors='ignore')
        newEml = newEml + (str(line).replace("=\r\n", ""))

context = {
    "CleanEML": newEml
}

command_results = CommandResults(outputs=context)

return_results(command_results)
