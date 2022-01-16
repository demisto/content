import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
from collections import Counter


args = demisto.args()
entry_id = args.get('entryID')
path = demisto.getFilePath(entry_id)['path']
with open(path, 'rb') as file_:
    fs = file_.read()
panicstr = fs.decode("utf-8")
lines = re.findall(
    r'(?P<time>^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01]).{14})\s(?P<log>.*)\s*(?P<value>[ !\w\/.:()\n@\'\[\]]*)\s', panicstr, re.MULTILINE)


table = []
print("Number of panics: {}".format(len(lines)))
for line in lines:
    panic = {}
    panic['time'] = line[0]
    panic['panic'] = line[1]
    panic['value'] = line[2]
    table.append(panic)


logArr = []
for log in table:
    logArr.append("{} {}".format(log['panic'], log['value']))


countValues = Counter(logArr)
common_values = countValues.most_common(3)
commonTable = []

for log in common_values:
    # print(log)
    panic1 = {}
    panic1['PanicValue'] = log[0]
    panic1['occurness'] = log[1]
    commonTable.append(panic1)
return_outputs(readable_output=tableToMarkdown("Panic", commonTable, ['PanicValue', 'occurness']))
