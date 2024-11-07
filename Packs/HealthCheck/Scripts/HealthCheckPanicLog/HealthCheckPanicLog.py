import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
from collections import Counter


def formatToTableStructure(lines):
    table = []
    for line in lines:
        panic = {}
        panic['time'] = line[0]
        panic['panic'] = line[1]
        panic['value'] = line[2]
        table.append(panic)
    return table


def countUniqueLogs(table):
    logArr = []
    for log in table:
        logArr.append("{} {}".format(log['panic'], log['value']))
    countValues = Counter(logArr)
    common_values = countValues.most_common(10)

    commonTable = []
    for log in common_values:

        panic1 = {}
        panic1['panicvalue'] = log[0]
        panic1['numberofoccurrences'] = str(log[1])
        commonTable.append(panic1)
    return commonTable


def findLatestTimestamp(table, commonTable):
    for entry in commonTable:
        for log in reversed(table):
            if entry['panicvalue'] == f"{log['panic']} {log['value']}":
                entry['latestpanictime'] = log['time']
                break

    return commonTable


DESCRIPTION = ['Panic logs were found, it typically means something went unexpectedly wrong']
RESOLUTION = ['Please contact customer support']

args = demisto.args()
entry_id = args.get('entryID')
path = demisto.getFilePath(entry_id)['path']
with open(path, 'rb') as file_:
    fs = file_.read()
panicstr = fs.decode("utf-8")
lines = re.findall(
    r'(?P<time>^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01]).{14})\s(?P<log>.*)\s*(?P<value>[ !\w\/.:()\n@\'\[\]]*)\s',
    panicstr, re.MULTILINE)

table = formatToTableStructure(lines)
commonTable = countUniqueLogs(table)
findLatestTimestamp(table, commonTable)
demisto.executeCommand("setIncident", {"healthcheckpanics": commonTable})

action_items = []
if commonTable:
    action_items.append({
        'category': 'Server',
        'severity': 'High',
        'description': DESCRIPTION[0],
        'resolution': f'{RESOLUTION[0]}',
    })
return_outputs(readable_output=tableToMarkdown("Panic", commonTable, ['panicvalue', 'numberofoccurrences']))
