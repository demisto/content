import json
import random
import re
import string
from datetime import datetime, timedelta

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# Returns a comma-separated string representation of a list
# Possible inputs: null, int, str, bytes, ["","",...], [int, int], 'a,b,...', '"a","b",...', '["","",...]'


def parseIds(idsArg):
    if idsArg is None:
        return
    if isinstance(idsArg, list):
        if len(idsArg) == 0 or isinstance(idsArg[0], str):
            return idsArg
        return ','.join(map(str, idsArg))
    if isinstance(idsArg, str) or isinstance(idsArg, bytes):
        return ','.join(argToList(idsArg))
    return str(idsArg)


args = demisto.args()
ids = parseIds(args['ids'].encode('utf-8'))
dt = args['dt']
pollingCommand = args['pollingCommand']
pollingCommandArgName = args['pollingCommandArgName']
tag = args['tag']
playbookId = ' playbookId="{}"'.format(args['playbookId']) if 'playbookId' in args else ''
interval = int(demisto.get(args, 'interval'))
timeout = int(demisto.get(args, 'timeout'))

additionalPollingCommandArgNames = demisto.getArg('additionalPollingCommandArgNames')
additionalPollingCommandArgNames = demisto.getArg('additionalPollingCommandArgValues')
args_names = [name.strip() for name in argToList(additionalPollingCommandArgNames)]
args_values = [value.strip() for value in argToList(additionalPollingCommandArgNames)]

if interval <= 0 or timeout <= 0:
    demisto.results({
        'Type': entryTypes['error'],
        'ContensFormat': formats['text'],
        'Contents': "Interval and timeout must be positive numbers"
    })
    sys.exit(2)

# Verify correct dt path (does not verify condition!)
if not demisto.dt(demisto.context(), dt):
    if not demisto.dt(demisto.context(), re.sub('\(.*\)', '', dt)):
        return_error("Incorrect dt path: no ids found")
    demisto.results(
        "Warning: no ids matching the dt condition were found.\nVerify that the condition is correct and that all ids have finished running.")

res = demisto.executeCommand("ScheduleCommand", {
    'command': '''!GenericPollingScheduledTask pollingCommand="%s" pollingCommandArgName="%s"%s ids="%s" pendingIds="%s" interval="%s" timeout="%s" tag="%s"
                additionalPollingCommandArgNames="%s" additionalPollingCommandArgValues="%s"'''
               % (pollingCommand, pollingCommandArgName, playbookId, ids.replace('"', r'\"'), dt.replace('"', r'\"'),
                  interval, timeout, tag, args_names, args_values),
    'cron': '*/{} * * * *'.format(interval),
    'times': 1
})
if isError(res[0]):
    demisto.results(res)
    sys.exit(1)
