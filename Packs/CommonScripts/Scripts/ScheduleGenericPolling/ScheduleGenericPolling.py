import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# Returns a comma-separated string representation of a list
# Possible inputs: null, int, str, bytes, ["","",...], [int, int], 'a,b,...', '"a","b",...', '["","",...]'
def parseIds(idsArg):
    if idsArg is None:
        return
    if isinstance(idsArg, list):
        return ','.join(map(lambda item: str(item).encode('utf-8'), idsArg))
    if isinstance(idsArg, str) or isinstance(idsArg, bytes):
        return ','.join(argToList(idsArg.encode('utf-8')))
    return str(idsArg)


args = demisto.args()
ids = parseIds(args['ids'])
dt = args['dt']
pollingCommand = args['pollingCommand']
pollingCommandArgName = args['pollingCommandArgName']
tag = args['tag']
playbookId = ' playbookId="{}"'.format(args['playbookId']) if 'playbookId' in args else ''
interval = int(demisto.get(args, 'interval'))
timeout = int(demisto.get(args, 'timeout'))

args_names = demisto.getArg('additionalPollingCommandArgNames').strip()
args_values = demisto.getArg('additionalPollingCommandArgValues').strip()

if interval <= 0 or timeout <= 0:
    return_error("Interval and timeout must be positive numbers")

# Verify correct dt path (does not verify condition!)
if not demisto.dt(demisto.context(), dt):
    if not demisto.dt(demisto.context(), re.sub('\(.*\)', '', dt)):
        return_error("Incorrect dt path: no ids found")
    demisto.results("Warning: no ids matching the dt condition were found.\nVerify that the condition is correct and "
                    "that all ids have finished running.")
command_string = '''!GenericPollingScheduledTask pollingCommand="{0}" pollingCommandArgName="{1}"{2} ids="{3}" \
                    pendingIds="{4}" interval="{5}" timeout="{6}" tag="{7}" additionalPollingCommandArgNames="{8}" \
                    additionalPollingCommandArgValues="{9}"'''.format(pollingCommand, pollingCommandArgName, playbookId,
                                                                      ids.replace('"', r'\"'), dt.replace('"', r'\"'),
                                                                      interval, timeout, tag, args_names, args_values)
res = demisto.executeCommand("ScheduleCommand",
                             {
                                 'command': command_string,
                                 'cron': '*/{} * * * *'.format(interval),
                                 'times': 1
                             })
if isError(res[0]):
    return_error(res)
