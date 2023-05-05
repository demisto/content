import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import uuid

# Constant to verify the minimum build number and XSIAM version for the new polling command (stopScheduleEntry feature).
MINIMUM_BUILD_NUMBER = 309463
MINIMUM_XSIAM_VERSION = '8.3.0'


# Returns a comma-separated string representation of a list
# Possible inputs: null, int, str, bytes, ["","",...], [int, int], 'a,b,...', '"a","b",...', '["","",...]'
def parseIds(idsArg):
    if idsArg is None:
        return
    if isinstance(idsArg, list):
        return ','.join(map(str, idsArg))
    if isinstance(idsArg, str):
        return ','.join(argToList(idsArg))
    if isinstance(idsArg, bytes):
        return ','.join(argToList(idsArg.decode('utf-8')))
    return str(idsArg)


def main():
    args = demisto.args()
    ids = parseIds(args.get('ids'))
    dt = args.get('dt')
    pollingCommand = args.get('pollingCommand')
    pollingCommandArgName = args.get('pollingCommandArgName')
    tag = args.get('tag')
    playbookId = f' playbookId="{args.get("playbookId", "")}"'
    interval = int(args.get('interval'))
    timeout = int(args.get('timeout'))

    args_names = args.get('additionalPollingCommandArgNames').strip() \
        if args.get('additionalPollingCommandArgNames') else None
    args_values = args.get('additionalPollingCommandArgValues').strip() \
        if args.get('additionalPollingCommandArgValues') else None

    if interval <= 0 or timeout <= 0:
        return_error("Interval and timeout must be positive numbers")

    # Verify correct dt path (does not verify condition!)
    if not demisto.dt(demisto.context(), dt):
        if not demisto.dt(demisto.context(), re.sub('\(.*\)', '', dt)):
            return_error("Incorrect dt path: no ids found")
        demisto.results("Warning: no ids matching the dt condition were found.\nVerify that the condition is correct and "
                        "that all ids have finished running.")
    res_version = demisto.demistoVersion()
    build_number = res_version.get('buildNumber')
    platform = res_version.get('platform')
    command_string = '''!GenericPollingScheduledTask pollingCommand="{0}" pollingCommandArgName="{1}"{2} ids="{3}" \
                        pendingIds="{4}" interval="{5}" timeout="{6}" tag="{7}" additionalPollingCommandArgNames="{8}" \
                        additionalPollingCommandArgValues="{9}"'''.format(pollingCommand, pollingCommandArgName, playbookId,
                                                                          ids.replace('"', r'\"'), dt.replace('"', r'\"'),
                                                                          interval, timeout, tag, args_names, args_values)
    schedule_command_args = {
        'command': command_string,
        'cron': f'*/{interval} * * * *',
        'times': 1
    }
    if build_number != "REPLACE_THIS_WITH_CI_BUILD_NUM" and \
            ((platform == "x2" and is_demisto_version_ge(MINIMUM_XSIAM_VERSION))
             or (platform == "xsoar" and int(build_number) >= MINIMUM_BUILD_NUMBER)):
        entryGuid = str(uuid.uuid4())
        command_string = f'{command_string} scheduledEntryGuid="{entryGuid}"'
        schedule_command_args['command'] = command_string
        schedule_command_args['times'] = timeout // interval
        schedule_command_args['scheduledEntryGuid'] = entryGuid

    res = demisto.executeCommand("ScheduleCommand",
                                 schedule_command_args)
    if isError(res[0]):
        return_error(res)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
