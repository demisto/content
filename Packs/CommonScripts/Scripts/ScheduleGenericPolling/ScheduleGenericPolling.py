import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import uuid

# Constant to verify the minimum build number and version for the new polling feature (stopScheduleEntry feature).
# MINIMUM_XSIAM_VERSION = '8.3.0'
# MINIMUM_BUILD_NUMBER_XSIAM = 313276
MINIMUM_XSOAR_VERSION = '8.2.0'
MINIMUM_BUILD_NUMBER_XSOAR = 309463


# Returns a comma-separated string representation of a list
# Possible inputs: null, int, str, bytes, ["","",...], [int, int], 'a,b,...', '"a","b",...', '["","",...]'
def parseIds(idsArg):
    if idsArg is None:
        return None
    if isinstance(idsArg, list):
        return ','.join(map(str, idsArg))
    if isinstance(idsArg, str):
        return ','.join(argToList(idsArg))
    if isinstance(idsArg, bytes):
        return ','.join(argToList(idsArg.decode('utf-8')))
    return str(idsArg)


def should_run_with_guid():
    """
    The function verifies that the server has the right version in order to support
     the stopScheduleEntry command and the add-on of the GUID to the Schedule command.
    """
    res_version = demisto.demistoVersion()
    build_number = res_version.get('buildNumber')
    platform = res_version.get('platform')

    # conditions to add when the feature is supported in XSIAM:
    # (platform == "x2" and is_demisto_version_ge(MINIMUM_XSIAM_VERSION) and int(
    #     build_number) >= MINIMUM_BUILD_NUMBER_XSIAM)
    # The try/except mechanism is to support development and to ignore cast errors.
    try:
        return (platform == "xsoar" and is_demisto_version_ge(MINIMUM_XSOAR_VERSION) and int(
            build_number) >= MINIMUM_BUILD_NUMBER_XSOAR)
    except ValueError:
        return False


def calculate_end_time(timeout):
    now = get_current_time()
    end_time = now + timedelta(minutes=timeout)
    short_format = "%Y-%m-%d %H:%M:%S"
    return end_time.strftime(short_format)


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
            demisto.debug(f"Could not find the dt path: {dt} in the context: {demisto.context()}")
            return_error(f"Incorrect dt path {dt}: no ids found in the context: {demisto.context()}")
        demisto.results("Warning: no ids matching the dt condition were found.\nVerify that the condition is correct and "
                        "that all ids have finished running.")

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
    if should_run_with_guid():
        # Generate a GUID for the scheduled entry and add it to the command.
        entryGuid = str(uuid.uuid4())
        command_string = f'{command_string} scheduledEntryGuid="{entryGuid}" endTime="{calculate_end_time(timeout)}"'
        schedule_command_args['command'] = command_string
        # Set the times to be the number of times the polling command should run (using the cron job functionally).
        # Adding extra iteration to verify that the polling command will stop the schedule entry.
        schedule_command_args['times'] = (timeout // interval) + 1
        schedule_command_args['scheduledEntryGuid'] = entryGuid

    res = demisto.executeCommand("ScheduleCommand",
                                 schedule_command_args)
    if isError(res[0]):
        return_error(res)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
