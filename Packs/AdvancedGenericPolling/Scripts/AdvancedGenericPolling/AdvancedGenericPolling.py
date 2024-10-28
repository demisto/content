import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# get the args
args = demisto.args()

# declare vars...
other_args_list = []
other_values_list = []
reopen_task_list = []
isIncidentField = False
inc = {}
script_results = []
cmd_args = {}

# assign args to variables
inc_id = args.get('Ids', False)
cmd = args.get('PollingCommandName')
cmd_arg_name = args.get('PollingCommandArgName', False)
looper_task_id = args.get('looper_task_id', False)
reopen_task_id = args.get('reopen_task_id', False)
schedule_timeout = args.get('schedule_timeout', 600)
schedule_next_run = args.get('schedule_next_run', 60)
other_args = args.get('AdditionalPollingCommandArgNames', False)
other_values = args.get('AdditionalPollingCommandArgValues', False)
dt_string = args.get('dt', False)

# if there is a incident. prefix then look in the incident key
if 'incident.' in dt_string:
    isIncidentField = True

    # get the incident data
    inc['incident'] = demisto.incidents()[0]

if other_args:
    if ',' in other_args:
        other_args_list = other_args.split(',')
    else:
        other_args_list.append(other_args)
if other_values:
    if ',' in other_values:
        other_values_list = other_values.split(',')
    else:
        other_values_list.append(other_values)

if len(other_args_list) != len(other_values_list):
    demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                    "Contents": "other_args and other_values do not match"})


if other_args and other_values:
    cmd_args = {other_args_list[i]: other_values_list[i] for i in range(len(other_args_list))}
if inc_id is not False and cmd_arg_name is not False:
    cmd_args[cmd_arg_name] = inc_id

inc_result = demisto.executeCommand(cmd, cmd_args)

if inc_result and not isError(inc_result[0]):
    dt_res = demisto.dt(demisto.context(), dt_string)
    if 'incident.' in dt_string:
        dt_res = demisto.dt(inc, dt_string)
    if dt_res is not None:
        schedule_command = 'AdvancedGenericPolling'
        scheduled_command = ScheduledCommand(
            command=schedule_command,
            next_run_in_seconds=int(schedule_next_run),
            args=args,
            timeout_in_seconds=int(schedule_timeout)
        )
        readable_output = "AdvancedGenericPolling running polling command..."
        script_results.append(CommandResults(
            readable_output=readable_output,
            scheduled_command=scheduled_command
        ))
    else:
        readable_output = "AdvancedGenericPolling polling is done, see result below."
        script_results.append(CommandResults(readable_output=readable_output))
    script_results.extend(inc_result)

if reopen_task_id:
    if ',' in reopen_task_id:
        reopen_task_list = reopen_task_id.split(',')
        for reopen_task in other_args_list:
            demisto.executeCommand("taskReopen", {"id": reopen_task})
    else:
        demisto.executeCommand("taskReopen", {"id": reopen_task_id})

if looper_task_id:
    demisto.executeCommand("taskReopen", {"id": looper_task_id})
    demisto.executeCommand("taskComplete", {"id": looper_task_id, "isAutoRun": True})

return_results(script_results)
