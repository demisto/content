import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

uuid = demisto.args().get('uuid')
next_run = int(demisto.args().get('timebetweenruns'))
timeout = int(demisto.args().get('timeout'))
action_status = demisto.executeCommand("xsoar-ws-get-action-status", {"uuid": uuid})[0]['Contents']

if not action_status["response_received"]:
    demisto.log("no response")
    scheduled_command = ScheduledCommand(command="xsoar-ws-poll-status", next_run_in_seconds=next_run,
                                         args={'uuid': uuid, 'timebetweenruns': next_run, 'timeout': timeout},
                                         timeout_in_seconds=timeout)
    toreturn = CommandResults(outputs_prefix='WS-ActionStatus(val.uuid==obj.uuid)',
                              outputs=action_status, scheduled_command=scheduled_command)
else:
    toreturn = CommandResults(outputs_prefix='WS-ActionStatus(val.uuid==obj.uuid)', outputs=action_status)

return_results(toreturn)
