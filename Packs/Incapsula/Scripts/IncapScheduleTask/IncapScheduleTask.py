import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


res = []
SCHEDULED_TASK_ID_CTXKEY = "ScheduledTaskID"

dArgs = demisto.args()
ssh_server = dArgs.pop("SSHValidationServer")
dArgs['command'] = f'!IncapWhitelistCompliance SSHValidationServer={ssh_server}'

res = demisto.executeCommand('scheduleEntry', dArgs)
if isError(res[0]):
    demisto.results(res)
else:
    taskID = demisto.get(res[0], "Contents.id")
    demisto.setContext(SCHEDULED_TASK_ID_CTXKEY, taskID)
    demisto.results(res)
