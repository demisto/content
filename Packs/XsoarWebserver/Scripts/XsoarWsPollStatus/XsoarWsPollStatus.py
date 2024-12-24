import demistomock as demisto
from CommonServerPython import *


uuid = demisto.args().get('uuid')
next_run = int(demisto.args().get('timebetweenruns'))
timeout = 259200
job_status = demisto.executeCommand("xsoar-ws-get-action-status", {"uuid": uuid})[0]['Contents']


def parse_job_status():
    link_tracker = job_status["link_tracker"]
    complete = False
    for link in link_tracker:
        if link["response_received"]:
            complete = True
        else:
            complete = False
            break

    if not complete:
        scheduled_command = ScheduledCommand(command="xsoar-ws-poll-status", next_run_in_seconds=next_run,
                                             args={'uuid': uuid, 'timebetweenruns': next_run, 'timeout': timeout},
                                             timeout_in_seconds=timeout)
        toreturn = CommandResults(outputs_prefix='WS-ActionStatus(val.job_uuid==obj.job_uuid)',
                                  readable_output="Waiting for Job to complete, polling job",
                                  outputs=job_status, scheduled_command=scheduled_command)
    else:
        demisto.executeCommand("xsoar-ws-set-job-complete", {"uuid": uuid})
        job_status["completed"] = True
        toreturn = CommandResults(outputs_prefix='WS-ActionStatus(val.job_uuid==obj.job_uuid)',
                                  readable_output="All responses received, stopped polling", outputs=job_status)
    return toreturn


if type(job_status) is not dict:
    toreturn = CommandResults()
    return_error(job_status)
elif job_status["completed"]:
    toreturn = CommandResults(outputs_prefix='WS-ActionStatus(val.job_uuid==obj.job_uuid)',
                              readable_output="Job has been set to complete, not polling", outputs=job_status)
else:
    toreturn = parse_job_status()


return_results(toreturn)
