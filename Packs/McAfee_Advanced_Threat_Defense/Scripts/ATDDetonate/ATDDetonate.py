import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from time import sleep


def main():

    dArgs = demisto.args()

    timeout = 960
    if 'timeout' in demisto.args():
        timeout = int(demisto.args()['timeout'])
    interval = 10
    if 'interval' in demisto.args():
        interval = int(demisto.args()['interval'])

    taskID = ""

    # Upload file/url and get taskID
    resp = demisto.executeCommand('atd-file-upload', dArgs)
    if isError(resp[0]):
        demisto.results(resp)
        sys.exit(0)
    else:
        upload_res = demisto.get(resp[0], 'Contents.results')
        if upload_res and isinstance(upload_res, list):
            taskID = demisto.get(upload_res[0], 'taskId')
        else:
            demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                            "Contents": "Coudn't extract TaskID from upload"})
            sys.exit(0)

    if taskID == "-1":
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": "File type not "
                                                                                                     "supported"})
        sys.exit(0)

    # Poll stage ############
    status = None
    istate = None
    sec = 0

    atdDone = False
    while sec < timeout and not atdDone:
        # Get status
        resp = demisto.executeCommand('atd-check-status', {'taskId': taskID})
        if isError(resp[0]):
            demisto.results(resp)
            sys.exit(0)

        status = demisto.get(resp[0], 'Contents.results.status')
        istate = demisto.get(resp[0], 'Contents.results.istate')

        # find status
        if istate and int(istate) in [1, 2]:
            atdDone = True
        # continue loop
        else:
            sec += interval
            sleep(interval)  # pylint: disable=sleep-exists
    # Get results ############
    if not atdDone:
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                        "Contents":
                            f'Could not retrieve results from ATD (may be due to timeout). last status = {status}'})
        sys.exit(0)
    if istate and int(istate) in [1, 2]:
        reportType = 'json'
        if demisto.get(demisto.args(), 'reportType'):
            reportType = demisto.args()['reportType']
        demisto.results(demisto.executeCommand('atd-get-report', {'taskId': taskID, 'type': reportType}))
    else:
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                        "Contents": f'ATD: Failed to detonate source, exit status = {status}'})


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
