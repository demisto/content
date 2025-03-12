import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from time import sleep


TIMEOUT = 960
INTERVAL = 10


def detonate_file(args):
    should_continue = True
    file = demisto.get(args, "file")
    feDone = False
    feSubmissionKeys = {}
    # profiles = ['win10x64','win7-sp1','win7x64-sp1','winxp-sp3']
    profiles = argToList(args["profiles"])
    analysistype = args.get("analysistype", 0)
    prefetch = args.get("prefetch", 1)

    # Make sure fireeye available
    if demisto.executeCommand("IsIntegrationAvailable", {"brandname": "fireeye"})[0]["Contents"] != "yes":
        feDone = True

    # Upload file and get submission_key
    if not feDone:
        bArgs = {
            "analysistype": analysistype,
            "application": "0",
            "force": "true",
            "prefetch": prefetch,
            "priority": "1",
            "timeout": "180",
            "upload": file,
        }

        for profile in profiles:
            bArgs["profiles"] = profile
            resp = demisto.executeCommand("fe-submit", bArgs)
            if isError(resp[0]):
                demisto.results(resp)
                should_continue = False
                break
            feSubmissionKey = demisto.get(resp[0], "Contents")
            if isinstance(feSubmissionKey, str):
                feSubmissionKey = json.loads(feSubmissionKey)
            feSubmissionKeys[profile] = demisto.get(feSubmissionKey[0], "ID")
    else:
        demisto.results(
            {"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": "FireEye: Integration not available."}
        )
        should_continue = False
    if should_continue:
        poll_stage(feDone, feSubmissionKeys, profiles, file)


def poll_stage(feDone, feSubmissionKeys, profiles, file):
    should_continue = True
    status = None
    sec = 0
    stauses = {}
    while sec < TIMEOUT and feSubmissionKeys:
        if not feDone:
            status = "Done"
            # Get status
            for profile in profiles:
                resp = demisto.executeCommand("fe-submit-status", {"submission_Key": feSubmissionKeys[profile]})
                if isError(resp[0]):
                    demisto.results(resp)
                    should_continue = False
                    break

                stauses[profile] = demisto.get(resp[0], "Contents.submissionStatus")
                if stauses[profile] in ["In Progress"]:
                    status = "In Progress"
            if not should_continue:
                break
            # find status
            if status in ["In Progress"]:
                sec += INTERVAL
                sleep(INTERVAL)  # pylint: disable=sleep-exists
                # continue loop
            else:
                # loop done failed
                feDone = True
        else:
            break
    if should_continue:
        get_results(feDone, profiles, stauses, feSubmissionKeys, file)


def get_results(feDone, profiles, stauses, feSubmissionKeys, file):
    if not feDone:
        demisto.results(
            {
                "Type": entryTypes["error"],
                "ContentsFormat": formats["text"],
                "Contents": "Could not retrieve results from FireEye (may be due to timeout).",
            }
        )

    for profile in profiles:
        status = stauses[profile]
        if status in ["Done"]:
            resp = demisto.executeCommand("fe-submit-result ", {"submission_Key": feSubmissionKeys[profile]})
            if isError(resp[0]):
                demisto.results(resp)
            else:
                data = demisto.get(resp[0], "Contents.alerts.alert")
                if data:
                    data = data if isinstance(data, list) else [data]
                    data = [{k: formatCell(row[k]).replace("\n", "<br>") for k in row} for row in data]
                    data = tblToMd(profile, data)
                    demisto.results({"ContentsFormat": formats["markdown"], "Type": entryTypes["note"], "Contents": data})
                else:
                    demisto.results("No results.")
        else:
            demisto.results(
                {
                    "Type": entryTypes["error"],
                    "ContentsFormat": formats["text"],
                    "Contents": f"FireEye: Failed to detonate file {file}, exit status = {status}",
                }
            )


def main():  # pragma: no cover
    args = demisto.args()
    try:
        detonate_file(args)
    except Exception as e:
        err_msg = f"Encountered an error while running the script: [{e}]"
        return_error(err_msg, error=e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
