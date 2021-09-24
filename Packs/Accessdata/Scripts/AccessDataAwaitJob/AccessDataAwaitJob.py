""" AccessData - Await Job Status """

import traceback

import demistomock as demisto

""" Main Definition """

def main():
    try:
        res = demisto.executeCommand('accessdata-api-get-job-status', **demisto.args())
        while res["accessdata.case.job.state"] not in ("InProgress", "Submitted"):
            res = demisto.executeCommand('accessdata-api-get-job-status', **demisto.args())
        demisto.results(res)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute gather Job Status. Error: {str(ex)}')

""" Entry Point """

main()