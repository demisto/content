""" AccessData - Await Job Status """

from time import sleep
from traceback import format_exc

from CommonServerPython import *
import demistomock as demisto

""" Main Definition """


def main():
    try:
        res = demisto.executeCommand('accessdata-api-get-job-status', **demisto.args())
        while res["accessdata.case.job.state"] not in ("InProgress", "Submitted"):
            res = demisto.executeCommand('accessdata-api-get-job-status', **demisto.args())
            sleep(10)
        demisto.results(res)
    except Exception as ex:
        demisto.error(format_exc())  # print the traceback
        return_error(f'Failed to execute gather Job Status. Error: {str(ex)}')


""" Entry Point """

main()
