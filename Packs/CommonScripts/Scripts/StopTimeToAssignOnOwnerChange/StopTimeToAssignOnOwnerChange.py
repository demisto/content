import demistomock as demisto
from CommonServerPython import *  # noqa: F401


# ##### Help #####
# This is an example script. The script is used to stop the Time to Assignment SLA field,
# once an owner was set to an incident. If you want to use this script, you should go to
# the Owner field, and set this script as the script to run upon change of field value.


def main():
    args = demisto.args()
    try:
        if not args.get('old') and args.get('new'):  # If owner was no-one and is now someone:
            demisto.executeCommand("stopTimer", {"timerField": "timetoassignment"})
            demisto.results("Assignment of the incident was successful and so the Time To Assignment"
                            " timer has been stopped.")
    except Exception as e:  # pragma: no cover
        err_msg = f'Encountered an error while running the script: [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
