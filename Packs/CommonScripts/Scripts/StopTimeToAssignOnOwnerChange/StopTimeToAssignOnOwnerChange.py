import demistomock as demisto
# ##### Help #####
# This is an example script. The script is used to stop the Time to Assignment SLA field,
# once an owner was set to an incident. If you want to use this script, you should go to
# the Owner field, and set this script as the script to run upon change of field value.

if not demisto.args().get('old') and demisto.args().get('new'):  # If owner was no-one and is now someone:
    demisto.executeCommand("stopTimer", {"timerField": "timetoassignment"})
    demisto.results("Assignment of the incident was successful and so the Time To Assignment"
                    " timer has been stopped.")
