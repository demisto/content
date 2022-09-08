import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import datetime, timedelta

# ##### Help #####
# This is an example script. The script is used to change the Remediation SLA of an incident,
# when the severity of the incident changes for any reason. Please copy this script and make changes to your liking.
# The Configuration section is there to help you easily configure the script with your desired SLAs.

# The CRITICAL_SLA field defines the number of minutes that you would want an incident with critical severity to have,
# in its Remediation SLA field.
# The NONCRITICAL_SLA field defines the number of days that you would want an incident with non-critical severity to have,
# in its Remediation SLA field.
# The NONCRITICAL_SLA field can also be configured in minutes if you want.

# Note that the SLA can be set with a number that represents minutes instead of days, like so:
# demisto.executeCommand("setIncident",{'sla': 30, "slaField":"remediationsla"})
# but it can also be set with a number that represents a complete date and time structure, like so:
# demisto.executeCommand("setIncident",{'sla': 2018-12-26T12:10:24Z, "slaField":"remediationsla"})
# To get the date+time structure, you can use timedelta, like so: newsla = now + datetime.timedelta(days=2)
# then, you would use this to convert it to the date+time structure that can be passed to the SLA field:
# newsla = newsla.strftime('%Y-%m-%dT%H:%M:%S+00:00')

# Since this script is to be triggered by a change of a field,
# you may want to make use of the changes to the field in your script.
# For example, in this case, when the severity of an incident is changed, we want to check if it is now critical, or not.
# We do this by using demisto.args()['new'], to get the new value of the severity.
# The field changes can be obtained in the following way:
# The name of the triggered field is in: demisto.args()['name']
# The field's old value is in: demisto.args()['old']
# The field's new value is in: demisto.args()['new']
# To print the whole argument structure, use this: demisto.results(demisto.args())


# ##### Configuration #####
CRITICAL_SLA = 60  # In minutes
NONCRITICAL_SLA = 6  # In days


def main():
    # ##### Logic #####
    args_sev = demisto.args().get('new')
    now = datetime.utcnow()

    if args_sev == 'Critical':
        return_results('Severity changed to Critical')
        demisto.executeCommand("setIncident", {'sla': CRITICAL_SLA, "slaField": "remediationsla"})

    else:
        return_results('Severity changed to Not Critical')
        newsla = now + timedelta(days=NONCRITICAL_SLA)
        newsla = newsla.strftime('%Y-%m-%dT%H:%M:%S+00:00')
        demisto.executeCommand("setIncident", {'sla': newsla, "slaField": "remediationsla"})


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
