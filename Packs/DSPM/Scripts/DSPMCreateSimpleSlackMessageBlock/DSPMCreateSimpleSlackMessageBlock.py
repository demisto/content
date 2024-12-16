import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback


""" DSPM OVERWRITE LIST AND NOTIFY """
"""
Script Name: DSPMCreateSimpleSlackMessageBlock

Description:
This automation script overwrites the value of a specified list and sends a Slack notification
to inform the user that they failed to respond to an incident notification in a timely manner.
The notification includes a message indicating the end of the incident playbook and an invitation
to reopen the incident if necessary.
"""


def create_slack_notification_block(message, incidentLink):
    # Slack block structure for simple message
    block = {
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": message}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*XSOAR Incident Link:* {incidentLink}"}},
        ]
    }
    return block


def main():  # pragma: no cover
    try:
        message = demisto.args().get("message")
        incidentLink = demisto.args().get("incidentLink")

        # Create a Slack notification block
        slackBlock = create_slack_notification_block(message, incidentLink)

        # Return the results in markdown format
        return_results(CommandResults(outputs_prefix="slackBlock", outputs=slackBlock))
    except Exception as excep:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute script. Error: {str(excep)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
