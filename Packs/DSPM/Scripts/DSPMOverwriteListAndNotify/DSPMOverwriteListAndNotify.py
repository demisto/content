import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback


''' DSPM OVERWRITE LIST AND NOTIFY '''
'''
Script Name: DSPMOverwriteListAndNotify

Description:
This automation script overwrites the value of a specified list and sends a Slack notification to inform the user that they failed to respond to an incident notification in a timely manner. The notification includes a message indicating the end of the incident playbook and an invitation to reopen the incident if necessary.
'''


def overwrite_list_value(list_name, new_value):
    try:
        # Fetch the existing list
        existing_list = demisto.executeCommand('getList', {'listName': list_name})

        # Overwrite the list with the new value
        demisto.executeCommand('createList', {'listName': list_name, 'listData': new_value})

        demisto.results(f"Successfully overwritten the list: {list_name}")
    except Exception as excep:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to overwrite list {list_name}. Error: {str(excep)}')


def create_slack_notification_block(message):
    # Slack block structure
    block = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message
                }
            }
        ]
    }

    return block


def main():  # pragma: no cover
    try:
        list_name = demisto.args().get("list_name")
        message = demisto.args().get("message")

        # Create a Slack notification block
        block = create_slack_notification_block(message)

        # Overwrite the list value
        overwrite_list_value(list_name, block)

        # Send the Slack block as a result
        demisto.results(block)

    except Exception as excep:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute script. Error: {str(excep)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
