import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
'''
  Script Name: DSPMNotifyUser
  Description:
  This script sends a Slack notification to the user when an error occurs during the execution of an incident playbook.
  It updates a list (Slack block) with the error details and sends a message notifying the user about the error and providing the option to revisit the incident.
  The script supports custom incident data and messages, allowing flexibility in notifications.
  '''

import traceback


def update_list_data(list_name, new_value):
    """
    Updates the content of a list with the specified new value. If the list does not exist, it is created.

    Args:
        list_name (str): The name of the list to update.
        new_value (dict): The new value (Slack block structure) to update in the list.

    Returns:
        None
    """
    try:
        if list_name is None:
            list_name = f"slack block of Incident ID : {incident.get('id')}"
        # Fetch the existing list
        existing_list = demisto.executeCommand('getList', {'listName': list_name})

        # Update the list with the new value
        demisto.executeCommand('createList', {'listName': list_name, 'listData': new_value})

        demisto.info(f"Successfully created/updated the list: {list_name}")
    except Exception as excep:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to create/update list {list_name}. Error: {str(excep)}')


def create_message_to_send_user(incident):
    """
    Creates a message to notify the user that the Slack notification will be re-run based on the configured lifetime.

    Args:
        incident (dict or list): The incident data from which the message is constructed.

    Returns:
        str: The notification message to be sent to the user.
    """
    if isinstance(incident, list):
        incident = incident[0]
    message = "It will re-run again as per the time you have provided in lifetime for slack notification."
    return message


def create_slack_notification_block(message, incident):
    """
    Creates a Slack notification block with the provided message and incident details.

    Args:
        message (str): The error message to be included in the Slack notification.
        incident (dict): The incident data for which the notification is being created.

    Returns:
        dict: The Slack block structure to send as a notification.
    """
    message = f"There is an error while running playbook for incident {incident.get('id')}. Error message: {message}"
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
    """
    Main function to execute the DSPMNotifyUser script. It creates a Slack notification block,
    updates the list with the block, deletes the context key "OnError", and sends the block as a result.
    """
    try:
        incident = demisto.args().get("dspm_incident")
        list_name = demisto.args().get("list_name", None)
        message = demisto.args().get("message", None)

        if message is None:
            message = create_message_to_send_user(incident)

        # Create a Slack notification block
        block = create_slack_notification_block(message, incident)

        # Overwrite the list value
        update_list_data(list_name, block)

        # Delete the context value
        res = demisto.executeCommand("delContext", {"key": "OnError"})
        print(res)

        # Send the Slack block as a result
        demisto.results(block)

    except Exception as excep:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute script. Error: {str(excep)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
