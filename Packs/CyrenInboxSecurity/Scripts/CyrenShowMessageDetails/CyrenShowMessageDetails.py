import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# type: ignore

import collections
from dateutil import parser
import json


def message_details_to_text(message_details):
    markdown_result = ""

    # extract key values
    msg_attachment_count = str(len(message_details['attachments']))
    msg_subject = message_details['email_subject']
    msg_id = message_details['message_id']
    msg_from = message_details['from']['name'] + " \<" + message_details['from']['address'] + "\>"
    msg_targeted = message_details['targeted_employee']['name'] + " \<" + message_details['targeted_employee']['address'] + "\>"
    msg_other_recipients = ""
    for other in message_details['other_recipients']:
        msg_other_recipients += "- " + other['name'] + " \<" + other['address'] + "\>, "
    if msg_other_recipients == "":
        msg_other_recipients = "None"

    # Build the text
    markdown_result += "From: " + msg_from + "<br>"
    markdown_result += "To (targeted employee): " + msg_targeted + "<br>"
    markdown_result += "Subject: " + msg_subject + "<br>"
    markdown_result += "Attachment Count: " + msg_attachment_count + "<br>"
    markdown_result += "Other Recipients (" + str(len(message_details['other_recipients'])) + "):" + msg_other_recipients + "<br>"
    markdown_result += "Message ID: " + msg_id + "<br>"

    return markdown_result


def stringify_message_details(message_details):
    markdown_result = ""

    # extract key values
    msg_attachment_count = str(len(message_details['attachments']))
    msg_subject = message_details['email_subject']
    msg_id = message_details['message_id']
    msg_from = message_details['from']['name'] + " \<" + message_details['from']['address'] + "\>"
    msg_targeted = message_details['targeted_employee']['name'] + " <" + message_details['targeted_employee']['address'] + ">"
    msg_other_recipients = ""
    for other in message_details['other_recipients']:
        msg_other_recipients += "- " + other['name'] + " \<" + other['address'] + "\>\n"
    if msg_other_recipients == "":
        msg_other_recipients = "None"

    # Build the markdown
    markdown_result += "**From**\n" + msg_from + "\n\n"
    markdown_result += "**To (targeted employee)**\n" + msg_targeted + "\n\n"
    markdown_result += "**Subject**\n" + msg_subject + "\n\n"
    markdown_result += "**Attachment Count**\n" + msg_attachment_count + "\n\n"
    markdown_result += "**Other Recipients (" + \
        str(len(message_details['other_recipients'])) + ")**\n" + msg_other_recipients + "\n\n"
    markdown_result += "**Message ID**\n" + msg_id + "\n\n"

    return markdown_result


def main():

    # threat indicators
    # raise NameError(demisto.incidents()[0])
    message_details = demisto.get(demisto.incidents()[0], 'CustomFields.cyrenmessagedetails')
    if not message_details:
        return

    message_details = json.loads(message_details)
    markdown_result = stringify_message_details(message_details)

    context = {
        'cyrenMessageDetails': message_details_to_text(message_details)
    }

    return {'ContentsFormat': formats['markdown'],
            'Type': entryTypes['note'],
            'Contents': markdown_result,
            'EntryContext': context
            }


if __name__ in ['__main__', '__builtin__', 'builtins']:
    entry = main()
    demisto.results(entry)
