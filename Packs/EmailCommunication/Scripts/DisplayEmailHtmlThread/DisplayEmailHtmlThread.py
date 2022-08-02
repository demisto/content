import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


no_entries_message = """<!DOCTYPE html>
<html>
<body>
<h3>This Incident does not contain any email threads yet.</h3>
</body>
</html>
"""


def set_email_reply(email_from, email_to, email_cc, email_subject, html_body, email_time, attachment_names):
    """Set the email reply from the given details.
    Args:
        email_from: The email author mail.
        email_to: The email recipients.
        email_cc: The email cc.
        email_subject: The email subject.
        html_body: The email HTML body.
        email_time: The time the email was received
        attachment_names: String of attachment names
    Returns:
        str. Email reply.
    """

    single_reply = f'<html><body><b>From:</b> {email_from}<br><b>To:</b> {email_to}<br><b>CC:</b> {email_cc}<br>' \
                   f'<b>Subject:</b> {email_subject}<br><b>Email Time:</b> {email_time}<br>' \
                   f'<b>Attachments:</b> {attachment_names}</body></html>'

    single_reply += f'\n{html_body}\n<hr style="width:98%;text-align:center;height:3px;border-width:0;' \
                    f'background-color:#cccccc">\n\n'

    return single_reply


def html_cleanup(full_thread_html):
    """
        Moves various HTML tags so the final output is a single HTML document
    Args:
        full_thread_html (string): The concatenated string of all email HTML
    Returns:
        str. Full email thread HTML
    """
    # Remove HTML tags within the string that should only occur once
    full_thread_html = re.sub('(?i)<!DOCTYPE html>', '', full_thread_html)
    full_thread_html = re.sub('(?i)<.?html>', '', full_thread_html)
    full_thread_html = re.sub('(?i)<.?body>', '', full_thread_html)

    # Place needed HTML tags in their appropriate locations
    final_html_result = f'<!DOCTYPE html>\n<html>\n<body>\n{full_thread_html}\n</body>\n</html>'

    return final_html_result


def main():
    incident = demisto.incident()
    custom_fields = incident.get('CustomFields')
    thread_number = custom_fields.get('emailselectedthread', 0)
    incident_context = demisto.context()
    email_threads = incident_context.get('EmailThreads', {})

    if len(email_threads) == 0:
        return_results({
            'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': no_entries_message
        })
        return None

    if isinstance(email_threads, dict):
        email_threads = [email_threads]

    thread_exists = False
    thread_items = []
    full_thread_html = str()

    for thread in email_threads:
        if str(thread['EmailCommsThreadNumber']) == str(thread_number):

            thread_exists = True
            thread_dict = {
                'email_from': thread.get('EmailFrom', None),
                'email_cc': thread.get('EmailCC', None),
                'email_to': thread.get('EmailTo', None),
                'email_subject': thread.get('EmailSubject', None),
                'email_html': thread.get('EmailHTML', None),
                'email_time': thread.get('MessageTime', None),
                'email_attachments': thread.get('EmailAttachments', None),
            }
            thread_items.append(thread_dict)

    if thread_exists:
        # Append all messages together, with the most recent on top
        for thread in reversed(thread_items):
            email_reply = set_email_reply(thread.get('email_from', None), thread.get('email_to', None),
                                          thread.get('email_cc', None), thread.get('email_subject', None),
                                          thread.get('email_html', None), thread.get('email_time', None),
                                          thread.get('email_attachments', None))
            full_thread_html += email_reply

        final_html_result = html_cleanup(full_thread_html)
        return_results({
            'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': final_html_result
        })
    else:
        return_error(f"An email thread of {thread_number} was not found. Please make sure this thread number is correct.")


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
