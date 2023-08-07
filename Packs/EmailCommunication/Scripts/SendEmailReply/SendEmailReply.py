import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import random
import re
from datetime import datetime as dt

ERROR_TEMPLATE = 'ERROR: SendEmailReply - {function_name}: {reason}'


def get_utc_now():
    """ A wrapper function for datetime.utcnow
    Helps handle tests
    Returns:
        datetime: current UTC time
    """
    return dt.utcnow()


def append_email_signature(html_body):
    """
        Retrieve the user defined email signature to include on new messages, if present.
    Args: (string) html_body
    Returns: (string) Original HTML body with HTML formatted email signature appended
    """
    email_signature = demisto.executeCommand('getList', {'listName': 'XSOAR - Email Communication Signature'})

    if is_error(email_signature):
        demisto.debug('Error occurred while trying to load the `XSOAR - Email Communication Signature` list. No '
                      'signature added to email')
    else:
        # Find the position of the closing </html> tag and insert the signature there
        if re.search('(?i)</body>', html_body):
            html_body = re.sub('(?i)</body>', f"\r\n{email_signature[0]['Contents']}\r\n</body>", html_body)

    return html_body


def validate_email_sent(incident_id, email_subject, subject_include_incident_id, email_to, reply_body, service_mail,
                        email_cc, email_bcc, reply_html_body, entry_id_list, email_latest_message, email_code,
                        mail_sender_instance):
    """
    Validate that the email was actually sent, returns an error string if it wasn't sent successfully.
    Args:
        incident_id: The incident ID.
        email_subject: The email subject.
        subject_include_incident_id: Should we include the incident id in the email subject.
        email_to: The email's recipients.
        reply_body: The email body.
        service_mail: The service mail (mail listener).
        email_cc: The email cc.
        email_bcc: The email bcc.
        reply_html_body: The email html body.
        entry_id_list: The files entry ids list.
        email_latest_message: The latest message ID in the email thread to reply to.
        email_code: The random code that was generated when the incident was created.
        mail_sender_instance: The name of the mail sender integration instance
    Returns:
        str: a message which indicates that the mail was sent successfully or an error message.
    """
    email_reply = execute_reply_mail(incident_id, email_subject, subject_include_incident_id, email_to, reply_body,
                                     service_mail, email_cc, email_bcc, reply_html_body, entry_id_list,
                                     email_latest_message, email_code, mail_sender_instance)

    if is_error(email_reply):
        return f'Error:\n {get_error(email_reply)}'

    msg = f'Mail sent successfully. To: {email_to}'
    if email_cc:
        msg += f' Cc: {email_cc}'
    if email_bcc:
        msg += f' Bcc: {email_bcc}'

    return msg


def execute_reply_mail(incident_id, email_subject, subject_include_incident_id, email_to, reply_body, service_mail,
                       email_cc, email_bcc, reply_html_body, entry_id_list, email_latest_message, email_code,
                       mail_sender_instance):
    if subject_include_incident_id and f'[{incident_id}]' not in email_subject:
        email_subject = f'[{incident_id}] {email_subject}'

    if f'<{email_code}' not in email_subject:
        subject_with_id = f"<{email_code}> {email_subject}"

        # setting the email's subject for gmail adjustments
        try:
            demisto.executeCommand('setIncident',
                                   {'id': incident_id, 'customFields': {'emailsubject': f'{subject_with_id}'}})
        except Exception:
            return_error(f'SetIncident Failed.'
                         f'"emailsubject" field was not updated with {subject_with_id} value '
                         f'for incident: {incident_id}')
    else:
        subject_with_id = email_subject

    # If a mail sender instance has been set, set the "using" parameter with it. Otherwise, do not set "using"
    if mail_sender_instance:
        mail_content = {
            "to": email_to,
            "inReplyTo": email_latest_message,
            "subject": subject_with_id,
            "cc": email_cc,
            "bcc": email_bcc,
            "htmlBody": reply_html_body,
            "body": reply_body,
            "attachIDs": ",".join(entry_id_list),
            "replyTo": service_mail,
            "using": mail_sender_instance
        }
    else:
        mail_content = {
            "to": email_to,
            "inReplyTo": email_latest_message,
            "subject": subject_with_id,
            "cc": email_cc,
            "bcc": email_bcc,
            "htmlBody": reply_html_body,
            "body": reply_body,
            "attachIDs": ",".join(entry_id_list),
            "replyTo": service_mail
        }
    return demisto.executeCommand("reply-mail", mail_content)


def get_email_threads(incident_id):
    """
        Retrieve all entries in the EmailThreads context key
    Args:
        incident_id: The current incident ID
    Returns:
        Dict of email thread entries
    """
    # Get current email threads from context if any are present
    incident_context = demisto.executeCommand("getContext", {'id': incident_id})
    incident_email_threads = dict_safe_get(incident_context[0], ['Contents', 'context', 'EmailThreads'])
    return incident_email_threads


def create_thread_context(email_code, email_cc, email_bcc, email_text, email_from, email_html,
                          email_latest_message, email_received, email_replyto, email_subject, email_to,
                          incident_id, new_attachment_names):
    """Creates a new context entry to store the email in the incident context.  Checks current threads
    stored on the incident to get the thread number associated with this new message, if present.
    Args:
        email_code: The random code that was generated when the email was received
        email_cc: The email CC
        email_bcc: The email BCC
        email_text: The email body plaintext
        email_from: The email sender address
        email_html: The email body HTML
        email_latest_message: The email message ID
        email_received: Mailbox that received the email at XSOAR is fetching from
        email_replyto: The replyTo address from the email
        email_subject: The email subject
        email_to: The address the email was delivered to
        incident_id: ID of the related incident
        new_attachment_names: File attachments sent with the email
    """
    thread_number = ''
    thread_found = False
    try:
        incident_email_threads = get_email_threads(incident_id)

        # Check if there is already a thread for this email code
        if incident_email_threads:
            if isinstance(incident_email_threads, dict):
                incident_email_threads = [incident_email_threads]

            search_result = next((i for i, item in enumerate(incident_email_threads) if
                                  item["EmailCommsThreadId"] == email_code), None)
            if search_result is not None:
                thread_number = incident_email_threads[search_result]['EmailCommsThreadNumber']
                thread_found = True

            if not thread_found:
                # If no related thread is found, determine the highest thread number
                max_thread_number = 0

                for message in incident_email_threads:
                    if int(message['EmailCommsThreadNumber']) > max_thread_number:
                        max_thread_number = int(message['EmailCommsThreadNumber'])

                thread_number = str(max_thread_number + 1)
        else:
            thread_number = '0'

        if len(thread_number) == 0:
            return_error('Failed to identify a Thread Number to set. Email not appended to incident context')

        email_message = {
            'EmailCommsThreadId': email_code,
            'EmailCommsThreadNumber': thread_number,
            'EmailCC': email_cc,
            'EmailBCC': email_bcc,
            'EmailBody': email_text,
            'EmailFrom': email_from,
            'EmailHTML': email_html,
            'MessageID': email_latest_message,
            'EmailReceived': email_received,
            'EmailReplyTo': email_replyto,
            'EmailSubject': email_subject,
            'EmailTo': email_to,
            'EmailAttachments': new_attachment_names,
            'MessageDirection': 'outbound',
            'MessageTime': get_utc_now().strftime("%Y-%m-%dT%H:%M:%SUTC")
        }
        # Add email message to context key
        try:
            appendContext('EmailThreads', email_message, False)
        except Exception as e:
            return_error(f"Failed to append new email to context of incident {incident_id}. Reason: {e}")
    except Exception as e:
        return_error(f"Unable to add new email message to Incident {incident_id}. Reason: \n {e}")


def send_new_email(incident_id, email_subject, subject_include_incident_id, email_to, email_body, service_mail,
                   email_cc, email_bcc, email_html_body, entry_id_list, email_code, mail_sender_instance,
                   new_attachment_names):
    """Send new email.-
    Args:
        incident_id: The incident ID.
        email_subject: The email subject.
        subject_include_incident_id: Should we include the incident id in the email subject.
        email_to: The email's recipients.
        email_body: The email body.
        service_mail: The service mail (mail listener).
        email_cc: The email cc.
        email_bcc: The email bcc.
        email_html_body: The email html body.
        entry_id_list: The files entry ids list.
        email_code: The random code that was generated when the incident was created.
        mail_sender_instance: The name of the mail sender integration instance
        new_attachment_names: List of attachment file names
    """
    # Get the custom email signature, if set, and append it to the message to be sent
    email_html_body = append_email_signature(email_html_body)

    email_result = send_new_mail_request(incident_id, email_subject, subject_include_incident_id, email_to, email_body,
                                         service_mail, email_cc, email_bcc, email_html_body, entry_id_list,
                                         new_attachment_names, email_code, mail_sender_instance)

    if is_error(email_result):
        return f'Error:\n {get_error(email_result)}'

    msg = f'Mail sent successfully. To: {email_to}'
    if email_cc:
        msg += f' Cc: {email_cc}'
    if email_bcc:
        msg += f' Bcc: {email_bcc}'

    return msg


def send_new_mail_request(incident_id, email_subject, subject_include_incident_id, email_to, email_body, service_mail,
                          email_cc, email_bcc, email_html_body, entry_id_list, new_attachment_names, email_code,
                          mail_sender_instance):
    """
            Use message details from the selected thread to construct a new mail message, since
            resending a first-contact email does not have a Message ID to reply to.
        Args:
            incident_id: ID of the current incident
            email_subject: The email subject
            subject_include_incident_id: Should we include the incident id in the email subject.
            email_to: The email's recipients
            email_body: The email body
            email_cc: The email cc
            email_bcc: The email bcc
            email_html_body: The email html body
            entry_id_list: The files entry ids list
            new_attachment_names: List of attachment file names
            email_code: The random code that was generated when the incident was created
            mail_sender_instance: The service email (sender address)
            service_mail: Address the email is sent from
        Returns: Results from the 'send-mail' command
        """
    if subject_include_incident_id and f'[{incident_id}]' not in email_subject:
        email_subject = f'[{incident_id}] {email_subject}'

    if f'<{email_code}' not in email_subject:
        subject_with_id = f"<{email_code}> {email_subject}"
    else:
        subject_with_id = email_subject

    # If a mail sender instance has been set, set the "using" parameter with it. Otherwise, do not set "using"
    if mail_sender_instance:
        mail_content = {
            "to": email_to,
            "subject": subject_with_id,
            "cc": email_cc,
            "bcc": email_bcc,
            "htmlBody": email_html_body,
            "body": email_body,
            "attachIDs": ",".join(entry_id_list),
            "replyTo": service_mail,
            "using": mail_sender_instance
        }
    else:
        mail_content = {
            "to": email_to,
            "subject": subject_with_id,
            "cc": email_cc,
            "bcc": email_bcc,
            "htmlBody": email_html_body,
            "body": email_body,
            "attachIDs": ",".join(entry_id_list),
            "replyTo": service_mail
        }
    # Send email
    email_result = demisto.executeCommand("send-mail", mail_content)

    # Store message details in context entry
    create_thread_context(email_code, email_cc, email_bcc, email_body, service_mail, email_html_body,
                          "", "", service_mail, subject_with_id, email_to, incident_id, new_attachment_names)

    return email_result


def get_email_cc(current_cc=None, additional_cc=None):
    """Get current email cc and additional cc and combines them together.
    Args:
        current_cc: Current email cc.
        additional_cc: Additional email cc.
    Returns:
        str. Email's cc
    """

    if current_cc:
        if additional_cc:
            return current_cc.replace(' ', '') + ',' + additional_cc.replace(' ', '')
        else:
            return current_cc.replace(' ', '')
    elif additional_cc:
        return additional_cc.replace(' ', '')
    return ''


def get_entry_id_list(incident_id, attachments, new_email_attachments, files):
    """Get the email attachments and create entry id list.
    Args:
        incident_id (str): The incident id.
        attachments (list): The attachments of the original incident email.
        new_email_attachments (list): Attachments to send on new emails
        files (list): The uploaded files in the context.
    Returns:
        list. Attachments entries ids list.
    """
    entry_id_list = []
    if attachments:
        attachment_list = attachments
        field_name = 'attachment'
    elif new_email_attachments:
        attachment_list = new_email_attachments
        field_name = 'emailnewattachment'
    else:
        attachment_list = False

    if attachment_list and files:
        for attachment in attachment_list:
            attachment_name = attachment.get('name', '')
            file_data = create_file_data_json(attachment, field_name)
            demisto.executeCommand("demisto-api-post", {"uri": f"/incident/remove/{incident_id}", "body": file_data})
            if not isinstance(files, list):
                files = [files]
            for file in files:
                if attachment_name == file.get('Name'):
                    entry_id_list.append(file.get('EntryID'))

    return entry_id_list


def create_file_data_json(attachment, field_name):
    """Get attachment and create a json with its data.
    Args:
        attachment (dict): The attachments of the email.
        field_name (string): The name of the attachment field to process
    Returns:
        dict. Attachment data.
    """
    attachment_name = attachment['name']
    attachment_path = attachment['path']
    attachment_type = attachment['type']
    attachment_media_file = attachment['showMediaFile']
    attachment_description = attachment['description']
    file_data = {
        "fieldName": field_name,
        "files": {
            attachment_path: {
                "description": "", "name": attachment_name, "path": attachment_path,
                "showMediaFile": attachment_media_file,
                "type": attachment_type
            }
        },
        "originalAttachments": [
            {
                "description": attachment_description,
                "name": attachment_name,
                "path": attachment_path,
                "showMediaFile": attachment_media_file,
                "type": attachment_type
            }
        ]}
    return json.dumps(file_data)


def get_reply_body(notes, incident_id, attachments, reputation_calc_async=False):
    """ Get the notes and the incident id and return the reply body
    Args:
        notes (list): The notes of the email.
        incident_id (str): The incident id.
        attachments (list): The email's attachments.
    Returns:
        The reply body and the html body.
    """
    reply_body = ''
    if notes:
        for note in notes:
            note_user = note['Metadata']['user']
            note_userdata = demisto.executeCommand("getUserByUsername", {"username": note_user})
            user_fullname = dict_safe_get(note_userdata[0], ['Contents', 'name']) or "DBot"
            reply_body += f"{user_fullname}: \n{note['Contents']}\n\n"

        if isinstance(attachments, str):
            attachments = argToList(attachments)

        if attachments:
            attachment_names = [attachment.get('name') for attachment in attachments]
            reply_body += f'Attachments: {attachment_names}\n\n'

        entry_note = json.dumps(
            [{"Type": 1, "ContentsFormat": 'html', "Contents": reply_body, "tags": ['email-thread']}])
        entry_tags_res = demisto.executeCommand(
            "addEntries", {"entries": entry_note, 'id': incident_id, 'reputationCalcAsync': reputation_calc_async})

        entry_note_res = demisto.executeCommand("demisto-api-post", {"uri": "/entry/note", "body": json.dumps(
            {"id": note.get('ID'), "version": -1, "investigationId": incident_id, "data": "false"})})
        if is_error(entry_note_res):
            return_error(get_error(entry_note_res))
        if is_error(entry_tags_res):
            return_error(get_error(entry_tags_res))

    else:
        return_error("Please add a note")

    try:
        res = demisto.executeCommand("mdToHtml", {"contextKey": "replyhtmlbody", "text": reply_body})
        reply_html_body = res[0]['EntryContext']['replyhtmlbody']
        return reply_body, reply_html_body
    except Exception:
        return_error(get_error(res))


def get_email_recipients(email_to, email_from, service_mail, mailbox):
    """Get the email recipient.
        The mailbox should be removed from the recipients list, so the replied email
        won't get to the same mailbox and causes a loop. If somehow it is None,
        the service mail should be removed.
    Args:
        email_to (str): The email receiver.
        email_from (str): The email's sender.
        service_mail (str): The mail listener.
        mailbox (str): The mailbox configured in the relevant integration.
    Returns:
        The email recipients.
    """
    email_to_set = {email_from}
    email_to = argToList(email_to)
    email_to_set = email_to_set.union(set(email_to))

    # Remove any empty values resulting from any arguments receiving an empty string
    email_to_set = list(filter(lambda item: item, email_to_set))

    recipient_to_remove = ''
    address_to_remove = mailbox if mailbox else service_mail
    if address_to_remove:
        for recipient in email_to_set:
            if address_to_remove in recipient:
                recipient_to_remove = recipient
                break

    if recipient_to_remove:
        email_to_set.remove(recipient_to_remove)

    email_recipients = ','.join(email_to_set)
    return email_recipients


def get_mailbox_from_incident_labels(labels):
    """
    Gets the mailbox from which the incident was fetched from the incident labels.
    Args:
        labels (list): the incident labels.
    Returns:
        The mailbox label.
    """
    if labels:
        for label in labels:
            if label.get('type') == 'Mailbox':
                return label.get('value')
    return None


def get_query_window():
    """
    Check if the user defined the list `XSOAR - Email Communication Days To Query` to give a custom value for the time
    to query back for related incidents. If yes, use this value, else use the default value of 60 days.
    """
    user_defined_time = demisto.executeCommand('getList', {'listName': 'XSOAR - Email Communication Days To Query'})
    if is_error(user_defined_time):
        demisto.debug('Error occurred while trying to load the `XSOAR - Email Communication Days To Query` list. Using'
                      ' the default query time - 60 days')
        return '60 days'

    try:
        query_time = user_defined_time[0].get('Contents')
        return f'{int(query_time)} days'
    except ValueError:
        return_error('Invalid input for number of days to query in the `XSOAR - Email Communication Days To Query` '
                     'list. Input should be a number only, representing the number of days to query back.\nUsing the '
                     'default query time - 60 days')
        return '60 days'


def get_incident_by_query(query):
    """
    Get a query and return all incidents details matching the given query.
    Args:
        query: Query for the incidents that should be returned.
    Returns:
        dict. The details of all incidents matching the query.
    """
    # In order to avoid performance issues, limit the number of days to query back for modified incidents.
    # By default, the limit is 60 days and can be modified by the user by adding a list called
    # `XSOAR - Email Communication Days To Query` (see README for more information).
    query_time = get_query_window()

    query_from_date = str(parse_date_range(query_time)[0])

    query += f' modified:>="{query_from_date}"'

    res = demisto.executeCommand("getIncidents", {"query": query, "populateFields": "id,status"})[0]
    if is_error(res):
        return_results(ERROR_TEMPLATE.format('getIncidents', res['Contents']))
        raise DemistoException(ERROR_TEMPLATE.format('getIncidents', res['Contents']))

    incidents_details = res['Contents']['data']

    return incidents_details


def get_unique_code():
    """
        Create an 8-digit unique random code that should be used to identify new created incidents.
    Args: None
    Returns:
        8-digit code returned as a string
    """
    while True:
        code = f'{random.randrange(1, 10 ** 8):08}'
        query = f'emailgeneratedcode: {code}'
        incidents_details = get_incident_by_query(query)
        if incidents_details is None or len(incidents_details) == 0:
            return code


def reset_fields():
    """
    Clears fields used to send the email message so that they can be used again to create another new message.
    Args: None
    """
    demisto.executeCommand('setIncident', {'emailnewrecipients': '', 'emailnewsubject': '',
                                           'emailnewbody': '', 'addcctoemail': '', 'addbcctoemail': ''})


def resend_first_contact(email_selected_thread, email_thread, incident_id, new_email_attachments, files, new_email_body,
                         add_cc, add_bcc, service_mail, mail_sender_instance, new_attachment_names,
                         subject_include_incident_id):
    """
        Use message details from the selected thread to construct a new mail message, since resending a first-contact
        email does not have a Message ID to reply to.
    Args:
        email_selected_thread: Selected thread number to re-send
        email_thread: Dict containing the thread details
        incident_id: ID of the current incident
        new_email_attachments: Dict of attachment details
        files: Incident files
        new_email_body: The email body
        add_cc: The email CC list
        add_bcc: The email BCC list
        service_mail: Address the email is sent from
        mail_sender_instance: The service email (sender address)
        new_attachment_names: List of attachment file names
        subject_include_incident_id: Should we include the incident id in the email subject.
    Returns: Results from send_new_email function
    """
    # Verify the selected thread ID matches this dict
    if str(email_selected_thread) == str(email_thread['EmailCommsThreadNumber']):
        new_email_recipients = email_thread['EmailTo']
        thread_cc = email_thread['EmailCC']
        thread_bcc = email_thread['EmailBCC']
        reply_subject = email_thread['EmailSubject']
        reply_code = email_thread['EmailCommsThreadId']
        entry_id_list = get_entry_id_list(incident_id, [], new_email_attachments, files)

        html_body = format_body(new_email_body)

        final_email_cc = get_email_cc(thread_cc, add_cc)
        final_email_bcc = get_email_cc(thread_bcc, add_bcc)
        result = send_new_email(incident_id, reply_subject, subject_include_incident_id, new_email_recipients,
                                new_email_body, service_mail, final_email_cc, final_email_bcc, html_body, entry_id_list,
                                reply_code, mail_sender_instance, new_attachment_names)

        return result
    else:
        return_error(f'The selected Thread Number to respond to ({email_selected_thread}) '
                     f'does not exist.  Please choose a valid Thread Number and re-try.')
        return None


def format_body(new_email_body):
    """
        Converts markdown included in the email body to HTML
    Args:
        new_email_body (str): Email body text with or without Markdown formatting included
    Returns: (str) HTML email body
    """
    # Replace newlines with <br> element to preserve line breaks
    new_email_body = new_email_body.replace('\n', '<br>')

    res = demisto.executeCommand("mdToHtml", {"text": new_email_body})
    html_body = res[0]['Contents']

    return html_body


def single_thread_reply(email_code, incident_id, email_cc, add_cc, notes, attachments, files, email_subject,
                        subject_include_incident_id, email_to_str, service_mail, email_latest_message,
                        mail_sender_instance, reputation_calc_async=False):
    """
        Retrieve all entries in the EmailThreads context key
    Args:
        email_code: The random code that was generated when the incident was created.
        incident_id: The incident ID.
        email_cc: The email cc.
        add_cc: The email bcc.
        notes: Entry IDs of notes containing the reply email body
        attachments: Entry IDs of file attachments
        files: Dictionary of incident file details
        email_subject: The email subject
        subject_include_incident_id: Should we include the incident id in the email subject.
        email_to_str: The email's recipients
        service_mail: The service mail (mail listener).
        email_latest_message: The latest message ID in the email thread to reply to.
        mail_sender_instance: The name of the mail sender integration instance
    Returns:
        String containing result message from send_reply function
    """
    # This action is used by the "Email Communication" layout
    # Use Incident fields to construct & send email reply.
    if not email_code:
        # If a unique code is not set for this incident yet, generate and set it
        email_code = get_unique_code()
        demisto.executeCommand('setIncident', {'id': incident_id,
                                               'customFields': {'emailgeneratedcode': email_code}})
    try:
        final_email_cc = get_email_cc(email_cc, add_cc)
        reply_body, reply_html_body = get_reply_body(notes, incident_id, attachments, reputation_calc_async)
        entry_id_list = get_entry_id_list(incident_id, attachments, [], files)
        result = validate_email_sent(incident_id, email_subject, subject_include_incident_id, email_to_str, reply_body,
                                     service_mail, final_email_cc, '', reply_html_body, entry_id_list,
                                     email_latest_message, email_code, mail_sender_instance)
        return_results(result)

    except Exception as error:
        return_error(f"Failed to send email via new_thread = 'n/a' branch. Reason: {error}")


def multi_thread_new(new_email_subject, subject_include_incident_id, new_email_recipients, new_email_body, incident_id,
                     email_codes, new_email_attachments, files, service_mail, add_cc, add_bcc, mail_sender_instance,
                     new_attachment_names):
    """Validates that all necessary fields are set to send a new email, gets a unique code to associate replies
    to the current incident, prepares the final HTML email message body, then sends the email.
    Args:
        email_codes: The random code that was generated when the incident was created.
        new_email_body: The email body
        incident_id: The incident ID.
        add_cc: The email cc.
        add_bcc: The email bcc.
        files: Dictionary of incident file details
        new_email_subject: The email subject
        subject_include_incident_id: Should we include the incident id in the email subject.
        new_email_recipients: The email's recipients
        service_mail: The service mail (mail listener).
        new_email_attachments: Files to attach to the new email message
        mail_sender_instance: The name of the mail sender integration instance
        new_attachment_names: File names of attachments being sent on the email
    Returns:
        String containing result message from send_new_email function
        """
    # Use New Thread Incident fields to construct & send email reply
    # This action is used by the "Email Threads" layout

    # Ensure that Recipient, Subject and Body fields have been set
    if not (new_email_subject and new_email_recipients and new_email_body):
        missing_fields = []
        if not new_email_subject:
            missing_fields.append('New Email Subject')
        if not new_email_recipients:
            missing_fields.append('New Email Recipients')
        if not new_email_body:
            missing_fields.append('New Email Body')
        return_error(f'The following required fields have not been set.  Please set them and try again. '
                     f'{missing_fields}')

    thread_code = get_unique_code()

    # If there are already other values in 'emailgeneratedcodes', append the new code as a comma-separated list
    if email_codes:
        demisto.executeCommand('setIncident',
                               {'id': incident_id,
                                'customFields': {'emailgeneratedcodes': f"{email_codes},{thread_code}"}})
    else:
        demisto.executeCommand('setIncident',
                               {'id': incident_id,
                                'customFields': {'emailgeneratedcodes': f"{thread_code}"}})
    try:
        entry_id_list = get_entry_id_list(incident_id, [], new_email_attachments, files)

        html_body = format_body(new_email_body)

        result = send_new_email(incident_id, new_email_subject, subject_include_incident_id, new_email_recipients,
                                new_email_body, service_mail, add_cc, add_bcc, html_body, entry_id_list, thread_code,
                                mail_sender_instance, new_attachment_names)
        return_results(result)

        # Clear fields for re-use
        reset_fields()

    except Exception as error:
        return_error(f"Failed to send email via new_thread = 'true' branch. Reason: {error}")


def collect_thread_details(incident_email_threads, email_selected_thread):
    """
    Retrieve all entries in the EmailThreads context key
    Args:
        incident_email_threads: Dict containing all threads present on the incident
        email_selected_thread: Thread Number currently selected
    Returns:
        Tuple containing details of the selected email thread for re-use in creating reply message
    """
    thread_found = False
    reply_to_message_id = ''
    reply_recipients = ''
    reply_subject = ''
    reply_mailbox = ''
    thread_cc = ''
    thread_bcc = ''
    reply_code = ''
    outbound_only = True
    last_thread_processed = 0

    # Iterate through each entry with the selected number.  The last one contains the ID to reply to.
    for idx, thread_entry in enumerate(incident_email_threads):
        if str(thread_entry['EmailCommsThreadNumber']) == str(email_selected_thread):
            thread_found = True

            if thread_entry['MessageDirection'] == 'inbound':
                reply_to_message_id = thread_entry['MessageID']
                outbound_only = False
            reply_code = thread_entry['EmailCommsThreadId']
            reply_subject = thread_entry['EmailSubject']
            email_to = thread_entry['EmailTo']
            email_from = thread_entry['EmailFrom']
            email_received = thread_entry['EmailReceived']

            # Create recipient list based on all 'EmailTo' and 'EmailFrom' values
            if email_to and email_to not in reply_recipients:
                if len(reply_recipients) == 0:
                    reply_recipients = email_to
                else:
                    reply_recipients += f", {email_to}"

            if email_from and email_from not in reply_recipients:
                if len(reply_recipients) == 0:
                    reply_recipients = email_from
                else:
                    reply_recipients += f", {email_from}"

            # Create list of mailboxes receiving messages in this thread in case there are multiple
            if email_received and email_received not in reply_mailbox:
                if len(reply_mailbox) == 0:
                    reply_mailbox = email_received
                else:
                    reply_mailbox += f", {email_received}"

            # Create list of CC addresses based on others CC'd on this thread
            if thread_entry['EmailCC']:
                for cc_address in thread_entry['EmailCC'].split(","):
                    if cc_address not in thread_cc and len(thread_cc) == 0:
                        thread_cc = cc_address
                    elif cc_address not in thread_cc:
                        thread_cc += f',{cc_address}'

            # Create list of BCC addresses based on others BCC'd on this thread
            if thread_entry['EmailBCC']:
                for bcc_address in thread_entry['EmailBCC'].split(","):
                    if bcc_address not in thread_bcc and len(thread_bcc) == 0:
                        thread_bcc = bcc_address
                    elif bcc_address not in thread_bcc:
                        thread_bcc += f',{bcc_address}'
            # Keep track of the last processed list position
            last_thread_processed = idx

    return thread_found, reply_to_message_id, outbound_only, reply_code, reply_subject, reply_recipients,\
        reply_mailbox, thread_cc, thread_bcc, last_thread_processed


def multi_thread_reply(new_email_body, incident_id, email_selected_thread, new_email_attachments, files, add_cc,
                       add_bcc, service_mail, mail_sender_instance, new_attachment_names, subject_include_incident_id):
    """Validates that all necessary fields are set to send a reply email, retrieves details about the thread from
    incident context (subject, list of recipients, etc.).  In the event this reply is for an email thread that has no
     inbound messages from end users this function will re-use details from the previous outbound first-contact email
     and create a new email to send. Prepares the final HTML email message body, then sends the email.
    Args:
        new_email_body: The email body
        incident_id: The incident ID.
        email_selected_thread: Thread Number currently selected
        add_cc: The email cc.
        add_bcc: The email bcc.
        files: Dictionary of incident file details
        service_mail: The service mail (mail listener).
        new_email_attachments: Files to attach to the new email message
        mail_sender_instance: The name of the mail sender integration instance
        new_attachment_names: File names of attachments being sent on the email
        subject_include_incident_id: Should we include the incident id in the email subject.
    Returns:
        String containing result message from resend_first_contact function or the send_reply function, whichever
        is required by the applicable case
        """
    # This action is used by the "Email Threads" layout
    # Ensure that the Body field has been set
    if not new_email_body:
        return_error('The \'New Email Body\' field has not been set. Please set it and try again')

    try:
        incident_email_threads = get_email_threads(incident_id)
        if not incident_email_threads:
            return_error('Failed to retrieve email thread entries - reply not sent!')

        first_contact_resent = False

        if type(incident_email_threads) == dict:
            """
            A 'dict' input means only one email message exists in the context.  This also means
            this was an 'outbound' message, as it is not possible for an an initial incoming message
            to be stored as a thread without an existing incident to link to.
            """
            result = resend_first_contact(email_selected_thread, incident_email_threads, incident_id,
                                          new_email_attachments, files, new_email_body, add_cc, add_bcc, service_mail,
                                          mail_sender_instance, new_attachment_names, subject_include_incident_id)

            # Clear fields for re-use
            reset_fields()

            return_results(result)

            first_contact_resent = True

        elif type(incident_email_threads) == list:
            # Process existing thread entries in this email chain to gather re-usable data for new message
            thread_found, reply_to_message_id, outbound_only, reply_code, reply_subject, reply_recipients, \
                reply_mailbox, thread_cc, thread_bcc,\
                last_thread_processed = collect_thread_details(incident_email_threads, email_selected_thread)

            if thread_found is False:
                # Return an error if the selected thread number is not found
                return_error(f'The selected Thread Number to respond to ({email_selected_thread}) '
                             f'does not exist.  Please choose a valid Thread Number and re-try.')

            if outbound_only is True:
                # If this thread does not contain any inbound messages, then this is an update to the original
                # first-contact message and must be sent as a new email message.
                result = resend_first_contact(email_selected_thread, incident_email_threads[last_thread_processed],
                                              incident_id, new_email_attachments, files, new_email_body, add_cc,
                                              add_bcc, service_mail, mail_sender_instance, new_attachment_names,
                                              subject_include_incident_id)

                # Clear fields for re-use
                reset_fields()

                return_results(result)

                first_contact_resent = True

        if first_contact_resent is False:
            # Strip service mail address(es) from reply recipients list
            final_reply_recipients = get_email_recipients(reply_recipients, service_mail, service_mail, reply_mailbox)

            # Verify a message ID to reply to was identified
            if not reply_to_message_id:
                return_error('Unable to identify an email message ID to reply to - reply not sent!')

            # Combine CC and BCC addresses already on the thread with new ones set in fields
            final_email_cc = get_email_cc(thread_cc, add_cc)
            final_email_bcc = get_email_cc(thread_bcc, add_bcc)

            # Get a list of entry ID's for attachments that were fetched as files
            entry_id_list = get_entry_id_list(incident_id, [], new_email_attachments, files)

            # Format any markdown in the email body as HTML
            reply_html_body = format_body(new_email_body)

            # Trim "Re:" from subject since the reply-mail command in both EWS and Gmail adds it again
            reply_subject = reply_subject.lstrip("Re: ")

            # Send the email reply
            result = validate_email_sent(incident_id, reply_subject, subject_include_incident_id,
                                         final_reply_recipients, new_email_body, service_mail, final_email_cc,
                                         final_email_bcc, reply_html_body, entry_id_list, reply_to_message_id,
                                         reply_code, mail_sender_instance)
            return_results(result)

            if subject_include_incident_id and f'[{incident_id}]' not in reply_subject:
                reply_subject = f'[{incident_id}] ${reply_subject}'

            if f'<{reply_code}' not in reply_subject:
                subject_with_id = f"<{reply_code}> {reply_subject}"
            else:
                subject_with_id = reply_subject

            # Store message details in context entry
            reply_html_body = append_email_signature(reply_html_body)
            create_thread_context(reply_code, final_email_cc, final_email_bcc, new_email_body, service_mail,
                                  reply_html_body, '', '', service_mail, subject_with_id, final_reply_recipients,
                                  incident_id, new_attachment_names)

            # Clear fields for re-use
            reset_fields()

    except Exception as error:
        return_error(f"Failed to send email via new_thread = 'false' branch. Reason: {error}")

    return True


def main():
    args = demisto.args()
    incident = demisto.incident()
    incident_id = incident.get('id')
    custom_fields = incident.get('CustomFields')
    labels = incident.get('labels', [])
    # The mailbox configured in the relevant integration
    mailbox = custom_fields.get('emailreceived') or get_mailbox_from_incident_labels(labels)
    email_subject = custom_fields.get('emailsubject')
    email_cc = custom_fields.get('emailcc', '')
    add_cc = custom_fields.get('addcctoemail', '')
    add_bcc = custom_fields.get('addbcctoemail', '')
    service_mail = args.get('service_mail', '')
    email_from = custom_fields.get('emailfrom', '')
    email_to = custom_fields.get('emailto', '')
    email_latest_message = custom_fields.get('emaillatestmessage')
    email_code = custom_fields.get('emailgeneratedcode')  # single code field for 'Email Communication' types
    email_codes = custom_fields.get('emailgeneratedcodes')  # multi-code field for other incident types
    email_to_str = get_email_recipients(email_to, email_from, service_mail, mailbox)
    files = args.get('files', {})
    attachments = argToList(args.get('attachment', []))
    new_email_attachments = custom_fields.get('emailnewattachment', {})
    notes = demisto.executeCommand("getEntries", {'filter': {'categories': ['notes']}})
    mail_sender_instance = args.get('mail_sender_instance', None)
    new_thread = args.get('new_thread')
    new_email_recipients = custom_fields.get('emailnewrecipients')
    new_email_subject = custom_fields.get('emailnewsubject')
    new_email_body = custom_fields.get('emailnewbody')
    email_selected_thread = custom_fields.get('emailselectedthread')
    subject_include_incident_id = argToBoolean(args.get('subject_include_incident_id', False))

    argToBoolean(args.get('reputation_calc_async', False))

    if new_email_attachments:
        new_attachment_names = ', '.join([attachment.get('name', '') for attachment in new_email_attachments])
    else:
        new_attachment_names = 'None'

    if new_thread == 'n/a':
        # This case is run when replying to an email from the 'Email Communication' layout
        single_thread_reply(email_code, incident_id, email_cc, add_cc, notes, attachments, files, email_subject,
                            subject_include_incident_id, email_to_str, service_mail, email_latest_message,
                            mail_sender_instance, reputation_calc_async=False)

    elif new_thread == 'true':
        # This case is run when using the 'Email Threads' layout to send a new first-contact email message
        multi_thread_new(new_email_subject, subject_include_incident_id, new_email_recipients, new_email_body,
                         incident_id, email_codes, new_email_attachments, files, service_mail, add_cc, add_bcc,
                         mail_sender_instance, new_attachment_names)

    elif new_thread == 'false':
        # This case is run when using the 'Email Threads' layout to reply to an existing email thread
        multi_thread_reply(new_email_body, incident_id, email_selected_thread, new_email_attachments, files, add_cc,
                           add_bcc, service_mail, mail_sender_instance, new_attachment_names,
                           subject_include_incident_id)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
