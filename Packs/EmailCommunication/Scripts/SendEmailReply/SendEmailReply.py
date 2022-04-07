from CommonServerPython import *
import json


def validate_email_sent(incident_id, email_subject, email_to, reply_body, service_mail, email_cc, reply_html_body,
                        entry_id_list, email_latest_message, email_code):
    """
    Validate that the email was actually sent, returns an error string if it wasn't sent successfully.

    Args:
        incident_id: The incident ID.
        email_subject: The email subject.
        email_to: The email's recipients.
        reply_body: The email body.
        service_mail: The service mail (mail listener).
        email_cc: The email cc.
        reply_html_body: The email html body.
        entry_id_list: The files entry ids list.
        email_latest_message: The latest message ID in the email thread to reply to.
        email_code: The random code that was generated when the incident was created.

    Returns:
        str: a message which indicates that the mail was sent successfully or an error message.
    """
    email_reply = execute_reply_mail(incident_id, email_subject, email_to, reply_body, service_mail, email_cc,
                                     reply_html_body, entry_id_list, email_latest_message, email_code)

    if is_error(email_reply):
        return f'Error:\n {get_error(email_reply)}'

    return f'Mail sent successfully to {email_to}'


def execute_reply_mail(incident_id, email_subject, email_to, reply_body, service_mail, email_cc, reply_html_body,
                       entry_id_list, email_latest_message, email_code):
    if f'<{email_code}' not in email_subject:
        subject_with_id = f"<{email_code}> {email_subject}"

        # setting the email's subject for gmail adjustments
        try:
            demisto.executeCommand('setIncident',
                                   {'id': incident_id, 'customFields': {'emailsubject': f'{subject_with_id}'}})
        except Exception:
            demisto.debug(f'SetIncident Failed.'
                          f'"emailsubject" field was not updated with {subject_with_id} value '
                          f'for incident: {incident_id}')
    else:
        subject_with_id = email_subject

    mail_content = {
        "to": email_to,
        "inReplyTo": email_latest_message,
        "subject": subject_with_id,
        "cc": email_cc,
        "htmlBody": reply_html_body,
        "body": reply_body,
        "attachIDs": ",".join(entry_id_list),
        "replyTo": service_mail,
    }
    return demisto.executeCommand("reply-mail", mail_content)


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


def get_entry_id_list(incident_id, attachments, files):
    """Get the email attachments and create entry id list.
    Args:
        incident_id (str): The incident id.
        attachments (list): The attachments of the email.
        files (list): The uploaded files in the context.
    Returns:
        list. Attachments entries ids list.
    """
    entry_id_list = []
    if attachments and files:
        for attachment in attachments:
            attachment_name = attachment.get('name', '')
            file_data = create_file_data_json(attachment)
            demisto.executeCommand("demisto-api-post", {"uri": f"/incident/remove/{incident_id}", "body": file_data})
            if not isinstance(files, list):
                files = [files]
            for file in files:
                if attachment_name == file.get('Name'):
                    entry_id_list.append(file.get('EntryID'))

    return entry_id_list


def create_file_data_json(attachment):
    """Get attachment and create a json with its data.
    Args:
        attachment (dict): The attachments of the email.
    Returns:
        dict. Attachment data.
    """
    attachment_name = attachment['name']
    attachment_path = attachment['path']
    attachment_type = attachment['type']
    attachment_media_file = attachment['showMediaFile']
    attachment_description = attachment['description']
    file_data = {
        "fieldName": "attachment",
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


def get_reply_body(notes, incident_id, attachments):
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
            entry_tags_res = demisto.executeCommand("addEntries", {"entries": entry_note, 'id': incident_id})

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
    for label in labels:
        if label.get('type') == 'Mailbox':
            return label.get('value')
    return None


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
    service_mail = args.get('service_mail', '')
    email_from = custom_fields.get('emailfrom')
    email_to = custom_fields.get('emailto')
    email_latest_message = custom_fields.get('emaillatestmessage')
    email_code = custom_fields.get('emailgeneratedcode')
    email_to_str = get_email_recipients(email_to, email_from, service_mail, mailbox)
    files = args.get('files', {})
    attachments = argToList(args.get('attachment', []))
    notes = demisto.executeCommand("getEntries", {'filter': {'categories': ['notes']}})

    try:
        final_email_cc = get_email_cc(email_cc, add_cc)
        reply_body, reply_html_body = get_reply_body(notes, incident_id, attachments)
        entry_id_list = get_entry_id_list(incident_id, attachments, files)
        result = validate_email_sent(incident_id, email_subject, email_to_str, reply_body, service_mail, final_email_cc,
                                     reply_html_body, entry_id_list, email_latest_message, email_code)
        demisto.results(result)
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
