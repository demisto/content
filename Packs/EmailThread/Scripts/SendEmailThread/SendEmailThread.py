import json
import re
import datetime
from CommonServerPython import is_error, get_error, argToList, return_error, DemistoException
import demistomock as demisto

ERROR_TEMPLATE = 'ERROR: SendEmailReply - {function_name}: {reason}'

def current_time():
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")


# Remove [.] characters in email subject to make it suitable for context key
def generate_email_topic(email_subject):
    email_topic = email_subject.replace(".","[dot]").replace(" ","_") if email_subject \
        else ""
    return email_topic


def store_topics(email_subject, email_to, email_content, email_cc=None, email_team=None, email_bcc=None, message_id=None):
    """
    Collect the updated email fields and store in the context key EmailCommunication as metadata
    Args:
        email_subject: The email subject
        email_to: The email to fields value from the replied email from user
        email_content: The email content
        email_team : The team (group) of multiple email addresses
        email_cc: The email CC
        email_bcc: The email CC
        message_id: The message id that can be used to reply-mail
    """

    inc = demisto.incidents()[0]['CustomFields']
    email_topics = []
    if "emailtopicslist" in inc:
        email_topics = inc.get('emailtopicslist')

    if email_subject not in email_topics:
        email_topics.append(email_subject)

    topic = {
        "to": email_to,
        "cc": email_cc,
        "subject": email_subject,
        "content": email_content,
        "team": email_team,
        "bcc": email_bcc,
        "message_id": message_id
    }

    demisto.executeCommand("setIncident", {"emailtopicslist": email_topics})
    demisto.executeCommand("Set", {"key": "EmailCommunication." + generate_email_topic(email_subject),"value": topic})
    return email_topics
    

def validate_email_sent(incident_id, email_subject, email_to, reply_body, email_cc, reply_html_body,
                        entry_id_list, email_latest_message, integration_name, email_bcc, email_brand):
    """
    Validate that the email was actually sent, returns an error string if it wasn't sent successfully.

    Args:
        incident_id: The incident ID.
        email_subject: The email subject.
        email_to: The email's recipients.
        reply_body: The email body.
        email_cc: The email cc.
        reply_html_body: The email html body.
        entry_id_list: The files entry ids list.
        email_latest_message: The latest message ID in the email thread to reply to.

    Returns:
        str: a message which indicates that the mail was sent successfully or an error message.
    """
    email_reply = execute_reply_mail(incident_id, email_subject, email_to, reply_body, email_cc,
                                     reply_html_body, entry_id_list, email_latest_message, 
                                     integration_name, email_bcc, email_brand)

    if is_error(email_reply):
        return f'Error:\n {get_error(email_reply)}'

    return f'Mail sent successfully to {email_to}'


def execute_reply_mail(incident_id, email_subject, email_to, reply_body, email_cc, reply_html_body,
                       entry_id_list, email_latest_message, integration_name, email_bcc, email_brand):
    """
    Args:
        incident_id: The incident ID.
        email_subject: The email subject.
        email_to: The email's recipients.
        reply_body: The email body.
        email_cc: The email cc.
        reply_html_body: The email html body.
        entry_id_list: The files entry ids list.
        email_latest_message: The latest message ID in the email thread to reply to.
        integration_name: Name of the integration instance to send mail
        email_bcc: The email bcc
        email_brand: The integration type to choose to send-mail or reply-mail
    """
    # When replying to an old email
    if f"#{incident_id}" in email_subject:
        mail_content = {
            "to": email_to,
            "inReplyTo": email_latest_message,
            "subject": email_subject,
            "cc": email_cc,
            "bcc": email_bcc,
            "htmlBody": reply_html_body,
            "body": reply_body,
            "attachIDs": ",".join(entry_id_list),
            "using": integration_name
        }
        demisto.executeCommand("setEntriesTags", {"entryIDs":",".join(entry_id_list),"entryTags": generate_email_topic(email_subject)})
    
    # When sending new email
    else:
        mail_content = {
            "to": email_to,
            "inReplyTo": email_latest_message,
            "subject": f"[SOC #{incident_id}] {email_subject}",
            "cc": email_cc,
            "bcc": email_bcc,
            "htmlBody": reply_html_body,
            "body": reply_body,
            "attachIDs": ",".join(entry_id_list),
            "using": integration_name
        }
        demisto.executeCommand("setEntriesTags", {"entryIDs":",".join(entry_id_list),"entryTags": generate_email_topic(email_subject)})
    if not email_latest_message or email_brand in ["EWSO365", "Mail Sender (New)"]:
        return demisto.executeCommand("send-mail", mail_content)
    else:
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


def get_reply_body(attachments, email_body):
    """ Convert the email body to HTML
    Args:
        attachments (list): The email's attachments.
        email_body (str): The email's body in markdown
    Returns:
        The reply body and the html body
    """
    reply_body = email_body

    if isinstance(attachments, str):
        attachments = argToList(attachments)
    
    try:
        res = demisto.executeCommand("mdToHtml", {"contextKey": "replyhtmlbody", "text": reply_body})
        reply_html_body = res[0]['EntryContext']['replyhtmlbody']
        return reply_body, reply_html_body
    except Exception:
        return_error(get_error(res))


def add_entries(email_reply, email_related_incident, email_topic, email_from, email_to, email_cc, email_bcc):
    """Add the entries to the related incident
    Args:
        email_reply: The email reply.
        email_related_incident: The related incident.
        email_topic: The email topic.
        email_from: The email from.
        email_to: The email to.
        email_bcc: The email bcc
    Returns:
        email_thread: the email thread with From, Sent, To, Subject and HTML body.

    """
    topic = email_topic.replace(" ","_").replace(".","[dot]")
    # Prepare email thread format header and content
    email_thread = f'<p><b>From: </b> {email_from} <br>' \
    + "<b>Sent: </b>" + current_time() + "<br>" \
    + f"<b>To: </b> {email_to} <br>"
    if email_cc: email_thread += f"<b>CC: </b> {email_cc} <br>"
    if email_bcc: email_thread += f"<b>BCC: </b> {email_bcc} <br>"
    email_thread += f"<b>Subject: </b> {email_topic} <br></p>" + email_reply
    # Add to war room entry
    entries_str = json.dumps(
        [{"Type": 1, "ContentsFormat": 'html', "Contents": email_thread, "tags": [topic]}])

    res = demisto.executeCommand("addEntries", {"entries": entries_str, 'id': email_related_incident})

    if is_error(res):
        demisto.error(ERROR_TEMPLATE.format('addEntries', res[0]['Contents']))
        raise DemistoException(ERROR_TEMPLATE.format('addEntries', res[0]['Contents']))
    
    return email_thread


def create_reply_email(email_reply, original_email):
    """
    Add <blockquote> tag to old email to create email thread content
    """
    if original_email != '':
        new_reply = "<p>" + re.findall("(?<=<p>)[\w\W]*(?=<\/p>)",email_reply)[0] + "</p>"
        reply_html = f'{new_reply} \
        <blockquote style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex;">{original_email} \
        </blockquote>'
        return re.sub('>\W+<','><',reply_html)
    else:
        return re.sub('>\W+<','><',email_reply)


def get_email_from(integration_name):
    """
    Get the configured email address from integration instance to use 
    as email_from field when email is sent from XSOAR
    """
    contents = demisto.executeCommand("demisto-api-post", {
            "uri":"/settings/integration/search",
            "body": {"size":1}
        })[0]['Contents']

    if contents:
        for content in contents.get('response').get('instances'):
            if content.get('name') == integration_name and content.get('enabled') == "true":
                if content.get('brand') == 'EWS Mail Sender':
                    email_from = content.get('configvalues').get('mailbox')
                elif content.get('brand') in ['EWSO365', 'EWSO365DeviceCodeFlow']:
                    email_from = content.get('configvalues').get('default_target_mailbox')
                elif content.get('brand') == 'Mail Sender (New)':
                    email_from = content.get('configvalues').get('from')
                else:
                    email_from = ''
                brand = content.get('brand')
                break
        return email_from, brand
    else:
        return '', ''


def check_valid_args(args):
    message = ""
    if not args.get('email_to'):
        message = "ERROR: Email To is missing!"
        demisto.executeCommand('setIncident',
            {
                'customFields': {
                    'emailto': message
                }
            })
    if not args.get('email_subject'):
        message = "ERROR: Email Subject is missing!"
        demisto.executeCommand('setIncident',
            {
                'customFields': {
                    'emailsubject': message
                }
            })
    if not (args.get('email_body') or args.get('email_body_html')):
        message = "ERROR: Email Body is missing!"
        demisto.executeCommand('setIncident',
            {
                'customFields': {
                    'emaileditor': message
                }
            })

    return message


def main():
    incident = demisto.incident()
    ctx = demisto.context()
    incident_id = incident.get('id')
    custom_fields = incident.get('CustomFields')
    args = demisto.args()
    integration_name = args.get('integration_name')
    email_body_html = ''
    # Check if user put email_to, subject and body
    check_args = check_valid_args(args)
    if check_args != "":
        return_error(check_args)
        return
    # Get email send params from arguments when using the script in playbook
    if args.get('email_subject') and args.get('email_to') and (args.get('email_body') or args.get('email_body_html')):
        email_to = args.get('email_to')
        email_cc = args.get('email_cc')
        email_bcc = args.get('email_bcc')
        email_subject = args.get('email_subject')
        email_body = args.get('email_body')
        email_body_html = args.get('email_body_html')
    # Get email send params from incident fields when using the script in layout button
    else:
        email_to = custom_fields.get('emailto','')
        email_cc = custom_fields.get('emailcc', '')
        email_bcc = custom_fields.get('emailbcc', '')
        email_subject = custom_fields.get('emailsubject')
        email_body = custom_fields.get('emaileditor')

    
    add_cc = custom_fields.get('addcctoemail', '')
    email_team = custom_fields.get('emailteam','')
    email_from, email_brand = get_email_from(integration_name)
    email_latest_message = custom_fields.get('emaillatestmessage')
    files = args.get('files', {})
    attachments = argToList(args.get('attachment', []))
    emails = [{'Contents':''}]

    # Get the last email in War room
    email_topic = custom_fields.get('emailtopic','email_subject')
    selected_topic = generate_email_topic(email_topic)
    # Condition to check when user creates a new topic while still select another topic in
    # the emailtopic field
    if email_topic and email_subject == email_topic:
        emails = demisto.executeCommand("getEntries", {'filter': {'tags': [selected_topic]}})

    # Get message ID if available
    if "EmailCommunication" in ctx:
        if selected_topic in ctx.get('EmailCommunication'):
            email_latest_message = ctx.get('EmailCommunication').get(selected_topic).get('message_id')
    
    final_email_cc = get_email_cc(email_cc, add_cc) # Get email CC information

    # Get email body from email editor md field
    if email_body and not email_body_html:
        reply_body, reply_html_body = get_reply_body(attachments, email_body)
    elif email_body_html:
        reply_body = reply_html_body = email_body_html

    final_email_reply = create_reply_email(reply_html_body, emails[-1]['Contents']) # Generate full HTML reply with reply and recent email thread
    entry_id_list = get_entry_id_list(incident_id, attachments, files)

    # Send email
    result = validate_email_sent(incident_id, email_subject, email_to, reply_body, final_email_cc,
                                     final_email_reply, entry_id_list, email_latest_message, 
                                     integration_name, email_bcc, email_brand)
    demisto.results(result)

    # Add new reply email to War room. The task will return a thread content after user reply
    thread_reply = add_entries(final_email_reply, incident_id, email_subject, email_from, email_to, email_cc, email_bcc)

    # Store email information to context
    store_topics(email_subject, email_to, thread_reply, email_cc, email_team, email_bcc, email_latest_message)

    # Present latest email to layout and store the latest email entry ID for the next search
    title_html = "<h2>" + email_subject + "</h2><br>"
    demisto.executeCommand('setIncident',
        {
            'id': incident_id,
            'customFields': {
                'emailthreadhtml': title_html + thread_reply,
                'emailtopic': email_subject,
                'emailsubject': email_subject,
                'emaileditor': '',
                'emailfrom': email_from
            }
        }),


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()