import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import re
import random
from datetime import datetime as dt

ERROR_TEMPLATE = 'ERROR: PreprocessEmail - {function_name}: {reason}'

# List of strings that mail clients use to separate new message content from previous thread messages when replying
QUOTE_MARKERS = ['<div class="gmail_quote">',
                 '<hr tabindex="-1" style="display:inline-block; width:98%"><div id="divRplyFwdMsg"',
                 '<hr style="display:inline-block;width:98%" tabindex="-1"><div id="divRplyFwdMsg"']


def get_utc_now():
    """ A wrapper function for datetime.utcnow
    Helps handle tests
    Returns:
        datetime: current UTC time
    """
    return dt.utcnow()


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
        demisto.error('Invalid input for number of days to query in the `XSOAR - Email Communication Days To Query` '
                      'list. Input should be a number only, representing the number of days to query back.\nUsing the '
                      'default query time - 60 days')
        return '60 days'


def remove_html_conversation_history(email_html):
    # Removing the conversation's history
    for marker in QUOTE_MARKERS:
        index = email_html.find(marker)
        if index != -1:
            email_html = f'{email_html[:index]}</body></html>'
    return email_html


def create_email_html(email_html='', entry_id_list=[]):
    """Modify the email's html body to use entry IDs instead of CIDs and remove the original message body if exists.
    Args:
        email_html (str): The attachments of the email.
        entry_id_list (list): The files entry ids list.
    Returns:
        str. Email Html.
    """
    content_id = "None"
    # Replacing the images' sources
    for image_name, image_entry_id in entry_id_list:
        if '-attachmentName-' in image_name:
            content_id = image_name.split('-attachmentName-', 1)[0]
        if re.search(rf'(src="cid:{content_id}")', email_html):
            email_html = re.sub(f'src="cid:{content_id}"', f'src=entry/download/{image_entry_id}',
                                email_html)
        elif re.search(f'src="[^>]+"(?=[^>]+alt="{image_name}")', email_html):
            email_html = re.sub(f'src="[^>]+"(?=[^>]+alt="{image_name}")', f'src=entry/download/{image_entry_id}',
                                email_html)
        # Handling inline attachments from Outlook mailboxes
        # Note: when tested, entry id list and inline attachments were in the same order, so there was no need in
        # special validation that the right src was being replaced.
        else:
            email_html = re.sub('(src="cid(.*?"))', f'src=entry/download/{image_entry_id}', email_html, count=1, )
    return email_html


def get_entry_id_list(attachments, files, email_html):
    """Get the entry ids for the email attachments from the email's related incident's files entry.
    Args:
        attachments (list): The attachments of the email.
        files (list): The uploaded files in the context of the related incident.
        email_html: The most recent message in html format
    Returns:
        list of tuples. (attachment_name, file_entry_id).
    """
    if not (attachments and files):
        return []

    matches = re.findall(r'src="cid:([^"]+)"', email_html) or []
    entry_id_list = []
    files = [files] if not isinstance(files, list) else files
    legacy_name = not any('-attachmentName-' in attachment.get('name') for attachment in attachments)
    for attachment in attachments:
        attachment_name = attachment.get('name', '')
        if not legacy_name:
            if '-attachmentName-' in attachment_name:
                identifier_id = attachment_name.split('-attachmentName-', 1)[0]
                for file in files:
                    file_name = file.get('Name')
                    if attachment_name == file_name and identifier_id in matches:
                        entry_id_list.append((attachment_name, file.get('EntryID')))
        else:
            for file in files:
                if attachment_name == file.get('Name') and attachment.get('description', '') != FileAttachmentType.ATTACHED:
                    entry_id_list.append((attachment_name, file.get('EntryID')))

    return entry_id_list


def add_entries(email_reply, email_related_incident, reputation_calc_async=False):
    """Add the entries to the related incident
    Args:
        email_reply: The email reply.
        email_related_incident: The related incident.
    """
    entries_str = json.dumps([{"Type": 1, "ContentsFormat": 'html', "Contents": email_reply, "tags": ['email-thread']}])
    res = demisto.executeCommand("addEntries", {"entries": entries_str,
                                 'id': email_related_incident, 'reputationCalcAsync': reputation_calc_async})
    if is_error(res):
        demisto.error(ERROR_TEMPLATE.format('addEntries', res['Contents']))
        raise DemistoException(ERROR_TEMPLATE.format('addEntries', res['Contents']))


def set_email_reply(email_from, email_to, email_cc, html_body, attachments):
    """Set the email reply from the given details.
    Args:
        email_from: The email author mail.
        email_to: The email recipients.
        email_cc: The email cc.
        html_body: The email body.
        attachments: The email attachments.

    Returns:
        str. Email reply.

    """
    email_reply = f"""
    From: *{email_from}*
    To: *{email_to}*
    CC: *{email_cc}*

    """
    if attachments:
        attachment_names = [attachment.get('name', '') for attachment in attachments]
        email_reply += f'Attachments: {attachment_names}\n\n'

    email_reply += f'{html_body}\n'

    return email_reply


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
    res = demisto.executeCommand("getIncidents",
                                 {"query": query, "populateFields": "id,status,type,emailsubject"})[0]

    if is_error(res):
        return_results(ERROR_TEMPLATE.format('getIncidents', res['Contents']))
        raise DemistoException(ERROR_TEMPLATE.format('getIncidents', res['Contents']))

    incidents_details = res['Contents']['data']
    if incidents_details is None:
        demisto.debug(f'incident was not found. query: {query}')
        return []

    for inc in incidents_details:
        if inc.get('CustomFields'):
            inc['emailsubject'] = inc.get('CustomFields', {}).get('emailsubject')

    return incidents_details


def check_incident_status(incident_details, email_related_incident):
    """Get the incident details and checks the incident status.
    Args:
        incident_details: The incident details.
        email_related_incident: The related incident.
    """

    status = incident_details.get('status')
    if status == 2:  # closed incident status
        res = demisto.executeCommand("reopenInvestigation", {"id": email_related_incident})
        if is_error(res):
            demisto.error(ERROR_TEMPLATE.format(f'Reopen incident {email_related_incident}', res['Contents']))
            raise DemistoException(ERROR_TEMPLATE.format(f'Reopen incident {email_related_incident}', res['Contents']))


def get_attachments_using_instance(email_related_incident, labels, email_to, identifier_ids=""):
    """Use the instance from which the email was received to fetch the attachments.
        Only supported with: EWS V2, Gmail

    Args:
        email_related_incident (str): ID of the incident to attach the files to.
        labels (Dict): Incident's labels to fetch the relevant data from.
        email_to (str): ID of the user the email is sent to.
    """
    message_id = ''
    instance_name = ''
    integration_name = ''

    for label in labels:
        if label.get('type') == 'Email/ID':
            message_id = label.get('value')
        elif label.get('type') == 'Instance':
            instance_name = label.get('value')
        elif label.get('type') == 'Brand':
            integration_name = label.get('value')

    if integration_name in ['EWS v2', 'EWSO365']:
        demisto.executeCommand("executeCommandAt",
                               {'command': 'ews-get-attachment', 'incidents': email_related_incident,
                                'arguments': {'item-id': str(message_id), 'using': instance_name}})

    elif integration_name in ['Gmail', 'Gmail Single User']:
        demisto.executeCommand("executeCommandAt",
                               {'command': 'gmail-get-attachments', 'incidents': email_related_incident,
                                'arguments': {'user-id': 'me', 'message-id': str(message_id), 'using': instance_name}})

    elif integration_name in ['MicrosoftGraphMail', 'Microsoft Graph Mail Single User']:
        demisto.executeCommand("executeCommandAt",
                               {'command': 'msgraph-mail-get-attachment', 'incidents': email_related_incident,
                                'arguments': {'user_id': email_to, 'message_id': str(message_id), 'using': instance_name}})

    else:
        demisto.debug('Attachments could only be retrieved from EWS v2 or Gmail')


def get_incident_related_files(incident_id):
    """Get the email reply attachments after they were uploaded to the server and saved
    to context of the email reply related incident.

    Args:
        incident_id (str): The ID of the incident whose context we'd like to get.
    """
    try:
        res = demisto.executeCommand("getContext", {'id': incident_id})
        return dict_safe_get(res[0], ['Contents', 'context', 'File'], default_return_value=[])
    except Exception:
        return []


def update_latest_message_field(incident_id, item_id):
    """Update the 'emaillatestmessage' field on the email related incident with the ID of the latest email reply.

    Args:
        incident_id (str): The ID of the incident whose field we'd like to set.
        item_id (str): The email reply ID.
    """
    try:
        demisto.debug(f'update latest message field. incident_id: {incident_id}')
        res = demisto.executeCommand('setIncident',
                                     {'id': incident_id, 'customFields': {'emaillatestmessage': item_id}})
        if is_error(res):
            demisto.error(f'Failed to setIncident. Reason: {get_error(res)}')
            raise DemistoException(f'Failed to setIncident. Reason: {get_error(res)}')
    except Exception:
        demisto.debug(f'SetIncident Failed.'
                      f'"emaillatestmessage" field was not updated with {item_id} value for incident: {incident_id}')


def get_email_related_incident_id(email_related_incident_code, email_original_subject):
    """
    Get the email generated code and the original text subject of an email and return the incident matching to the
    email code and original subject.
    """

    query = f'(emailgeneratedcode:{email_related_incident_code}) ' \
            f'or (emailgeneratedcodes:*{email_related_incident_code}*)'

    incidents_details = get_incident_by_query(query)

    for incident in incidents_details:
        email_subject = incident.get('emailsubject', '')
        if email_subject and email_original_subject in email_subject:
            return str(incident.get('id'))
        else:
            # If 'emailsubject' doesn't match, check 'EmailThreads' context entries
            try:
                incident_context = demisto.executeCommand("getContext", {"id": str(incident.get('id'))})
                incident_email_threads = dict_safe_get(incident_context[0], ['Contents', 'context', 'EmailThreads'])
                if incident_email_threads:
                    if isinstance(incident_email_threads, dict):
                        incident_email_threads = [incident_email_threads]
                    search_result = next((i for i, item in enumerate(incident_email_threads) if
                                          email_original_subject in item["EmailSubject"]), None)
                    if search_result is not None:
                        return str(incident.get('id'))
            except Exception as e:
                demisto.error(f'Exception while retrieving thread context: {e}')
    return None


def get_unique_code():
    """
        Create an 8-digit unique random code that should be used to identify new created incidents.
    Args: None
    Returns:
        8-digit code returned as a string
    """
    code_is_unique = False
    while not code_is_unique:
        code = f'{random.randrange(1, 10 ** 8):08}'
        query = f'(emailgeneratedcode:*{code}*) or (emailgeneratedcodes:*{code}*)'
        incidents_details = get_incident_by_query(query)
        if len(incidents_details) == 0:
            code_is_unique = True
    return code


def create_thread_context(email_code, email_cc, email_bcc, email_text, email_from, email_html, email_latest_message,
                          email_received, email_replyto, email_subject, email_to, incident_id, attachments):
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
        attachments: File attachments from the email
    """
    thread_number = ''
    thread_found = False
    try:
        # Get current email threads from context if any are present
        incident_context = demisto.executeCommand("getContext", {'id': incident_id})
        incident_email_threads = dict_safe_get(incident_context[0], ['Contents', 'context', 'EmailThreads'])

        # Check if there is already a thread for this email code
        if incident_email_threads:
            if isinstance(incident_email_threads, dict):
                incident_email_threads = [incident_email_threads]

            search_result = next(
                (i for i, item in enumerate(incident_email_threads) if item["EmailCommsThreadId"] == email_code), None)
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
            demisto.error('Failed to identify a Thread Number to set. Email not appended to incident context')

        if attachments:
            attachment_names = [attachment.get('name', '') for attachment in attachments]
        else:
            attachment_names = ["None"]

        email_message = {'EmailCommsThreadId': email_code, 'EmailCommsThreadNumber': thread_number, 'EmailCC': email_cc,
                         'EmailBCC': email_bcc, 'EmailBody': email_text, 'EmailFrom': email_from,
                         'EmailHTML': email_html, 'MessageID': email_latest_message, 'EmailReceived': email_received,
                         'EmailReplyTo': email_replyto, 'EmailSubject': email_subject, 'EmailTo': email_to,
                         'EmailAttachments': f'{attachment_names}', 'MessageDirection': 'inbound',
                         'MessageTime': get_utc_now().strftime("%Y-%m-%dT%H:%M:%SUTC")}
        # Add email message to context key
        try:
            demisto.executeCommand('executeCommandAt', {'command': 'Set', 'incidents': incident_id,
                                                        'arguments': {'key': 'EmailThreads', 'value': email_message,
                                                                      'append': 'true'}})
        except Exception as e:
            demisto.error(f"Failed to append new email to context of incident {incident_id}. Reason: {e}")
    except Exception as e:
        demisto.error(f"Unable to add new email message to Incident {incident_id}. Reason: \n {e}")


def main():
    args = demisto.args()
    incident = demisto.incident()
    attachments = incident.get('attachment', [])
    custom_fields = incident.get('CustomFields')
    email_from = custom_fields.get('emailfrom', '')
    email_cc = custom_fields.get('emailcc', '')
    email_bcc = custom_fields.get('emailbcc', '')
    email_to = custom_fields.get('emailto', '')
    email_subject = custom_fields.get('emailsubject', '')
    email_text = custom_fields.get('emailbody', '')
    email_html = custom_fields.get('emailhtml', '')
    email_received = custom_fields.get('emailreceived', '')
    email_replyto = custom_fields.get('emailreplyto', '')
    email_latest_message = custom_fields.get('emaillatestmessage', '')

    reputation_calc_async = argToBoolean(args.get('reputation_calc_async', False))

    try:
        email_related_incident_code = email_subject.split('<')[1].split('>')[0]
        email_original_subject = email_subject.split('<')[-1].split('>')[1].strip()

        email_related_incident = get_email_related_incident_id(email_related_incident_code, email_original_subject)
        update_latest_message_field(email_related_incident, email_latest_message)
        query = f"id:{email_related_incident}"

        incident_details = get_incident_by_query(query)[0]

        check_incident_status(incident_details, email_related_incident)

        email_html = remove_html_conversation_history(email_html)

        get_attachments_using_instance(email_related_incident, incident.get('labels'), email_to)

        # Adding a 5 seconds sleep in order to wait for all the attachments to get uploaded to the server.
        time.sleep(5)
        files = get_incident_related_files(email_related_incident)
        entry_id_list = get_entry_id_list(attachments, files, email_html)
        html_body = create_email_html(email_html, entry_id_list)

        if incident_details['type'] == 'Email Communication':
            # Add new email message as Entry if type is 'Email Communication'
            demisto.debug(
                "Incoming email related to Email Communication Incident"
                f" {email_related_incident}. Appending a message there.")
            email_reply = set_email_reply(email_from, email_to, email_cc, html_body, attachments)
            add_entries(email_reply, email_related_incident, reputation_calc_async)
        else:
            # For all other incident types, add message details as context entry
            demisto.debug(f"Incoming email related to Incident {email_related_incident}.  Appending message there.")
            create_thread_context(email_related_incident_code, email_cc, email_bcc, email_text, email_from, html_body,
                                  email_latest_message, email_received, email_replyto, email_subject, email_to,
                                  email_related_incident, attachments)

        # Return False - tell pre-processing to not create new incident
        return_results(False)

    except (IndexError, ValueError, DemistoException) as e:
        args = demisto.args()

        create_incidents_untagged = argToBoolean(args.get('CreateIncidentUntaggedEmail', True))
        if not create_incidents_untagged and isinstance(e, IndexError):
            # Return False - tell pre-processing not to create a new incident.
            demisto.debug("No incident was created, Reason: CreateIncidentUntaggedEmail is False")
            return_results(False)
        else:
            # Return True - tell pre-processing to create a new incident.
            if isinstance(e, IndexError):
                demisto.debug('No related incident was found. A new incident was created.')
            else:
                demisto.debug(f"A new incident was created. Reason: \n {e}")
            demisto.executeCommand('setIncident',
                                   {'id': incident.get('id'),
                                    'customFields': {'emailgeneratedcode': get_unique_code()}})
            return_results(True)


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
