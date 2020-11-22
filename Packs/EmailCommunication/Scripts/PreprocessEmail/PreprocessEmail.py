import demistomock as demisto
from CommonServerPython import *
import json
import re

ERROR_TEMPLATE = 'ERROR: PreprocessEmail - {function_name}: {reason}'
QUOTE_MARKERS = ['<div class="gmail_quote">',
                 '<hr tabindex="-1" style="display:inline-block; width:98%"><div id="divRplyFwdMsg"']


def create_email_html(email_html='', entry_id_list=None):
    """Modify the email's html body to use entry IDs instead of CIDs and remove the original message body if exists.
    Args:
        email_html (str): The attachments of the email.
        entry_id_list (list): The files entry ids list.
    Returns:
        str. Email Html.
    """

    # Removing the conversation's history
    for marker in QUOTE_MARKERS:
        index = email_html.find(marker)
        if index != -1:
            email_html = f'{email_html[:index]}</body></html>'

    # Replacing the images' sources
    for image_name, image_entry_id in entry_id_list:
        email_html = re.sub(f'src="[^>]+"(?=[^>]+alt="{image_name}")', f'src=entry/download/{image_entry_id}',
                            email_html)
    return email_html


def get_entry_id_list(attachments, files):
    """Get the entry ids for the email attachments from the email's related incident's files entry.
    Args:
        attachments (list): The attachments of the email.
        files (list): The uploaded files in the context of the related incident.
    Returns:
        list of tuples. (attachment_name, file_entry_id).
    """
    if not (attachments and files):
        return []

    entry_id_list = []
    files = [files] if not isinstance(files, list) else files
    for attachment in attachments:
        attachment_name = attachment.get('name', '')
        for file in files:
            if attachment_name == file.get('Name'):
                entry_id_list.append((attachment_name, file.get('EntryID')))

    return entry_id_list


def add_entries(email_reply, email_related_incident):
    """Add the entries to the related incident
    Args:
        email_reply: The email reply.
        email_related_incident: The related incident.
    """
    entries_str = json.dumps(
        [{"Type": 1, "ContentsFormat": 'html', "Contents": email_reply, "tags": ['email-thread']}])
    res = demisto.executeCommand("addEntries", {"entries": entries_str, 'id': email_related_incident})
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
    Get incident id and return it's details.
    Args:
        query: Query for the incident id.
    Returns:
        dict. Incident details.
    """
    res = demisto.executeCommand("GetIncidentsByQuery", {"query": query, "Contents": "id,status"})[0]

    if is_error(res):
        demisto.results(ERROR_TEMPLATE.format('GetIncidentsByQuery', res['Contents']))
        raise DemistoException(ERROR_TEMPLATE.format('GetIncidentsByQuery', res['Contents']))

    incident_details = json.loads(res['Contents'])[0]
    return incident_details


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


def get_attachments_using_instance(email_related_incident, labels):
    """Use the instance from which the email was received to fetch the attachments.
        Only supported with: EWS V2, Gmail

    Args:
        email_related_incident (str): ID of the incident to attach the files to.
        labels (Dict): Incidnet's labels to fetch the relevant data from.

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

    if integration_name == 'EWS v2':
        demisto.executeCommand("executeCommandAt",
                               {'command': 'ews-get-attachment', 'incidents': email_related_incident,
                                'arguments': {'item-id': str(message_id), 'using': instance_name}})

    elif integration_name == 'Gmail':
        demisto.executeCommand("executeCommandAt",
                               {'command': 'gmail-get-attachments', 'incidents': email_related_incident,
                                'arguments': {'user-id': 'me', 'message-id': str(message_id), 'using': instance_name}})

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
        demisto.executeCommand('setIncident', {'id': incident_id, 'customFields': {'emaillatestmessage': item_id}})
    except Exception:
        demisto.debug(f'SetIncident Failed.'
                      f'"emaillatestmessage" field was not updated with {item_id} value for incident: {incident_id}')


def main():
    incident = demisto.incident()
    custom_fields = incident.get('CustomFields')
    email_from = custom_fields.get('emailfrom')
    email_cc = custom_fields.get('emailcc')
    email_to = custom_fields.get('emailto')
    email_subject = custom_fields.get('emailsubject')
    email_html = custom_fields.get('emailhtml')
    attachments = incident.get('attachment', [])
    email_latest_message = custom_fields.get('emaillatestmessage')

    try:
        email_related_incident = email_subject.split('#')[1].split()[0]
        update_latest_message_field(email_related_incident, email_latest_message)
        query = f"id:{email_related_incident}"
        incident_details = get_incident_by_query(query)
        check_incident_status(incident_details, email_related_incident)
        get_attachments_using_instance(email_related_incident, incident.get('labels'))

        # Adding a 5 seconds sleep in order to wait for all the attachments to get uploaded to the server.
        time.sleep(5)
        files = get_incident_related_files(email_related_incident)
        entry_id_list = get_entry_id_list(attachments, files)
        html_body = create_email_html(email_html, entry_id_list)

        email_reply = set_email_reply(email_from, email_to, email_cc, html_body, attachments)
        add_entries(email_reply, email_related_incident)
        # False - to not create new incident
        demisto.results(False)

    except (IndexError, ValueError, DemistoException) as e:
        # True - For creating new incident
        demisto.results(True)
        return_error(f"The PreprocessEmail script has encountered an error:\n {e} \nA new incidents was created.")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
