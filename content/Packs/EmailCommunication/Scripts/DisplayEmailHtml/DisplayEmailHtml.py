import json
import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_email_html(email_html='', entry_id_list=None):
    for entry_id in entry_id_list:
        email_html = re.sub(f'src="[^>]+"(?=[^>]+alt="{entry_id[0]}")', f'src=entry/download/{entry_id[1]} ', email_html)
    return email_html


def get_entry_id_list(attachments, files):
    """Get the email attachments and create entry id list.
    Args:
        attachments (list): The attachments of the email.
        files (list): The uploaded files in the context.
    Returns:
        list. Attachments entries ids list.
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
    demisto.info(f'\n\n idlist \n\n{entry_id_list}')
    return entry_id_list


def add_entries(single_reply, incident_id):
    """Add the entries to the related incident
    Args:
        single_reply: The email reply.
        email_related_incident: The related incident.
    """
    entries_str = json.dumps(
        [{"Type": 1, "ContentsFormat": 'html', "Contents": single_reply, "tags": ['email-thread']}])
    res = demisto.executeCommand("addEntries", {"entries": entries_str, 'id': incident_id})
    if is_error(res):
        demisto.error(f"ERROR: PreprocessEmail - addEntries: {res['Contents']}")
        raise DemistoException(f"ERROR: PreprocessEmail - addEntries: {res['Contents']}")


def set_email_reply(email_from, email_to, email_cc, email_subject, html_body, attachments):
    """Set the email reply from the given details.
    Args:
        email_from: The email author mail.
        email_to: The email recipients.
        email_cc: The email cc.
        html_body: The email HTML body.
    Returns:
        str. Email reply.
    """
    single_reply = f"""
    From: {email_from}
    To: {email_to}
    CC: {email_cc}
    Subject: {email_subject}
    """
    if attachments:
        attachment_names = [attachment.get('name', '') for attachment in attachments]
        single_reply += f'Attachments: {attachment_names}\n'

    single_reply += f'\n{html_body}\n'

    return single_reply


args = demisto.args()
incident = demisto.incidents()[0]
incident_id = incident.get('id')
custom_fields = incident.get('CustomFields', {})
email_body = custom_fields.get('emailbody')
email_from = custom_fields.get('emailfrom')
email_cc = custom_fields.get('emailcc')
email_to = custom_fields.get('emailto')
email_subject = custom_fields.get('emailsubject')
email_html = custom_fields.get('emailhtml')
email_html_image = custom_fields.get('emailhtmlimage')
attachments = incident.get('attachment', {})
files = demisto.context().get('File', [])

if not email_html_image or 'src="cid' in email_html_image:
    if 'src="cid' in email_html:
        entry_id_list = get_entry_id_list(attachments, files)
        html_body = create_email_html(email_html, entry_id_list)
        email_reply = set_email_reply(email_from, email_to, email_cc, email_subject, html_body, attachments)
        demisto.executeCommand("setIncident", {'customFields': {"emailhtmlimage": email_reply}})
        demisto.results({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': email_reply})

    else:
        email_reply = set_email_reply(email_from, email_to, email_cc, email_subject, email_html, attachments)
        demisto.results({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': email_reply})

else:
    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': email_html_image})
