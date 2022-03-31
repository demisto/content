import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_email_html(email_html='', entry_id_list=None):
    if not entry_id_list:
        return email_html

    account_name = get_tenant_account_name()

    for entry_id in entry_id_list:
        # Handling inline attachments from Gmail mailboxes
        if re.search(f'src="[^>]+"(?=[^>]+alt="{entry_id[0]}")', email_html):
            email_html = re.sub(f'src="[^>]+"(?=[^>]+alt="{entry_id[0]}")',
                                f'src={account_name}/entry/download/{entry_id[1]}',
                                email_html
                                )
        # Handling inline attachments from Outlook mailboxes
        # Note: when tested, entry id list and inline attachments were in the same order, so there was no need in
        # special validation that the right src was being replaced.
        else:
            email_html = re.sub('(src="cid(.*?"))',
                                f'src={account_name}/entry/download/{entry_id[1]}',
                                email_html, count=1,
                                )
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


def main(args):
    incident = demisto.incident()
    custom_fields = incident.get('CustomFields', {})
    email_from = custom_fields.get('emailfrom')
    email_cc = custom_fields.get('emailcc')
    email_to = custom_fields.get('emailto')
    email_subject = custom_fields.get('emailsubject')
    email_html = custom_fields.get('emailhtml', '')
    email_html_image = custom_fields.get('emailhtmlimage')
    attachments = incident.get('attachment', {})
    files = demisto.context().get('File', [])

    if not email_html_image or 'src="cid' in email_html_image:
        if 'src="cid' in email_html:
            entry_id_list = get_entry_id_list(attachments, files)
            html_body = create_email_html(email_html, entry_id_list)
            email_reply = set_email_reply(email_from, email_to, email_cc, email_subject, html_body, attachments)
            demisto.executeCommand("setIncident", {'customFields': {"emailhtmlimage": email_reply}})
            return_results({
                'ContentsFormat': formats['html'],
                'Type': entryTypes['note'],
                'Contents': email_reply,
            })

        else:
            email_reply = set_email_reply(email_from, email_to, email_cc, email_subject, email_html, attachments)
            return_results({
                'ContentsFormat': formats['html'],
                'Type': entryTypes['note'],
                'Contents': email_reply})

    else:
        return_results({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': email_html_image})


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main(demisto.args())
