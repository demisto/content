import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


def create_html_with_images(email_html='', entry_id_list=None):
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


# for backwards compatible
def get_entry_id_list_by_incident_attachments(attachments, files):
    """Get the incident attachments and create entry id list.
    Args:
        attachments (list): The incident attachments.
        files (list): The uploaded files in the context.
    Returns:
        list. Attachments entries ids list.
    """
    if not (attachments and files):
        return []

    entry_id_list = []
    for attachment in attachments:
        attachment_name = attachment.get('name', '')
        if attachment_name and not attachment_name.endswith('eml'):
            for file in files:
                if attachment_name == file.get('Name'):
                    entry_id_list.append((attachment_name, file.get('EntryID')))
    demisto.info(f'\n\n idlist by incident attachments \n\n{entry_id_list}')
    return entry_id_list


def get_entry_id_list_by_parsed_email_attachments(attachments, files):
    """Get the email attachments and create entry id list.
    Args:
        attachments (list): The parsed email attachments.
        files (list): The uploaded files in the context.
    Returns:
        list. Attachments entries ids list.
    """
    if not (attachments and files):
        return []

    entry_id_list = []
    for attachment in attachments:
        attachment_name = attachment.get('Name', '')
        for file in files:
            if attachment_name == file.get('Name'):
                entry_id_list.append((attachment_name, file.get('EntryID')))
    demisto.info(f'\n\n idlist by parsed email attachments\n\n{entry_id_list}')
    return entry_id_list


def main(args):
    incident = demisto.incident()
    custom_fields = incident.get('CustomFields', {})
    html_body = custom_fields.get('emailhtml', '') or \
        custom_fields.get('emailbody', '')
    files = demisto.context().get('File', [])
    files = [files] if not isinstance(files, list) else files
    html_body = f'<div style="background-color: white; color:black;"> {html_body} </div>\n'
    if 'src="cid' in html_body:
        attachments = incident.get('attachment', {})
        entry_id_list = get_entry_id_list_by_incident_attachments(attachments, files)
        if not entry_id_list:
            attachments = demisto.get(demisto.context(), 'Email.AttachmentsData', [])
            entry_id_list = get_entry_id_list_by_parsed_email_attachments(attachments, files)
        html_body = create_html_with_images(html_body, entry_id_list)

    return_results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html_body,
    })


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main(demisto.args())
