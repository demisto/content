from typing import Optional, Union

import demistomock as demisto
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import base64
import binascii

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''

CONTEXT_FOLDER_PATH = 'MSGraphMail.Folders(val.ID && val.ID === obj.ID)'
CONTEXT_COPIED_EMAIL = 'MSGraphMail.MovedEmails(val.ID && val.ID === obj.ID)'
CONTEXT_DRAFT_PATH = 'MicrosoftGraph.Draft(val.ID && val.ID == obj.ID)'
CONTEXT_SENT_EMAIL_PATH = 'MicrosoftGraph.Email'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

EMAIL_DATA_MAPPING = {
    'id': 'ID',
    'createdDateTime': 'CreatedTime',
    'lastModifiedDateTime': 'ModifiedTime',
    'receivedDateTime': 'ReceivedTime',
    'sentDateTime': 'SentTime',
    'subject': 'Subject',
    'importance': 'Importance',
    'conversationId': 'ConversationID',
    'isRead': 'IsRead',
    'isDraft': 'IsDraft',
    'internetMessageId': 'MessageID'
}

FOLDER_MAPPING = {
    'id': 'ID',
    'displayName': 'DisplayName',
    'parentFolderId': 'ParentFolderID',
    'childFolderCount': 'ChildFolderCount',
    'unreadItemCount': 'UnreadItemCount',
    'totalItemCount': 'TotalItemCount'
}

# Well known folders shortcut in MS Graph API
# For more information: https://docs.microsoft.com/en-us/graph/api/resources/mailfolder?view=graph-rest-1.0
WELL_KNOWN_FOLDERS = {
    'archive': 'archive',
    'conversation history': 'conversationhistory',
    'deleted items': 'deleteditems',
    'drafts': 'drafts',
    'inbox': 'inbox',
    'junk email': 'junkemail',
    'outbox': 'outbox',
    'sent items': 'sentitems',
}


GLOBAL_PARAMS = None


def parse_folders_list(folders_list):
    if isinstance(folders_list, dict):
        folders_list = [folders_list]

    return [{FOLDER_MAPPING[k]: v for (k, v) in f.items() if k in FOLDER_MAPPING} for f in folders_list]


def build_mail_object(raw_response: Union[dict, list], user_id: str, get_body: bool = False) -> Union[dict, list]:
    """Building mail entry context
    Getting a list from build_mail_object

    Args:
        user_id (str): user id of the mail
        get_body (bool): should get body
        raw_response (dict or list): list of pages

    Returns:
        dict or list: output context
    """

    def build_mail(given_mail: dict) -> dict:
        """

        Args:
            given_mail (dict):

        Returns:
            dict:
        """
        # Dicts
        mail_properties = {
            'ID': 'id',
            'Created': 'createdDateTime',
            'LastModifiedTime': 'lastModifiedDateTime',
            'ReceivedTime': 'receivedDateTime',
            'SendTime': 'sentDateTime',
            'Categories': 'categories',
            'HasAttachments': 'hasAttachments',
            'Subject': 'subject',
            'IsDraft': 'isDraft',
            'Headers': 'internetMessageHeaders',
            'Flag': 'flag',
            'Importance': 'importance',
        }

        contact_properties = {
            'Sender': 'sender',
            'From': 'from',
            'CCRecipients': 'ccRecipients',
            'BCCRecipients': 'bccRecipients',
            'ReplyTo': 'replyTo'
        }

        # Create entry properties
        entry = {k: given_mail.get(v) for k, v in mail_properties.items()}

        # Create contacts properties
        entry.update(
            {k: build_contact(given_mail.get(v)) for k, v in contact_properties.items()}  # type: ignore
        )

        if get_body:
            entry['Body'] = given_mail.get('body', {}).get('content')
        entry['UserID'] = user_id
        return entry

    def build_contact(contacts: Union[dict, list, str]) -> object:
        """Building contact object

        Args:
            contacts (list or dict or str):

        Returns:
            dict or list[dict] or str or None: describing contact
        """
        if contacts:
            if isinstance(contacts, list):
                return [build_contact(contact) for contact in contacts]
            elif isinstance(contacts, dict):
                email = contacts.get('emailAddress')
                if email and isinstance(email, dict):
                    return {
                        'Name': email.get('name'),
                        'Address': email.get('address')
                    }
        return None

    mails_list = list()
    if isinstance(raw_response, list):
        for page in raw_response:
            # raw_response can be a list containing multiple pages or one response
            # if value in page, we got
            value = page.get('value')
            if value:
                for mail in value:
                    mails_list.append(build_mail(mail))
            else:
                mails_list.append(build_mail(page))
    elif isinstance(raw_response, dict):
        return build_mail(raw_response)
    return mails_list


def file_result_creator(raw_response: dict) -> dict:
    """

    Args:
        raw_response (dict):

    Returns:
        dict:

    """
    name = raw_response.get('name')
    data = raw_response.get('contentBytes')
    try:
        data = base64.b64decode(data)  # type: ignore
        return fileResult(name, data)
    except binascii.Error:
        return_error('Attachment could not be decoded')
        return {}  # return_error will exit


class Client:
    def __init__(self, params, args):
        self.params = params
        self.args = args
        self.verify = params
        self.base_url = urljoin(params.get('url', ''), '/msgraphmail/v1.0')
        self.tenant_id = params.get('tenant_id', '1')
        self.auth_and_token_url = params.get('auth_id', '')
        self.self_deployed = params.get('self_deployed', False)
        self.enc_key = params.get('enc_key', '')
        self.app_name = 'ms-graph-mail'
        self.ok_codes = (200, 201, 202, 204)
        self.use_ssl = not params.get('insecure', False)
        self.proxy = params.get('proxy', False)


''' COMMANDS '''


def list_mails_command(client):
    search = client.args.get('search')
    user_id = client.args.get('user_id')
    folder_id = client.args.get('folder_id')
    odata = client.args.get('odata')

    url = f'{client.base_url}/users/{user_id}/messages/'
    if search:
        url += f'?search={search}'

    raw_response = requests.request('GET', url, verify=client.use_ssl)
    raw_response = raw_response.json()
    mail_context = build_mail_object(raw_response, user_id)
    entry_context = {'MSGraphMail(val.ID === obj.ID)': mail_context}

    # human_readable builder
    human_readable = tableToMarkdown(
        f'### Total of {len(mail_context)} of mails received',
        mail_context,
        headers=['Subject', 'From', 'SendTime']
    )
    return_outputs(human_readable, entry_context, raw_response)


def delete_mail_command(client):
    user_id = client.args.get('user_id')
    folder_id = client.args.get('folder_id')
    message_id = client.args.get('message_id')
    human_readable = tableToMarkdown(
        'Message has been deleted successfully',
        {
            'Message ID': message_id,
            'User ID': user_id,
            'Folder ID': folder_id
        },
        headers=['Message ID', 'User ID', 'Folder ID'],
        removeNull=True
    )

    entry_context = {}  # type: ignore

    return_outputs(human_readable, entry_context)


def get_attachment_command(client):
    message_id = client.args.get('message_id')
    user_id = client.args.get('user_id')
    folder_id = client.args.get('folder_id')
    attachment_id = client.args.get('attachment_id')
    url = f'{client.base_url}/users/{user_id}/messages/{message_id}/attachments/{attachment_id}'
    raw_response = requests.request('GET', url, verify=client.use_ssl)
    entry_context = file_result_creator(raw_response.json())
    demisto.results(entry_context)


def get_message_command(client):
    user_id = client.args.get('user_id')
    folder_id = client.args.get('folder_id')
    message_id = client.args.get('message_id')
    get_body = client.args.get('get_body') == 'true'
    odata = client.args.get('odata')
    url = f'{client.base_url}/users/{user_id}/messages/{message_id}/'
    raw_response = requests.request('GET', url, verify=client.use_ssl)
    raw_response = raw_response.json()

    mail_context = build_mail_object(raw_response, user_id=user_id, get_body=get_body)
    entry_context = {'MSGraphMail(val.ID === obj.ID)': mail_context}
    human_readable = tableToMarkdown(
        f'Results for message ID {message_id}',
        mail_context,
        headers=['ID', 'Subject', 'SendTime', 'Sender', 'From', 'HasAttachments', 'Body']
    )
    return_outputs(
        human_readable,
        entry_context,
        raw_response=raw_response
    )


def list_attachments_command(client):
    user_id = client.args.get('user_id')
    message_id = client.args.get('message_id')
    folder_id = client.args.get('folder_id')
    url = f'{client.base_url}/users/{user_id}/messages/{message_id}/attachments/list'
    raw_response = requests.request('GET', url, verify=client.use_ssl)
    raw_response = raw_response.json()
    attachments = raw_response.get('value')
    if attachments:
        attachment_list = [{
            'ID': attachment.get('id'),
            'Name': attachment.get('name'),
            'Type': attachment.get('contentType')
        } for attachment in attachments]
        attachment_entry = {'ID': message_id, 'Attachment': attachment_list, 'UserID': user_id}
        entry_context = {'MSGraphMailAttachment(val.ID === obj.ID)': attachment_entry}

        # Build human readable
        file_names = [attachment.get('Name') for attachment in attachment_list if isinstance(
            attachment, dict) and attachment.get('Name')]
        human_readable = tableToMarkdown(
            f'Total of {len(attachment_list)} attachments found in message {message_id} from user {user_id}',
            {'File names': file_names}
        )
        return_outputs(human_readable, entry_context, raw_response)
    else:
        human_readable = f'### No attachments found in message {message_id}'
        return_outputs(human_readable, dict(), raw_response)


def list_folders_command(client):
    user_id = client.args.get('user_id')
    limit = client.args.get('limit', '20')
    url = f'{client.base_url}/users/{user_id}/mailFolders?$top={limit}'
    raw_response = requests.request('GET', url, verify=client.use_ssl)
    raw_response = raw_response.json()
    parsed_folder_result = parse_folders_list(raw_response.get('value', []))
    human_readable = tableToMarkdown(f'Mail Folder collection under root folder for user {user_id}',
                                     parsed_folder_result)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_folder_result}

    return_outputs(human_readable, entry_context, raw_response)


def list_child_folders_command(client):
    user_id = client.args.get('user_id')
    parent_folder_id = client.args.get('parent_folder_id')
    limit = client.args.get('limit', '20')
    url = f'{client.base_url}/users/{user_id}/mailFolders/{parent_folder_id}/childFolders?$top={limit}'

    raw_response = requests.request('GET', url, verify=client.use_ssl)
    raw_response = raw_response.json()
    parsed_child_folders_result = parse_folders_list(raw_response.get('value', []))  # type: ignore
    human_readable = tableToMarkdown(f'Mail Folder collection under {parent_folder_id} folder for user {user_id}',
                                     parsed_child_folders_result)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_child_folders_result}

    return_outputs(human_readable, entry_context, raw_response)


def create_folder_command(client):
    user_id = client.args.get('user_id')
    new_folder_name = client.args.get('new_folder_name')
    parent_folder_id = client.args.get('parent_folder_id')
    url = f'{client.base_url}/users/{user_id}/mailFolders'
    if parent_folder_id:
        url += f'/{parent_folder_id}/childFolders'

    json_data = {'displayName': new_folder_name}
    raw_response = requests.request('POST', url, json=json_data, verify=client.use_ssl)
    parsed_created_folder = raw_response.json()
    headers = ['ChildFolderCount', 'DisplayName', 'ID', 'ParentFolderID', 'TotalItemCount', 'UnreadItemCount']
    human_readable = tableToMarkdown(
        f'Mail folder was created with display name: {new_folder_name}',
        parsed_created_folder, headers)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_created_folder}
    return_outputs(human_readable, entry_context, parsed_created_folder)


def update_folder_command(client):
    user_id = client.args.get('user_id')
    folder_id = client.args.get('folder_id')
    new_display_name = client.args.get('new_display_name')

    parsed_updated_folder = {
        'ID': folder_id,
        'DisplayName': new_display_name,
        'ParentFolderID': '3495875698wsdfojhfsdog097345h',
        'ChildFolderCount': 0,
        'UnreadItemCount': 15,
        'TotalItemCount': 512
    }
    human_readable = tableToMarkdown(f'Mail folder {folder_id} was updated with display name: {new_display_name}',
                                     parsed_updated_folder)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_updated_folder}

    return_outputs(human_readable, entry_context, parsed_updated_folder)


def delete_folder_command(client):
    user_id = client.args.get('user_id')
    folder_id = client.args.get('folder_id')

    return_outputs(f'The folder {folder_id} was deleted successfully')


def move_email_command(client):
    user_id = client.args.get('user_id')
    message_id = client.args.get('message_id')
    destination_folder_id = client.args.get('destination_folder_id')

    raw_response = {
        "id": "9875v98769890unsd7bvsdiljhvsd98",
        "destinationfolderid": destination_folder_id,
        "userid": user_id
    }
    new_message_id = raw_response.get('id')
    moved_email_info = {
        'ID': new_message_id,
        'DestinationFolderID': destination_folder_id,
        'UserID': user_id
    }
    human_readable = tableToMarkdown('The email was moved successfully. Updated email data:', moved_email_info)
    entry_context = {CONTEXT_COPIED_EMAIL: moved_email_info}

    return_outputs(human_readable, entry_context, raw_response)


def get_email_as_eml_command(client):
    user_id = client.args.get('user_id')
    message_id = client.args.get('message_id')

    url = f'{client.base_url}/users/{user_id}/messages/{message_id}/$value'
    eml_content = requests.request('GET', url, verify=client.use_ssl)
    eml_content = eml_content.text
    file_result = fileResult(f'{message_id}.eml', eml_content)

    if is_error(file_result):
        raise Exception(file_result['Contents'])

    demisto.results(file_result)


def prepare_args(command, args):
    """
    Receives command and prepares the arguments for future usage.

    :type command: ``str``
    :param command: Command to execute

    :type args: ``dict``
    :param args: Demisto args

    :return: Prepared args
    :rtype: ``dict``
    """
    if command in ['create-draft', 'send-mail']:
        return {
            'to_recipients': argToList(args.get('to')),
            'cc_recipients': argToList(args.get('cc')),
            'bcc_recipients': argToList(args.get('bcc')),
            'subject': args.get('subject', ''),
            'body': args.get('body', ''),
            'body_type': args.get('bodyType', 'text'),
            'flag': args.get('flag', 'notFlagged'),
            'importance': args.get('importance', 'Low'),
            'internet_message_headers': argToList(args.get('headers')),
            'attach_ids': argToList(args.get('attachIDs')),
            'attach_names': argToList(args.get('attachNames')),
            'attach_cids': argToList((args.get('attachCIDs'))),
            'manual_attachments': args.get('manualAttachObj', [])
        }

    elif command == 'reply-to':
        return {
            'to_recipients': argToList(args.get('to')),
            'message_id': args.get('ID', ''),
            'comment': args.get('body')
        }

    return args


def create_draft_command(client):
    """
    Creates draft message in user's mailbox, in draft folder.
    """
    prepared_args = client.args
    email = client.args.get('from')
    suffix_endpoint = f'{client.base_url}/users/{email}/messages'
    draft = prepared_args

    created_draft = requests.request('POST', suffix_endpoint, json=draft, verify=client.use_ssl)
    parsed_draft = created_draft.json()
    headers = ['ID', 'From', 'Sender', 'To', 'Subject', 'Body', 'BodyType', 'Cc', 'Bcc', 'Headers', 'Importance',
               'MessageID', 'ConversationID', 'CreatedTime', 'SentTime', 'ReceivedTime', 'ModifiedTime', 'IsDraft',
               'IsRead']
    human_readable = tableToMarkdown(f'Created draft with id: {parsed_draft.get("ID", "")}',
                                     parsed_draft, headers=headers)
    entry_context = {CONTEXT_DRAFT_PATH: parsed_draft}

    return_outputs(human_readable, entry_context, parsed_draft)


def build_recipients_human_readable(message_content):
    to_recipients = []
    cc_recipients = []
    bcc_recipients = []

    for recipients_dict in message_content.get('toRecipients', {}):
        to_recipients.append(recipients_dict.get('emailAddress', {}).get('address'))

    for recipients_dict in message_content.get('ccRecipients', {}):
        cc_recipients.append(recipients_dict.get('emailAddress', {}).get('address'))

    for recipients_dict in message_content.get('bccRecipients', {}):
        bcc_recipients.append(recipients_dict.get('emailAddress', {}).get('address'))

    return to_recipients, cc_recipients, bcc_recipients


def send_email_command(client):
    """
    Sends email from user's mailbox, the sent message will appear in Sent Items folder
    """
    prepared_args = prepare_args('send-mail', args)
    email = args.get('from', client._mailbox_to_fetch)
    suffix_endpoint = f'/users/{email}/sendMail'
    message_content = MsGraphClient.build_message(**prepared_args)
    client.ms_client.http_request('POST', suffix_endpoint, json_data={'message': message_content}, resp_type="text")

    message_content.pop('attachments', None)
    message_content.pop('internet_message_headers', None)

    to_recipients, cc_recipients, bcc_recipients = build_recipients_human_readable(message_content)
    message_content['toRecipients'] = to_recipients
    message_content['ccRecipients'] = cc_recipients
    message_content['bccRecipients'] = bcc_recipients

    message_content = assign_params(**message_content)
    human_readable = tableToMarkdown(f'Email was sent successfully.', message_content)
    ec = {CONTEXT_SENT_EMAIL_PATH: message_content}

    return_outputs(human_readable, ec)


def reply_to_command(client):
    to_recipients = [client.args.get('to')]
    message_id = client.args.get('ID', '')
    comment = client.args.get('body')
    email = client.args.get('from')
    return_outputs(f'### Replied to: {", ".join(to_recipients)} with comment: {comment}')


def send_draft_command(client):
    email = client.args.get('from')
    draft_id = client.args.get('draft_id')
    return_outputs(f'### Draft with: {draft_id} id was sent successfully.')


def fetch_incidents_command(client):
    url = f"{client.base_url}/incidents"
    jsonIncidents = requests.get(url, verify=client.use_ssl)
    return(jsonIncidents.json())


def main():
    """ COMMANDS MANAGER / SWITCH PANEL """
    args: dict = demisto.args()
    params: dict = demisto.params()
    self_deployed: bool = params.get('self_deployed', False)
    tenant_id: str = params.get('tenant_id', '1')
    auth_and_token_url: str = params.get('auth_id', '')
    enc_key: str = params.get('enc_key', '')
    base_url: str = urljoin(params.get('url', ''), '/msgraphmail/v1.0')
    app_name: str = 'ms-graph-mail'
    ok_codes: tuple = (200, 201, 202, 204)
    use_ssl: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)
    client = Client(demisto.params(), demisto.args())

    # params related to mailbox to fetch incidents
    mailbox_to_fetch = params.get('mailbox_to_fetch', '')
    folder_to_fetch = params.get('folder_to_fetch', 'Inbox')
    first_fetch_interval = params.get('first_fetch', '15 minutes')
    emails_fetch_limit = int(params.get('fetch_limit', '50'))

    command = demisto.command()
    LOG(f'Command being called is {command}')

    # try:
    if command == 'test-module':
        demisto.results('ok')
    if command == 'fetch-incidents':
        incidents = fetch_incidents_command(client)
        demisto.incidents(incidents)
    elif command in ('msgraph-mail-list-emails', 'msgraph-mail-search-email'):
        list_mails_command(client)
    elif command == 'msgraph-mail-get-email':
        get_message_command(client)
    elif command == 'msgraph-mail-delete-email':
        delete_mail_command(client)
    elif command == 'msgraph-mail-list-attachments':
        list_attachments_command(client)
    elif command == 'msgraph-mail-get-attachment':
        get_attachment_command(client)
    elif command == 'msgraph-mail-list-folders':
        list_folders_command(client)
    elif command == 'msgraph-mail-list-child-folders':
        list_child_folders_command(client)
    elif command == 'msgraph-mail-create-folder':
        create_folder_command(client)
    elif command == 'msgraph-mail-update-folder':
        update_folder_command(client)
    elif command == 'msgraph-mail-delete-folder':
        delete_folder_command(client)
    elif command == 'msgraph-mail-move-email':
        move_email_command(client)
    elif command == 'msgraph-mail-get-email-as-eml':
        get_email_as_eml_command(client)
    elif command == 'msgraph-mail-create-draft':
        create_draft_command(client)
    elif command == 'msgraph-mail-reply-to':
        reply_to_command(client)  # pylint: disable=E1123
    elif command == 'msgraph-mail-send-draft':
        send_draft_command(client)  # pylint: disable=E1123
    elif command == 'send-mail':
        send_email_command(client)
    # Log exceptions
    # except Exception as e:
    #    return_error(str(e))


if __name__ in ["builtins", "__main__"]:
    main()
