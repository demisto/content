import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Union, Optional

''' IMPORTS '''
import requests
import base64
import binascii

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''

CONTEXT_FOLDER_PATH = 'MSGraphMail.Folders(val.ID && val.ID === obj.ID)'
CONTEXT_COPIED_EMAIL = 'MSGraphMail.MovedEmails(val.ID && val.ID === obj.ID)'

FOLDER_MAPPING = {
    'id': 'ID',
    'displayName': 'DisplayName',
    'parentFolderId': 'ParentFolderID',
    'childFolderCount': 'ChildFolderCount',
    'unreadItemCount': 'UnreadItemCount',
    'totalItemCount': 'TotalItemCount'
}

''' CLIENT '''


class MsGraphClient:
    def __init__(self, ms_client):
        self.ms_client = ms_client

    def pages_puller(self, response: dict, page_count: int) -> list:
        """ Gets first response from API and returns all pages

        Args:
            response (dict):
            page_count (int):

        Returns:
            list: list of all pages
        """
        responses = [response]
        i = page_count
        while i != 0:
            next_link = response.get('@odata.nextLink')
            if next_link:
                responses.append(
                    self.ms_client.http_request('GET', url=next_link)
                )

            else:
                return responses
            i -= 1
        return responses

    def list_mails(self, user_id: str, folder_id: str = '', search: str = None, odata: str = None) -> Union[dict, list]:
        """Returning all mails from given user

        Args:
            user_id (str):
            folder_id (str):
            search (str):
            odata (str):

        Returns:
            dict or list:
        """
        no_folder = f'/users/{user_id}/messages/'
        with_folder = f'/users/{user_id}/{build_folders_path(folder_id)}/messages/'
        pages_to_pull = demisto.args().get('pages_to_pull', 1)

        if search:
            odata = f'?{odata}$search={search}' if odata else f'?$search={search}'
        suffix = with_folder if folder_id else no_folder
        if odata:
            suffix += odata
        response = self.ms_client.http_request('GET', suffix)
        return self.pages_puller(response, assert_pages(pages_to_pull))

    def delete_mail(self, user_id: str, message_id: str, folder_id: str = None) -> bool:
        """

        Args:
            user_id (str):
            message_id (str):
            folder_id (str):

        Returns:
            bool
        """
        with_folder = f'/users/{user_id}/{build_folders_path(folder_id)}/messages/{message_id}'  # type: ignore
        no_folder = f'/users/{user_id}/messages/{message_id}'
        suffix = with_folder if folder_id else no_folder
        self.ms_client.http_request('DELETE', suffix)
        return True

    def get_attachment(self, message_id: str, user_id: str, attachment_id: str, folder_id: str = None) -> dict:
        """

        Args:
            message_id (str):
            user_id (str_:
            attachment_id (str):
            folder_id (str):

        Returns:
            dict:
        """
        no_folder = f'/users/{user_id}/messages/{message_id}/attachments/{attachment_id}'
        with_folder = (f'/users/{user_id}/{build_folders_path(folder_id)}/'  # type: ignore
                       f'messages/{message_id}/attachments/{attachment_id}')
        suffix = with_folder if folder_id else no_folder
        response = self.ms_client.http_request('GET', suffix)
        return response

    def get_message(self, user_id: str, message_id: str, folder_id: str = '', odata: str = '') -> dict:
        """

        Args:
            user_id (str): User ID to pull message from
            message_id (str): Message ID to pull
            folder_id: (str) Folder ID to pull from
            odata (str): OData query

        Returns
            dict: request json
        """
        no_folder = f'/users/{user_id}/messages/{message_id}/'
        with_folder = (f'/users/{user_id}/{build_folders_path(folder_id)}'  # type: ignore
                       f'/messages/{message_id}/')

        suffix = with_folder if folder_id else no_folder
        if odata:
            suffix += odata
        response = self.ms_client.http_request('GET', suffix)

        # Add user ID
        response['userId'] = user_id
        return response

    def list_attachments(self, user_id: str, message_id: str, folder_id: str) -> dict:
        """Listing all the attachments

        Args:
            user_id (str):
            message_id (str):
            folder_id (str):

        Returns:
            dict:
        """
        no_folder = f'/users/{user_id}/messages/{message_id}/attachments/'
        with_folder = f'/users/{user_id}/{build_folders_path(folder_id)}/messages/{message_id}/attachments/'
        suffix = with_folder if folder_id else no_folder
        return self.ms_client.http_request('GET', suffix)

    def list_folders(self, user_id: str, limit: str = '20') -> dict:
        """List folder under root folder (Top of information store)

        Args:
            user_id (str): User id or mailbox address
            limit (str): Limit number of returned folder collection

        Returns:
            dict: Collection of folders under root folder
        """
        suffix = f'/users/{user_id}/mailFolders?$top={limit}'
        return self.ms_client.http_request('GET', suffix)

    def list_child_folders(self, user_id: str, parent_folder_id: str, limit: str = '20') -> list:
        """List child folder under specified folder.

        Args:
            user_id (str): User id or mailbox address
            parent_folder_id (str): Parent folder id
            limit (str): Limit number of returned folder collection

        Returns:
            list: Collection of folders under specified folder
        """
        # for additional info regarding OData query https://docs.microsoft.com/en-us/graph/query-parameters
        suffix = f'/users/{user_id}/mailFolders/{parent_folder_id}/childFolders?$top={limit}'
        return self.ms_client.http_request('GET', suffix)

    def create_folder(self, user_id: str, new_folder_name: str, parent_folder_id: str = None) -> dict:
        """Create folder under specified folder with given display name

        Args:
            user_id (str): User id or mailbox address
            new_folder_name (str): Created folder display name
            parent_folder_id (str): Parent folder id under where created new folder

        Returns:
            dict: Created folder data
        """

        suffix = f'/users/{user_id}/mailFolders'
        if parent_folder_id:
            suffix += f'/{parent_folder_id}/childFolders'

        json_data = {'displayName': new_folder_name}
        return self.ms_client.http_request('POST', suffix, json_data=json_data)

    def update_folder(self, user_id: str, folder_id: str, new_display_name: str) -> dict:
        """Update folder under specified folder with new display name

        Args:
            user_id (str): User id or mailbox address
            folder_id (str): Folder id to update
            new_display_name (str): New display name of updated folder

        Returns:
            dict: Updated folder data
        """

        suffix = f'/users/{user_id}/mailFolders/{folder_id}'
        json_data = {'displayName': new_display_name}
        return self.ms_client.http_request('PATCH', suffix, json_data=json_data)

    def delete_folder(self, user_id: str, folder_id: str):
        """Deletes folder under specified folder

        Args:
            user_id (str): User id or mailbox address
            folder_id (str): Folder id to delete
        """

        suffix = f'/users/{user_id}/mailFolders/{folder_id}'
        return self.ms_client.http_request('DELETE', suffix)

    def move_email(self, user_id: str, message_id: str, destination_folder_id: str) -> dict:
        """Moves email to destination folder

        Args:
            user_id (str): User id or mailbox address
            message_id (str): The message id to move
            destination_folder_id (str): Destination folder id

        Returns:
            dict: Moved email data
        """

        suffix = f'/users/{user_id}/messages/{message_id}/move'
        json_data = {'destinationId': destination_folder_id}
        return self.ms_client.http_request('POST', suffix, json_data=json_data)

    def get_email_as_eml(self, user_id: str, message_id: str) -> str:
        """Returns MIME content of specified message

        Args:
            user_id (str): User id or mailbox address
            message_id (str): The message id of the email

        Returns:
            str: MIME content of the email
        """

        suffix = f'/users/{user_id}/messages/{message_id}/$value'
        return self.ms_client.http_request('GET', suffix, resp_type='text')


''' HELPER FUNCTIONS '''


def assert_pages(pages: Union[str, int]) -> int:
    """

    Args:
        pages (str or int): pages need to pull in int or str

    Returns:
        int: default 1

    """
    if isinstance(pages, str) and pages.isdigit():
        return int(pages)
    elif isinstance(pages, int):
        return pages
    return 1


def build_folders_path(folder_string: str) -> Optional[str]:
    """

    Args:
        folder_string (str): string with `,` delimiter. first one is mailFolders all other are child

    Returns:
        str or None:  string with path to the folder and child folders
    """
    if isinstance(folder_string, str):
        path = 'mailFolders/'
        folders_list = argToList(folder_string, ',')
        first = True
        for folder in folders_list:
            if first:
                path += folder
                first = False
            else:
                path += f'/childFolders/{folder}'
        return path
    return None


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


def parse_folders_list(folders_list):
    if isinstance(folders_list, dict):
        folders_list = [folders_list]

    return [{FOLDER_MAPPING[k]: v for (k, v) in f.items() if k in FOLDER_MAPPING} for f in folders_list]


''' COMMANDS '''


def list_mails_command(client: MsGraphClient, args):
    search = args.get('search')
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    odata = args.get('odata')

    raw_response = client.list_mails(user_id, folder_id=folder_id, search=search, odata=odata)
    mail_context = build_mail_object(raw_response, user_id)
    entry_context = {'MSGraphMail(val.ID === obj.ID)': mail_context}

    # human_readable builder
    human_readable = tableToMarkdown(
        f'### Total of {len(mail_context)} of mails received',
        mail_context,
        headers=['Subject', 'From', 'SendTime']
    )
    return_outputs(human_readable, entry_context, raw_response)


def delete_mail_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    message_id = args.get('message_id')
    client.delete_mail(user_id, message_id, folder_id)

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


def get_attachment_command(client: MsGraphClient, args):
    message_id = args.get('message_id')
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    attachment_id = args.get('attachment_id')
    raw_response = client.get_attachment(message_id, user_id, folder_id=folder_id, attachment_id=attachment_id)
    entry_context = file_result_creator(raw_response)
    demisto.results(entry_context)


def get_message_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    message_id = args.get('message_id')
    get_body = args.get('get_body') == 'true'
    odata = args.get('odata')
    raw_response = client.get_message(user_id, message_id, folder_id, odata=odata)
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


def list_attachments_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    message_id = args.get('message_id')
    folder_id = args.get('folder_id')
    raw_response = client.list_attachments(user_id, message_id, folder_id)
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


def list_folders_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    limit = args.get('limit', '20')

    raw_response = client.list_folders(user_id, limit)
    parsed_folder_result = parse_folders_list(raw_response.get('value', []))
    human_readable = tableToMarkdown(f'Mail Folder collection under root folder for user {user_id}',
                                     parsed_folder_result)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_folder_result}

    return_outputs(human_readable, entry_context, raw_response)


def list_child_folders_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    parent_folder_id = args.get('parent_folder_id')
    limit = args.get('limit', '20')

    raw_response = client.list_child_folders(user_id, parent_folder_id, limit)
    parsed_child_folders_result = parse_folders_list(raw_response.get('value', []))  # type: ignore
    human_readable = tableToMarkdown(f'Mail Folder collection under {parent_folder_id} folder for user {user_id}',
                                     parsed_child_folders_result)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_child_folders_result}

    return_outputs(human_readable, entry_context, raw_response)


def create_folder_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    new_folder_name = args.get('new_folder_name')
    parent_folder_id = args.get('parent_folder_id')

    raw_response = client.create_folder(user_id, new_folder_name, parent_folder_id)
    parsed_created_folder = parse_folders_list(raw_response)
    human_readable = tableToMarkdown(
        f'Mail folder was created with display name: {new_folder_name}',
        parsed_created_folder)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_created_folder}

    return_outputs(human_readable, entry_context, raw_response)


def update_folder_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')
    new_display_name = args.get('new_display_name')

    raw_response = client.update_folder(user_id, folder_id, new_display_name)
    parsed_updated_folder = parse_folders_list(raw_response)
    human_readable = tableToMarkdown(f'Mail folder {folder_id} was updated with display name: {new_display_name}',
                                     parsed_updated_folder)
    entry_context = {CONTEXT_FOLDER_PATH: parsed_updated_folder}

    return_outputs(human_readable, entry_context, raw_response)


def delete_folder_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    folder_id = args.get('folder_id')

    client.delete_folder(user_id, folder_id)
    return_outputs(f'The folder {folder_id} was deleted successfully')


def move_email_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    message_id = args.get('message_id')
    destination_folder_id = args.get('destination_folder_id')

    raw_response = client.move_email(user_id, message_id, destination_folder_id)
    new_message_id = raw_response.get('id')
    moved_email_info = {
        'ID': new_message_id,
        'DestinationFolderID': destination_folder_id,
        'UserID': user_id
    }
    human_readable = tableToMarkdown('The email was moved successfully. Updated email data:', moved_email_info)
    entry_context = {CONTEXT_COPIED_EMAIL: moved_email_info}

    return_outputs(human_readable, entry_context, raw_response)


def get_email_as_eml_command(client: MsGraphClient, args):
    user_id = args.get('user_id')
    message_id = args.get('message_id')

    eml_content = client.get_email_as_eml(user_id, message_id)
    file_result = fileResult(f'{message_id}.eml', eml_content)

    if is_error(file_result):
        raise Exception(file_result['Contents'])

    demisto.results(file_result)


def main():
    """ COMMANDS MANAGER / SWITCH PANEL """
    command = demisto.command()
    args = demisto.args()
    LOG(f'Command being called is {command}')

    params = demisto.params()
    self_deployed = params.get('self_deployed', False)
    tenant_id = params.get('tenant_id')
    auth_and_token_url = params.get('auth_id', '')
    enc_key = params.get('enc_key')
    # Remove trailing slash to prevent wrong URL path to service
    url = params.get('url', '')
    server = url[:-1] if (url and url.endswith('/')) else url
    # Service base URL
    base_url = server + '/v1.0'
    app_name = 'ms-graph-mail'
    ok_codes = (200, 201, 202)
    use_ssl = not params.get('insecure', False)
    proxy = handle_proxy()

    if self_deployed:
        app_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        ms_client = MicrosoftClient.from_self_deployed(tenant_id, auth_and_token_url,
                                                       enc_key, app_url=app_url,
                                                       scope='https://graph.microsoft.com/.default',
                                                       base_url=base_url, verify=use_ssl,
                                                       proxy=proxy, ok_codes=ok_codes)
    else:
        # params related to oproxy
        ms_client = MicrosoftClient.from_oproxy(auth_and_token_url, enc_key, app_name,
                                                tenant_id=tenant_id, base_url=base_url, verify=use_ssl,
                                                proxy=proxy, ok_codes=ok_codes)

    client = MsGraphClient(ms_client)

    try:
        if command == 'test-module':
            client.ms_client.get_access_token()
            demisto.results('ok')
        elif command in ('msgraph-mail-list-emails', 'msgraph-mail-search-email'):
            list_mails_command(client, args)
        elif command == 'msgraph-mail-get-email':
            get_message_command(client, args)
        elif command == 'msgraph-mail-delete-email':
            delete_mail_command(client, args)
        elif command == 'msgraph-mail-list-attachments':
            list_attachments_command(client, args)
        elif command == 'msgraph-mail-get-attachment':
            get_attachment_command(client, args)
        elif command == 'msgraph-mail-list-folders':
            list_folders_command(client, args)
        elif command == 'msgraph-mail-list-child-folders':
            list_child_folders_command(client, args)
        elif command == 'msgraph-mail-create-folder':
            create_folder_command(client, args)
        elif command == 'msgraph-mail-update-folder':
            update_folder_command(client, args)
        elif command == 'msgraph-mail-delete-folder':
            delete_folder_command(client, args)
        elif command == 'msgraph-mail-move-email':
            move_email_command(client, args)
        elif command == 'msgraph-mail-get-email-as-eml':
            get_email_as_eml_command(client, args)
    # Log exceptions
    except Exception as e:
        return_error(str(e))


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
