import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Union, Optional


''' IMPORTS '''
import requests
import base64
import os
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
PARAMS = demisto.params()
TENANT_ID = PARAMS.get('tenant_id')
AUTH_AND_TOKEN_URL = PARAMS.get('auth_id', '').split('@')
AUTH_ID = AUTH_AND_TOKEN_URL[0]
ENC_KEY = PARAMS.get('enc_key')
if len(AUTH_AND_TOKEN_URL) != 2:
    TOKEN_RETRIEVAL_URL = 'https://oproxy.demisto.ninja/obtain-token'  # disable-secrets-detection
else:
    TOKEN_RETRIEVAL_URL = AUTH_AND_TOKEN_URL[1]
# Remove trailing slash to prevent wrong URL path to service
URL = PARAMS.get('url', '')
SERVER = URL[:-1] if (URL and URL.endswith('/')) else URL
# Service base URL
BASE_URL = SERVER + '/v1.0'
APP_NAME = 'ms-graph-mail'

USE_SSL = not PARAMS.get('insecure', False)
# Remove proxy if not set to true in params
if not PARAMS.get('proxy'):
    os.environ.pop('HTTP_PROXY', '')
    os.environ.pop('HTTPS_PROXY', '')
    os.environ.pop('http_proxy', '')
    os.environ.pop('https_proxy', '')

''' HELPER FUNCTIONS '''


def epoch_seconds(d: datetime = None) -> int:
    """
    Return the number of seconds for given date. If no date, return current.

    Args:
        d (datetime): timestamp
    Returns:
         int: timestamp in epoch
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def get_encrypted(content: str, key: str) -> str:
    """

    Args:
        content (str): content to encrypt. For a request to Demistobot for a new access token, content should be
            the tenant id
        key (str): encryption key from Demistobot

    Returns:
        encrypted timestamp:content
    """
    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        """

        Args:
            enc_key (str):
            string (str):

        Returns:
            bytes:
        """
        # String to bytes
        enc_key = base64.b64decode(enc_key)
        # Create key
        aes_gcm = AESGCM(enc_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct)
    now = epoch_seconds()
    encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
    return encrypted


def get_access_token():
    integration_context = demisto.getIntegrationContext()
    access_token = integration_context.get('access_token')
    valid_until = integration_context.get('valid_until')
    if access_token and valid_until:
        if epoch_seconds() < valid_until:
            return access_token
    headers = {'Accept': 'application/json'}

    dbot_response = requests.post(
        TOKEN_RETRIEVAL_URL,
        headers=headers,
        data=json.dumps({
            'app_name': APP_NAME,
            'registration_id': AUTH_ID,
            'encrypted_token': get_encrypted(TENANT_ID, ENC_KEY)
        }),
        verify=USE_SSL
    )
    if dbot_response.status_code not in {200, 201}:
        msg = 'Error in authentication. Try checking the credentials you entered.'
        try:
            demisto.info('Authentication failure from server: {} {} {}'.format(
                dbot_response.status_code, dbot_response.reason, dbot_response.text))
            err_response = dbot_response.json()
            server_msg = err_response.get('message')
            if not server_msg:
                title = err_response.get('title')
                detail = err_response.get('detail')
                if title:
                    server_msg = f'{title}. {detail}'
            if server_msg:
                msg += ' Server message: {}'.format(server_msg)
        except Exception as ex:
            demisto.error('Failed parsing error response - Exception: {}'.format(ex))
        raise Exception(msg)
    try:
        gcloud_function_exec_id = dbot_response.headers.get('Function-Execution-Id')
        demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
        parsed_response = dbot_response.json()
    except ValueError:
        raise Exception(
            'There was a problem in retrieving an updated access token.\n'
            'The response from the Demistobot server did not contain the expected content.'
        )
    access_token = parsed_response.get('access_token')
    expires_in = parsed_response.get('expires_in', 3595)
    time_now = epoch_seconds()
    time_buffer = 5  # seconds by which to shorten the validity period
    if expires_in - time_buffer > 0:
        # err on the side of caution with a slightly shorter access token validity period
        expires_in = expires_in - time_buffer

    demisto.setIntegrationContext({
        'access_token': access_token,
        'valid_until': time_now + expires_in
    })
    return access_token


def error_parser(resp_err: requests.Response) -> str:
    """

    Args:
        error (requests.Response): response with error

    Returns:
        str: string of error

    """
    try:
        response = resp_err.json()
        error = response.get('error', {})
        err_str = f"{error.get('code')}: {error.get('message')}"
        if err_str:
            return err_str
        # If no error message
        raise ValueError
    except ValueError:
        return resp_err.text


def http_request(method: str, url_suffix: str = '', params: dict = None, data: dict = None, odata: str = None,
                 url: str = None) -> dict:
    """
    A wrapper for requests lib to send our requests and handle requests and responses better
    Headers to be sent in requests

    Args:
        method (str): any restful method
        url_suffix (str): suffix to add to BASE_URL
        params (str): http params
        data (dict): http body
        odata (str): odata query format
        url (str): url to replace if need a new api call

    Returns:
        dict: requests.json()
    """
    token = get_access_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    if odata:
        url_suffix += odata
    res = requests.request(
        method,
        url if url else BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=headers
    )
    # Handle error responses gracefully
    if not (199 < res.status_code < 299):
        error = error_parser(res)
        return_error(f'Error in API call to Microsoft Graph Mail Integration [{res.status_code}] - {error}')
    try:
        if method.lower() != 'delete':  # the DELETE request returns nothing in response
            return res.json()
        return {}
    except ValueError:
        return_error('Could not decode response from API')
        return {}  # return_error will exit


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


def pages_puller(response: dict, page_count: int) -> list:
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
                http_request('GET', url=next_link)
            )

        else:
            return responses
        i -= 1
    return responses


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
            'IsDraft': 'isDraft'
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


''' COMMANDS + REQUESTS FUNCTIONS '''


def list_mails(user_id: str, folder_id: str = '', search: str = None, odata: str = None) -> Union[dict, list]:
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
    with_folder = f'users/{user_id}/{build_folders_path(folder_id)}/messages/'
    pages_to_pull = demisto.args().get('pages_to_pull', 1)

    if search:
        odata = f'?{odata}$search={search}' if odata else f'?$search={search}'
    suffix = with_folder if folder_id else no_folder
    response = http_request('GET', suffix, odata=odata)
    return pages_puller(response, assert_pages(pages_to_pull))


def list_mails_command():
    search = demisto.args().get('search')
    user_id = demisto.args().get('user_id')
    folder_id = demisto.args().get('folder_id')
    odata = demisto.args().get('odata')

    raw_response = list_mails(user_id, folder_id=folder_id, search=search, odata=odata)
    mail_context = build_mail_object(raw_response, user_id)
    entry_context = {'MSGraphMail(var.ID === obj.ID)': mail_context}

    # human_readable builder
    human_readable = tableToMarkdown(
        f'### Total of {len(mail_context)} of mails received',
        mail_context,
        headers=['Subject', 'From', 'SendTime']
    )
    return_outputs(human_readable, entry_context, raw_response)


def delete_mail(user_id: str, message_id: str, folder_id: str = None) -> bool:
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
    http_request('DELETE', suffix)
    return True


def delete_mail_command():
    user_id = demisto.args().get('user_id')
    folder_id = demisto.args().get('folder_id')
    message_id = demisto.args().get('message_id')
    delete_mail(user_id, message_id, folder_id)

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


def get_attachment(message_id: str, user_id: str, attachment_id: str, folder_id: str = None) -> dict:
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
    response = http_request('GET', suffix)
    return response


def get_attachment_command():
    message_id = demisto.args().get('message_id')
    user_id = demisto.args().get('user_id')
    folder_id = demisto.args().get('folder_id')
    attachment_id = demisto.args().get('attachment_id')
    raw_response = get_attachment(message_id, user_id, folder_id=folder_id, attachment_id=attachment_id)
    entry_context = file_result_creator(raw_response)
    demisto.results(entry_context)


def get_message(user_id: str, message_id: str, folder_id: str = None, odata: str = None) -> dict:
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
    response = http_request('GET', suffix, odata=odata)

    # Add user ID
    response['userId'] = user_id
    return response


def get_message_command():
    user_id = demisto.args().get('user_id')
    folder_id = demisto.args().get('folder_id')
    message_id = demisto.args().get('message_id')
    get_body = demisto.args().get('get_body') == 'true'
    odata = demisto.args().get('odata')
    raw_response = get_message(user_id, message_id, folder_id, odata=odata)
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


def list_attachments(user_id: str, message_id: str, folder_id: str) -> dict:
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
    return http_request('GET', suffix)


def list_attachments_command():
    user_id = demisto.args().get('user_id')
    message_id = demisto.args().get('message_id')
    folder_id = demisto.args().get('folder_id')
    raw_response = list_attachments(user_id, message_id, folder_id)
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


def main():
    """ COMMANDS MANAGER / SWITCH PANEL """
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            get_access_token()
            demisto.results('ok')
        elif command in ('msgraph-mail-list-emails', 'msgraph-mail-search-email'):
            list_mails_command()
        elif command == 'msgraph-mail-get-email':
            get_message_command()
        elif command == 'msgraph-mail-delete-email':
            delete_mail_command()
        elif command == 'msgraph-mail-list-attachments':
            list_attachments_command()
        elif command == 'msgraph-mail-get-attachment':
            get_attachment_command()
    # Log exceptions
    except Exception as e:
        return_error(str(e))


if __name__ == "builtins":
    main()
