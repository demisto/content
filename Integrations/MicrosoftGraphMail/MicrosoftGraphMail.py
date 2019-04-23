from CommonServerPython import *

''' IMPORTS '''
import requests
import base64

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' PARAMS DECLARATIONS '''
BASE_URL = None
USE_SSL = None
CONTEXT = None
TOKEN = None
DEMISTOBOT = None
TENANT_ID = None

''' HELPER FUNCTIONS '''


def http_request(method: str, url_suffix: str, params: dict = None, data: dict = None, odata: str = None,
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
    token = get_token()
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
    if res.status_code != requests.codes.ok:
        return_error(f'Error in API call to Microsoft Graph Mail Integration [{res.status_code}] - {res.reason}')
    return res.json()


def epoch_seconds(d: str = None) -> int:
    """
    Return the number of seconds for given date. If no date, return current.

    Args:
        d (str): timestamp
    Returns:
         int: timestamp in epoch
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def get_token() -> str:
    """
    Check if we have a valid token and if not get one from demistobot

    Returns:
        str: token from demistobot

    """
    product = 'MicrosoftGraphMail'
    token = CONTEXT.get('token')
    stored = CONTEXT.get('stored')
    if token and stored:
        if epoch_seconds() - stored < 60 * 60 - 30:
            return token
    headers = {
        'Authorization': TOKEN,
        'Accept': 'application/json'
    }

    r = requests.get(
        DEMISTOBOT,
        headers=headers,
        params={
            'tenant': TENANT_ID,
            'product': product
        },
        verify=USE_SSL
    )
    if r.status_code != requests.codes.ok:
        return_error(
            f'Error in API call to Azure Security Center [{r.status_code}] - {r.text}')
    data = r.json()

    demisto.setIntegrationContext(
        {
            'token': data.get('token'),
            'stored': epoch_seconds()
        }
    )
    return data.get('token')


def odata_query_builder():
    odata = {
        'count': True if demisto.args().get('count') else False,
        'expand': demisto.args().get('expand'),
        'filter': {
            'eq': demisto.args().get('filter_equals'),
            'ne': demisto.args().get('filter_not_equals'),
            'gt': demisto.args().get('filter_greater_than'),
            'ge': demisto.args().get('filter_greater_or_equal'),
            'lt': demisto.args().get('filter_less_than'),
            'le': demisto.args().get('filter_less_or_equal'),
            'or': demisto.args().get('or'),
            'not': demisto.args().get('not')
        }
    }


def assert_pages(pages: str or int) -> int:
    """

    Args:
        pages (str or int): pages need to pull in int or str

    Returns:
        int: 

    """
    if isinstance(pages, str) and pages.isdigit():
        return int(pages)
    elif isinstance(pages, int):
        return pages
    return 1


def assert_folders(folder_string: str) -> str:
    """

    Args:
        folder_string (str): string with `,` delimiter. first one is mailFolders all other are child

    Returns:
        str:  string with path to the folder and child folders

    """
    path = 'mailFolders/'
    folders_list = folder_string.split(',')
    for i in range(len(folders_list)):
        if i == 0:
            path += folders_list[0]
        else:
            path += '/childFolders/' + folders_list[0]
    return path


def pages_puller(response, page_count):
    responses = list()
    responses.append(response)
    i = page_count
    while i != 0:
        next_link = response.get('@odata.nextLink')
        if next_link:
            responses.append(
                http_request('GET', None, url=next_link)
            )

        else:
            return responses
        i -= 1
    return responses


def build_mail_object(raw_response: dict or list, get_body: bool = False) -> dict or list:
    """Building mail entry context
    Getting a list from build_mail_object

    Args:
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
            'HasAttachment': 'hasAttachment',
            'Subject': 'subject',
        }

        contact_properties = {
            'Sender': 'sender',
            'From': 'from',
            'CCRecipients': 'ccRecipients',
            'BCCRecipients': 'bccRecipients',
            'ReplyTo': 'replyTo'
        }

        # Create entry properties
        entry = (
            {k: given_mail.get(v) for k, v in mail_properties.items()}
        )

        # Create contacts properties
        entry.update(
            {k: build_contact(v) for k, v in contact_properties.items()}
        )

        if get_body:
            entry['Body'] = given_mail.get('body', {}).get('content')
        return entry

    def build_contact(contacts: dict or list or str) -> object:
        """Building contact object

        Args:
            contacts (list or dict or str):

        Returns:
            dict or list[dict] or str or None: describing contact

        >>> build_contact([{'emailAddress':{'name': 'Sample Name','address': 'user@example.com'}}])
        [{'Name': 'Sample Name', 'Address': 'user@example.com'}]

        >>> build_contact({'emailAddress':{'name': 'Sample Name','address': 'user@example.com'}})
        {'Name': 'Sample Name', 'Address': 'user@example.com'}

        >>> build_contact({}) is None
        True

        >>> build_contact([]) is None
        True
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
            value = page.get('value')
            if value:
                for mail in value:
                    mails_list.append(build_mail(mail))
            else:
                mails_list.append(build_mail(page))
    elif isinstance(raw_response, dict):
        return build_mail(raw_response)
    return mails_list


def file_builder(raw_response):
    name = raw_response.get('name')
    data = raw_response.get('contentBytes')
    data = base64.decodebytes(data)
    return fileResult(name, data)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    get_token()


def list_mails(user_id, folder_id, search, odata):
    no_folder = f'/users/{user_id}/messages'
    with_folder = f'users/{user_id}/mailFolders/{folder_id}/messages'
    pages_to_pull = demisto.args().get('pages_to_pull', 1)

    if search:
        odata = odata + f'$search={search}' if odata else f'$search={search}'

    suffix = with_folder if folder_id else no_folder
    response = http_request('GET', suffix, odata=odata)
    return pages_puller(response, assert_pages(pages_to_pull))


def list_mails_command():
    search = demisto.args().get('message_id')
    user_id = demisto.args().get('user_id')
    folder_id = demisto.args().get('folder_id')
    odata = demisto.args().get('odata_query')

    raw_response = list_mails(user_id, folder_id, search, odata)
    entry_context = {'MSGraphMail(var.ID === obj.ID)': build_mail_object(raw_response)}
    human_readable = f'### Total of {len(entry_context)} of mails received'
    return_outputs(human_readable, entry_context, raw_response)


def delete_mail(user_id: str, message_id: str, folder_id: str = None) -> True or False:
    with_folder = f'/users/{user_id}/mailFolders/{folder_id}/messages/{message_id}'
    no_folder = f'/users/{user_id}/messages/{message_id}'
    suffix = with_folder if folder_id else no_folder
    return http_request('DELETE', suffix)


def delete_mail_command():
    user_id = demisto.args().get('user_id')
    folder_id = demisto.args().get('folder_id')
    message_id = demisto.args().get('message_id')
    delete_mail(user_id, message_id, folder_id)

    human_readable = tableToMarkdown(
        'Message has been deleted',
        {
            'Message ID': message_id,
            'User ID': user_id,
            'Folder ID': folder_id
        },
        headers=['Message ID', 'User ID', 'Folder ID'],
        removeNull=True
    )

    entry_context = {
        f'MSGraphMail(val.ID == {message_id}': None
    }

    return_outputs(human_readable, entry_context)


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
    no_folder = f'/users/{user_id}/messages/{user_id}'
    with_folder = f'/users/{user_id}/mailFolders/{folder_id}/messages/{message_id}'

    if folder_id:
        suffix = with_folder
    else:
        suffix = no_folder

    response = http_request('GET', suffix, odata=odata)

    # Add user ID
    response['userId'] = user_id
    return response


def get_message_command():
    user_id = demisto.args().get('user_id')
    folder_id = demisto.args().get('folder_id')
    message_id = demisto.args().get('message_id')
    odata = demisto.args().get('odata')
    pull_attachment = demisto.args().get('get_attachment')
    raw_response = get_message(user_id, folder_id, message_id, odata=odata)
    entry_context = {'MSGraphMail(val.ID === obj.ID)': build_mail_object(raw_response)}
    if pull_attachment and raw_response.get('hasAttachment'):
        attachment = get_attachments()
        entry_context['MSGraphMail(val.ID === obj.ID)'].update(attachment)
    human_readable = tableToMarkdown(
        f'Results for message ID {message_id}',
        entry_context,
        headers=['ID', 'Subject', 'Send', 'Sender', 'From', 'HasAttachment']
    )
    return_outputs(
        human_readable,
        entry_context,
        raw_response=raw_response
    )


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
    with_folder = f'/users/{user_id}/mailFolders/{folder_id}/messages/{message_id}/attachments/{attachment_id}'
    suffix = with_folder if folder_id else no_folder
    response = http_request('GET', suffix)
    return response


def get_attachment_command():
    message_id = demisto.args().get('message_id')
    user_id = demisto.args().get('user_id')
    folder_id = demisto.args().get('folder_id')
    raw_response = get_attachment(message_id, user_id, folder_id)
    entry_context = file_builder(raw_response)
    demisto.results(entry_context)


def list_attachments(user_id: str, message_id: str, folder_id: str) -> dict:
    no_folder = f'/users/{user_id}/messages/{message_id}/attachments'
    with_folder = f'/users/{user_id}/mailFolders/{folder_id}/messages/{message_id}/attachments'


def list_attachments_command():
    user_id = demisto.args().get('user_id')
    message_id = demisto.args().get('message_id')
    folder_id = demisto.args().get('folder_id')
    raw_response = list_attachments(user_id, message_id, folder_id)


def main():
    """ GLOBALS/PARAMS """
    # Global annotation
    global CONTEXT, DEMISTOBOT, TOKEN, TENANT_ID, USE_SSL, BASE_URL
    CONTEXT = demisto.getIntegrationContext()
    DEMISTOBOT = 'https://demistobot.demisto.com/msg-mail-token'
    # Credentials
    TOKEN = demisto.params().get('token')
    TENANT_ID = demisto.params().get('tenant_id')
    # Remove trailing slash to prevent wrong URL path to service
    server = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else \
        demisto.params()['url']
    # Should we use SSL
    USE_SSL = not demisto.params().get('unsecure', False)
    # Service base URL
    BASE_URL = server + '/v1.0'

    # Remove proxy if not set to true in params
    if not demisto.params().get('proxy'):
        del os.environ['HTTP_PROXY']
        del os.environ['HTTPS_PROXY']
        del os.environ['http_proxy']
        del os.environ['https_proxy']

    ''' COMMANDS MANAGER / SWITCH PANEL '''
    # Global arguments
    command = demisto.command()
    LOG('Command being called is %s' % (demisto.command()))

    try:
        if command == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
            demisto.results('ok')
        elif command in ('msgraph-mail-list-emails', 'msgraph-mail-search-email'):
            list_mails_command()
        elif command == 'msgraph-mail-get-email':
            get_message_command()
        elif command == 'msgraph-mail-get-attachment':
            get_attachment_command()
        elif command == 'msgraph-mail-delete-email':
            delete_mail_command()
        elif command == 'msgraph-mail-list-attachments':
            list_attachments_command()
    # Log exceptions
    except Exception as e:
        LOG(e)
        LOG.print_log()
        raise


if __name__ == "builtins":
    main()
