import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

''' IMPORTS '''

import json
import requests
from distutils.util import strtobool
from urllib.parse import urlencode, urlparse, parse_qs
from datetime import datetime

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

# Service base URL


# Headers to be sent in requests
SITE_ID = 'Demistodev.sharepoint.com,142d3744-cd7e-4f4c-bbe9-f3dae7ebdc83,9e632eea-5727-4232-b68a-ecd4b9a460d4'
# TODO: this is only for debugging. remove it when test it in demisto.
VERSION = 'v1.0'
NETLOC = 'graph.microsoft.com'
BASE_URL = f'https://{NETLOC}/{VERSION}'
GRANT_TYPE = 'client_credentials'
SCOPE = 'https://graph.microsoft.com/.default'
INTEGRATION_NAME = 'MsGraph'

APP_NAME = 'ms-graph-files'


def epoch_seconds() -> int:
    """
    Return the number of seconds for return current date.
    """
    return int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds())


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
        ct_ = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct_)

    now = epoch_seconds()
    encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
    return encrypted


class Client(BaseClient):
    """
    Client will implement the service API, should not contain Demisto logic.
    Should do requests and return data
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.auth_id = demisto.params().get('auth_id')  # TODO: remove to const
        self.tenant_id = demisto.params().get('tenant_id')  # TODO: remove to const
        self.enc_key = demisto.params().get('enc_key')
        self.host = demisto.params().get('host')
        self.auto_url = f"https://login.microsoftonline.com/{demisto.params().get('tenant_id')}/oauth2/v2.0/token"  # TODO: remove to const
        self.tenant_domain = demisto.params().get('share_point_domain')
        self.access_token = self.get_access_token()
        self.headers = {'Authorization': f'Bearer {self.access_token}'}

    def http_call(self, *args, **kwargs):
        demisto.log(f'Sending: {kwargs}')
        res = self._http_request(*args, **kwargs)
        if 'status_code' in res and res.status_code == 401:
            self.access_token = self.get_access_token()
            res = self._http_request(*args, **kwargs)
        return res
    # def _http_request(self, method, url, params=None, data=None, json=None, headers=None, files=None):
    #     # A wrapper for requests lib to send our requests and handle requests and responses better
    #     res = requests.request(
    #         method,
    #         url,
    #         verify=self._verify,
    #         params=params,
    #         data=data,
    #         json=json,
    #         headers=headers,
    #         files=files
    #     )
    #     if res.status_code == 401:
    #         self.get_access_token()
    #
    #     # Handle error responses gracefully
    #     if res.status_code not in {200, 204, 201}:
    #         return_error('Error in API call to Example Integration [%d] - %s' % (res.status_code, res.reason))
    #
    #     if 'json' in res.headers.get('Content-Type'):
    #         demisto.log(f'{res.json()}')
    #         return res.json()
    #     else:
    #         demisto.log('Response content is not in JSON format.')  # in DELETE the response returns as text
    #         return res.status_code


    def return_valid_access_token_if_exist_in_context(self):
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        valid_until = integration_context.get('valid_until')
        if access_token and valid_until:
            if epoch_seconds() < valid_until:
                return access_token

    def return_token_and_save_it_in_context(self, access_token_response):
        access_token = access_token_response.get('access_token')
        if not access_token:
            return demisto.error('Access Token returned empty')
        expires_in = access_token_response.get('expires_in', 3595)
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer

        demisto.setIntegrationContext({
            'access_token': access_token,
            'valid_until': epoch_seconds() + expires_in
        })
        return access_token

    def get_access_token(self):
        context_access_token = self.return_valid_access_token_if_exist_in_context()
        if context_access_token:
            return context_access_token

        body = json.dumps({
            'app_name': APP_NAME,
            'registration_id': self.auth_id,
            'encrypted_token': get_encrypted(self.tenant_id, self.enc_key)
        })
        try:
            access_token_res = self._http_request(method='POST', full_url=self.host, data=body,
                                                  headers={'Accept': 'application/json'}, url_suffix='')
        except DemistoException as error:
            title = 'Error in authentication. Try checking the credentials you entered.'
            raise DemistoException(title, error)
        else:
            return self.return_token_and_save_it_in_context(access_token_res)


    def convert_site_name_to_site_id(self, site_name):
        url = BASE_URL + '/sites/' + self.tenant_domain + f':/sites/{site_name}?'
        query_string = {"$select": "id"}
        access_token = self.get_access_token()  # TODO: put this in a class and access token will be an attribute
        if not access_token:
            return False  # TODO: return an error
        final_headers = {}
        final_headers['Authorization'] = f'Bearer {access_token}'
        res = self._http_request('GET', url, headers=final_headers, params=query_string)
        try:
            site_id = res['id']
        except KeyError:
            demisto.error('could not get site id')
        else:
            return site_id

    def get_drive_id_for_site(self, site_id):
        access_token = self.get_access_token()  # TODO: put this in a class and access token will be an attribute

        headers = {'Authorization': f'Bearer {access_token}'}
        if not access_token:
            return False  # TODO: return an error
        url = BASE_URL + '/sites/' + site_id + '/drive'
        query_string = {"$select": "id"}

        res = self._http_request('GET', url, params=query_string, headers=headers)
        try:
            documents_id = res['id']
        except KeyError:
            demisto.error('could not get site id')
        else:
            return documents_id

    def find_documents_folder_id(self, site_id):
        # access_token = self.get_access_token()  # TODO: put this in a class and access token will be an attribute
        # # see premissions - why can't  I find sites
        # headers = {'Authorization': f'Bearer {access_token}'}
        # if not access_token:
        #     return False  # TODO: return an error
        # url = BASE_URL + '/sites/' + site_id + '/drive/root?'
        # query_string = {"$select": "id"}
        #
        # res = self._http_request('GET', url, params=query_string, headers=headers)
        # try:
        #     documents_id = res['id']
        # except KeyError:
        #     demisto.error('could not get site id')
        # else:
        #     return documents_id
        pass

    def get_item_id_by_path(self, path, site_id):
        # site_id = convert_site_name_to_site_id(site_name)  # TODO comment out
        # # TODO: path: need to add slash and back slash validation - path validation
        # access_token = self.get_access_token()  # TODO: put this in a class and access token will be an attribute
        # headers = {'Authorization': f'Bearer {access_token}'}
        # query_string = {"$select": "id"}
        # url = BASE_URL + f'/sites/{site_id}/drive/root:/{path}?'
        #
        # res = self._http_request('GET', url, params=query_string, headers=headers)
        # try:
        #     item_id = res['id']
        # except KeyError:
        #     raise  # TODO: handle exception
        # else:
        #     return item_id
        pass

    def validate_url_netloc(self, url):
        try:
            parsed_url = urlparse(url)
            if NETLOC not in parsed_url.netloc:
                return False  # TODO: need to add demisto error - "url not valid, see @odata.nextLink"

        except ValueError:
            raise  # TODO see how to return an error to demisto
        else:
            return parsed_url

    def url_validation(self, url):
        # test if netloc
        parsed_url = self.validate_url_netloc(url)

        # test if exits $skiptoken
        try:
            url_parameters = parse_qs(parsed_url.query)
            if not url_parameters.get('$skiptoken', False) or not url_parameters['$skiptoken']:
                return False  # TODO: need to add demisto error - "url not valid, see @odata.nextLink, missing $skiptoken"

        except ValueError:
            raise  # TODO see how to return an error to demisto " could not parse parameters""url not valid, see @odata.nextLink"

    def list_tenant_sites(self):
        url = 'https://graph.microsoft.com/v1.0/sites/root'
        return self.http_call(method='GET', full_url=url, headers=self.headers, url_suffix='')


    def list_drives_in_site(self, site_id=None, limit=None, next_page_url=None):
        # check if got site_id or next_page args
        # if next_page -> do validation to next_page
        # perform request.

        if not any([site_id, next_page_url]):
            raise DemistoException('Please pass at least one argument to this command: \n'
                                   'site_id: if you want to get all sites.\n'
                                   'limit: if you want to limit the number of command\'s results. \n'
                                   'next_page_url: if you have used the limit argument')

        if limit:
            params = urlencode({'$top': limit})
        else:
            params = ''

        if next_page_url:
            self.url_validation(next_page_url)
            url = next_page_url
        else:
            url = f'{BASE_URL}/sites/{site_id}/drives'

        return self.http_call('GET', full_url=url, params=params, headers=self.headers, url_suffix='')

    def list_drive_children(self, object_type, object_type_id, item_id=None, limit=None, next_page_url=None):
        if next_page_url:
            url = next_page_url
        else:
            if not item_id:
                item_id = 'root'
            if object_type == 'drives':
                url = f'{object_type}/{object_type_id}/items/{item_id}/children'

            elif object_type in ['groups', 'sites', 'users']:
                url = f'{object_type}/{object_type_id}/drive/items/{item_id}/children'

            url = BASE_URL + f'/{url}'

        if limit:
            params = urlencode({'$top': limit})
        else:
            params = ''

        return self.http_call(method='GET', full_url=url, url_suffix='', params=params, headers=self.headers)

    def replace_existing_file(self, object_type, object_type_id, item_id, entry_id):

        file_path = demisto.getFilePath(entry_id).get('path')
        if object_type == 'drives':
            url = f'{object_type}/{object_type_id}/items/{item_id}/content'

        elif object_type in ['groups', 'sites', 'users']:
            url = f'{object_type}/{object_type_id}/drive/items/{item_id}/content'

        # send request
        url = BASE_URL + f'/{url}'
        with open(file_path, 'rb') as file:
            self.headers['Content-Type'] = 'application/octet-stream'
            return self.http_call('PUT', full_url=url, data=file, headers=self.headers, url_suffix='')

    def delete_file(self, object_type, object_type_id, item_id):
        if object_type == 'drives':
            url = f'{object_type}/{object_type_id}/items/{item_id}'

        elif object_type in ['groups', 'sites', 'users']:
            url = f'{object_type}/{object_type_id}/drive/items/{item_id}'

        # send request
        url = BASE_URL + f'/{url}'
        self.headers['Content-Type'] = 'text/plain'  # request returned empty and can not decoded to json
        if '' is self.http_call('DELETE', full_url=url, headers=self.headers, url_suffix='', resp_type='text'):
            # resp_type='text' returned empty and can not decoded to json
            return f'\"{item_id}\" was deleted successfully'


    def upload_new_file(self, object_type, object_type_id, parent_id, file_name, entry_id):
        """
        this function upload new file to a selected folder(parent_id)
        :param object_type: drive/ group/ me/ site/ users
        :param object_type_id: the selected object type id.
        :param parent_id:
        :param file_name:
        :param entry_id:
        :return:
        """
        file_path = demisto.getFilePath(entry_id).get('path')
        if 'drives' == object_type:
            url = f'{object_type}/{object_type_id}/items/{parent_id}:/{file_name}:/content'

        elif object_type in ['groups', 'users', 'sites']:
            url = f'{object_type}/{object_type_id}/drive/items/{parent_id}:/{file_name}:/content'
            # for sites, groups, users
        url = BASE_URL + f'/{url}'
        with open(file_path, 'rb') as file:
            self.headers['Content-Type'] = 'application/octet-stream'
            return self.http_call('PUT', full_url=url, headers=self.headers, url_suffix='', data=file)


    def download_file(self, object_type, object_type_id, item_id):
        if object_type == 'drives':
            url = f'{object_type}/{object_type_id}/items/{item_id}/content'

        elif object_type in ['groups', 'sites', 'users']:
            url = f'{object_type}/{object_type_id}/drive/items/{item_id}/content'

        # send request
        url = BASE_URL + f'/{url}'
        res = self.http_call('GET', full_url=url, headers=self.headers, url_suffix='', resp_type='')  # it needs
        # resp_type='' to stay empty because if response type is empty http_requests returned the raw response.
        # I need it because graph api returnes an response as text without content so res.text fails
        return res


    def create_new_folder(self, object_type, object_type_id, parent_id, folder_name):
        if object_type == 'drives':
            url = f'{object_type}/{object_type_id}/items/{parent_id}/children'

        elif object_type in ['groups', 'sites', 'users']:
            url = f'{object_type}/{object_type_id}/drive/items/{parent_id}/ children'

        # send request
        url = BASE_URL + f'/{url}'

        payload = {
            'name': folder_name,  # TODO: need to add type validation.
            'folder': {},
            '@microsoft.graph.conflictBehavior': 'rename'
        }
        self.headers['Content-Type'] = 'application/json'
        demisto.log(f'sending POST to {url}, with the next payload: {payload}')
        return self.http_call('POST', full_url=url, json_data=payload, headers=self.headers, url_suffix='')


def download_file_command(client, args):
    object_type = args.get('object_type')
    object_type_id = args.get('object_type_id')
    item_id = args.get('item_id')

    result = client.download_file(object_type=object_type, object_type_id=object_type_id, item_id=item_id)
    screen_path = result.url

    stored_img = fileResult(item_id, result.content)

    context_entry = result  # TODO: think about what I want to return to the user: file name ? location? date_of_creation ?

    title = f'{INTEGRATION_NAME} - File information:'
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entry.content.decode("utf-8"), headers=item_id)

    # context == output
    context = {
        f'{INTEGRATION_NAME}.File(val.ID && val.ID === obj.ID)': context_entry.content.decode("utf-8"),
        'File': stored_img['File'],
        'FileID': stored_img['FileID'],
    }

    return (
        {
            'Type': entryTypes['file'],
            'ContentsFormat': formats['text'],
            'File': stored_img['File'],
            'FileID': stored_img['FileID'],
            'Contents': ''
        }
    )


def list_drive_children_command(client, args):
    object_type = args.get('object_type')
    object_type_id = args.get('object_type_id')
    item_id = args.get('item_id')
    limit = args.get('limit')
    next_page_url = args.get('next_page_url')

    result = client.list_drive_children(object_type=object_type, object_type_id=object_type_id, item_id=item_id,
                                        limit=limit, next_page_url=next_page_url)

    context_entry = result  # TODO: think about what I want to return to the user: file name ? location? date_of_creation ?

    title = f'{INTEGRATION_NAME} - drivesItems information:'
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entry)

    # context == output
    context = {
        f'{INTEGRATION_NAME}.drivesItems(val.ID && val.ID === obj.ID)': context_entry
    }

    return (
        human_readable,
        context,
        result
    )


def list_tenant_sites_command(client, args):
    result = client.list_tenant_sites()

    context_entry = result  # TODO: think about what I want to return to the user: file name ? location? date_of_creation ?

    title = f'{INTEGRATION_NAME} - Sites information:'
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entry)

    # context == output
    context = {
        f'{INTEGRATION_NAME}.Sites(val.ID && val.ID === obj.ID)': context_entry
    }

    return (
        human_readable,
        context,
        result
    )


def list_drives_in_site_command(client, args):
    site_id = args.get('site_id')
    limit = args.get('limit')
    next_page_url = args.get('next_page_url')

    result = client.list_drives_in_site(site_id=site_id, limit=limit, next_page_url=next_page_url)

    context_entry = result  # TODO: think about what I want to return to the user: file name ? location? date_of_creation ?

    title = f'{INTEGRATION_NAME} - Drives information:'
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entry)

    # context == output
    context = {
        f'{INTEGRATION_NAME}.Drives(val.ID && val.ID === obj.ID)': context_entry
    }

    return (
        human_readable,
        context,
        result
    )


def replace_an_existing_file_command(client, args):
    object_type = args.get('object_type')
    item_id = args.get('item_id')
    entry_id = args.get('entry_id')
    object_type_id = args.get('object_type_id')

    result = client.replace_existing_file(object_type, object_type_id, item_id, entry_id)

    context_entry = result  # TODO: think about what I want to return to the user: file name ? location? date_of_creation ?

    title = f'{INTEGRATION_NAME} - File information:'
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entry)

    # context == output
    context = {
        f'{INTEGRATION_NAME}.Document(val.ID && val.ID === obj.ID)': context_entry
    }

    return (
        human_readable,
        context,
        result
    )


def upload_new_file_command(client, args):
    object_type = args.get('object_type')
    object_type_id = args.get('object_type_id')
    parent_id = args.get('parent_id')
    file_name = args.get('file_name')
    entry_id = args.get('entry_id')

    result = client.upload_new_file(object_type, object_type_id, parent_id, file_name, entry_id)

    context_entry = result  # TODO: think about what I want to return to the user: file name ? location? date_of_creation ?

    title = f'{INTEGRATION_NAME} - File information:'
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entry)

    # context == output
    context = {
        f'{INTEGRATION_NAME}.Document(val.ID && val.ID === obj.ID)': context_entry
    }

    return (
        human_readable,
        context,
        result
    )


def create_new_folder_command(client, args):
    object_type = args.get('object_type')
    parent_id = args.get('parent_id')
    folder_name = args.get('folder_name')
    object_type_id = args.get('object_type_id')

    result = client.create_new_folder(object_type, object_type_id, parent_id, folder_name)

    context_entry = result  # TODO: think about what I want to return to the user: file name ? location? date_of_creation ?

    title = f'{INTEGRATION_NAME} - Folder information:'
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entry)

    # context == output
    context = {
        f'{INTEGRATION_NAME}.Folder(val.ID && val.ID === obj.ID)': context_entry
    }

    return (
        human_readable,
        context,
        result
    )


def delete_file_command(client, args):
    object_type = args.get('object_type')
    item_id = args.get('item_id')
    object_type_id = args.get('object_type_id')

    deleted_file_id, text = client.delete_file(object_type, object_type_id, item_id)

    context_entry = text  # TODO: think about what I want to return to the user: file name ? location? date_of_creation ?

    title = f'{INTEGRATION_NAME} - File information:'
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entry, headers=deleted_file_id)

    # context == output
    context = {
        f'{INTEGRATION_NAME}.File(val.ID && val.ID === obj.ID)': context_entry
    }

    return (
        human_readable,
        context,
        text  # == raw response
    )


def main():
    # CLIENT_ID = demisto.params().get('client_id')
    # CLIENT_SECRET = demisto.params().get('client_secret')
    # Remove trailing slash to prevent wrong URL path to service
    # SERVER = f"https://login.microsoftonline.com/{demisto.params().get('tenant_id')}"

    # Should we use SSL
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        # client = Client(BASE_URL, proxy=proxy, verify=verify_certificate)
        client = Client(base_url=BASE_URL, verify=verify_certificate, proxy=proxy, ok_codes=(200, 204, 201))
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'msgraph-delete-file':
            return_outputs(*delete_file_command(client, demisto.args()))
        elif demisto.command() == 'msgraph-download-file':
            demisto.results(download_file_command(client, demisto.args()))  # it has to be demisto.results instead
            # of return_outputs. because fileResult contains 'content': '' and if that key is empty return_outputs
            # returns error
        elif demisto.command() == 'msgraph-list-tenant-sites':
            return_outputs(*list_tenant_sites_command(client, demisto.args()))
        elif demisto.command() == 'msgraph-list-drive-children':
            return_outputs(*list_drive_children_command(client, demisto.args()))
        elif demisto.command() == 'msgraph-create-new-folder':
            return_outputs(*create_new_folder_command(client, demisto.args()))
        elif demisto.command() == 'msgraph-replace-existing-file':
            return_outputs(*replace_an_existing_file_command(client, demisto.args()))
        elif demisto.command() == 'msgraph-list-drives-in-site':
            return_outputs(*list_drives_in_site_command(client, demisto.args()))
        elif demisto.command() == 'msgraph-upload-new-file':
            return_outputs(*upload_new_file_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}', e)

''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client):
    """
    Performs basic get request to get item samples
    """

    result = client.get_access_token()
    if result.get('access_token', False):
        return 'ok'
    else:
        return 'Test failed because could not get access token'


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
