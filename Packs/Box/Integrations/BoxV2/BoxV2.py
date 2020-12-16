import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
import time
import secrets
import jwt
import re
from distutils.util import strtobool
from datetime import timezone
from typing import Any, Dict, Tuple, List, Optional, BinaryIO
from requests.models import Response
from hashlib import sha1
from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%z'
MAX_INCIDENTS_TO_FETCH = 50

''' CLIENT CLASS '''


class QueryHandler:
    """
    Class which handles the search query parameters for the box-search-content command.
    """
    def __init__(self, args):
        self.content_types = []
        self.type = args.get('type')
        self.ancestor_folder_ids = args.get('ancestor_folder_ids')
        self.item_name = args.get('item_name')
        self.item_description = args.get('item_description')
        self.comments = args.get('comments')
        self.tag = args.get('tag')
        self.created_range = format_time_range(args.get('created_range'))
        self.file_extensions = args.get('file_extensions')
        self.limit = args.get('limit')
        self.offset = args.get('offset')
        self.owner_user_ids = args.get('owner_uids')
        self.trash_content = args.get('trash_content')
        self.updated_at_range = format_time_range(args.get('updated_at_range'))
        self.query = args.get('query')
        self.args = args

        if self.item_name:
            self.content_types.append('name')
            self.query = self.item_name
            self.item_name = None
        if self.item_description:
            self.content_types.append('description')
            self.query = self.item_description
            self.item_description = None
        if self.tag:
            self.content_types.append('tag')
            self.query = self.tag
            self.tag = None
        if self.comments:
            self.content_types.append('comments')
            self.query = self.comments
            self.comments = None

    def prepare_params_object(self):
        """
        Creates a dictionary of all available arguments. This method allows for args to be
        manipulated and formatted prior to use.
        :return: dict containing the formatted query parameters
        """
        query_params_dict = vars(QueryHandler(self.args))
        query_params_dict.pop('args')
        return remove_empty_elements(query_params_dict)


class FileShareLink:
    """
    Class which handles the File Share Link object for CRUD operations.
    """

    def __init__(self, args):
        self.access = args.get('access')
        self.password = args.get('password')
        self.unshared_at = args.get('unshared_at')
        self.permissions = {'can_download': bool(strtobool(args.get('can_download', 'False')))}
        self.file_id = args.get('file_id')
        self.args = args

    def prepare_request_object(self):
        """
        Creates a dictionary of all available arguments. This method allows for args to be
        manipulated and formatted prior to use.
        :return: dict containing the formatted FileShareLink arguments as required by the API.
        """
        file_share_dict = vars(FileShareLink(self.args))
        file_share_dict.pop('file_id')
        file_share_dict.pop('args')
        return remove_empty_elements(file_share_dict)


class FolderShareLink:
    """
    Class which handles the Folder Share Link object for CRUD operations.
    """

    def __init__(self, args):
        self.access = args.get('access')
        self.password = args.get('password')
        self.unshared_at = args.get('unshared_at')
        self.permissions = {'can_download': bool(strtobool(args.get('can_download', 'False')))}
        self.folder_id = args.get('folder_id')
        self.args = args

        if self.folder_id == '0':
            raise DemistoException('The root folder is incapable of being shared. Please provide a '
                                   'valid folder id.')

    def prepare_request_object(self):
        """
        Creates a dictionary of all available arguments. This method allows for args to be
        manipulated and formatted prior to use.
        :return: dict containing the formatted FolderShareLink arguments as required by the
        API.
        """
        folder_share_dict = vars(FolderShareLink(self.args))
        folder_share_dict.pop('folder_id')
        folder_share_dict.pop('args')
        return remove_empty_elements(folder_share_dict)


class Event:
    """
    Class which handles the Event objects for incident creation.
    """

    def __init__(self, raw_input):
        #  Created at time is stored in either or two locations, never both.
        created_at = raw_input.get('created_at')
        _created_at = raw_input.get('source').get('created_at')
        self.created_at = created_at if created_at is not None else _created_at
        self.event_id = raw_input.get('event_id')
        self.event_type = raw_input.get('event_type')
        self.labels = raw_input

    def format_incident(self):
        incident = {
            'name': f'Incident ID: {self.event_id} - {self.event_type}',
            'occurred': self.created_at,
            'rawJSON': json.dumps(self.labels)
        }
        return incident


class Client(BaseClient):
    """
    Client class to interact with the service API
    """
    def __init__(self, base_url, verify, proxy, auth_params, as_user=None):
        try:
            self.credentials_dict = json.loads(auth_params.get('credentials_json', '{}'))
        except ValueError as e:
            raise DemistoException("Failed to parse the credentials JSON. Please verify the JSON is "
                                   "valid.", exception=e)
        self.credentials = self.credentials_dict.get('boxAppSettings')
        self.client_id = self.credentials.get('clientID')
        self.app_auth = self.credentials.get('appAuth')
        self.client_secret = self.credentials.get('clientSecret')
        self.public_key_id = self.app_auth.get('publicKeyID')
        self.private_key = self.app_auth.get('privateKey')
        self.passphrase = self.app_auth.get('passphrase')
        self.enterprise_id = self.credentials_dict.get('enterpriseID')
        self.authentication_url = 'https://api.box.com/oauth2/token'
        self.as_user = as_user

        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._headers = self._request_token()

    def _decrypt_private_key(self):
        """
        Attempts to load the private key as given in the integration configuration.

        :return: an initialized Private key object.
        """
        try:
            key = load_pem_private_key(
                data=self.private_key.encode('utf8'),
                password=self.passphrase.encode('utf8'),
                backend=default_backend(),
            )
        except (TypeError, ValueError, exceptions.UnsupportedAlgorithm) as exception:
            raise DemistoException("An error occurred while loading the private key.", exception)
        return key

    def _create_jwt_assertion(self):
        """
        Establishes the claims based on information retrieved from the integration configuration.
        Afterwards the assertion is encoded to be sent as a parameter for the token request.

        :return: encoded jwt assertion object.
        """
        if self.as_user:
            claims = {
                'iss': self.client_id,
                'sub': self.as_user,
                'box_sub_type': 'user',
                'aud': self.authentication_url,
                'jti': secrets.token_hex(64),
                'exp': round(time.time()) + 45
            }
        else:
            claims = {
                'iss': self.client_id,
                'sub': self.enterprise_id,
                'box_sub_type': 'enterprise',
                'aud': self.authentication_url,
                'jti': secrets.token_hex(64),
                'exp': round(time.time()) + 45
            }

        assertion = jwt.encode(
            payload=claims,
            key=self._decrypt_private_key(),
            algorithm='RS512',
            headers={
                'kid': self.public_key_id
            }
        )
        return assertion

    def _request_token(self):
        """
        Handles the actual request made to retrieve the access token.

        :return: Access token to be used in the authorization header for each request.
        """
        params = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': self._create_jwt_assertion().decode("utf-8"),
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

        response = self._http_request(
            method='POST',
            url_suffix=None,
            full_url=self.authentication_url,
            json_data=params
        )
        access_token = response.get('access_token')
        auth_header = {'Authorization': f'Bearer {access_token}'}
        return auth_header

    def search_content(self, as_user: str, query_object: QueryHandler) -> Dict[str, Any]:
        """
        Searches for files, folders, web links, and shared files across the users content or across
        the entire enterprise.

        :param as_user: str - the user ID of for whom the request is being made.
        :param query_object: QueryHandler - an object containing the data required for the query.
        :return: dict containing the results from the http request.
        """
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='GET',
            url_suffix='/search/',
            params=query_object.prepare_params_object()
        )

    def find_file_folder_by_share_link(self, shared_link: str, password: str) -> Dict[str, Any]:
        """
        Return the file represented by a shared link.

        :param shared_link: str - the link which is being queried against.
        :param password: str - the password associated with the link.
        :return: dict containing the results from the http request.
        """
        shared_link_header = f'shared_link={shared_link}'
        if password:
            password_header_part = f'&shared_link_password={password}'
            shared_link_header = shared_link_header + password_header_part
        self._headers.update({'BoxApi': shared_link_header})
        return self._http_request(
            method='GET',
            url_suffix='shared_items/',
            resp_type='json'
        )

    def get_shared_link_by_file(self, file_id: str, as_user: str) -> Dict[str, Any]:
        """
        Gets the shared link associated with a particular file.

        :param file_id: str - ID of the file.
        :param as_user: str - The ID of the user making the request.
        :return: dict containing the results from the http request.
        """
        url_suffix = f'/files/{file_id}/'
        request_params = {'fields': 'shared_link'}
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=request_params
        )

    def crud_file_share_link(self, file_share_link: FileShareLink, as_user: str,
                             is_delete: bool = False
                             ) -> Dict[str, Any]:
        """
        CRUD function which makes the request to the API based on the given parameters.

        :param file_share_link: FileShareLink object containing the formatted request object.
        :param as_user: str - The ID of the user making the request.
        :param is_delete: bool - Indicates if the request should result in the deletion of the
        share link.
        :return: dict containing the results from the http request.
        """
        url_suffix = f'/files/{file_share_link.file_id}/'
        if not is_delete:
            request_body = file_share_link.prepare_request_object()
        else:
            request_body = None
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='PUT',
            url_suffix=url_suffix,
            json_data={"shared_link": request_body},
            params={
                'fields': 'shared_link'
            }
        )

    def get_shared_link_by_folder(self, folder_id: str, as_user: str):
        """
        Handles the request to find a shared link based on the folder id.

        :param folder_id: str - The UUID of the folder to find a shared link for.
        :param as_user: str - The ID of the user making the request.
        :return: dict containing the results from the http request.
        """
        url_suffix = f'/folders/{folder_id}/'
        request_params = {'fields': 'shared_link'}
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=request_params
        )

    def crud_folder_share_link(self, folder_share_link: FolderShareLink, as_user: str,
                               is_delete: bool = False) -> Dict[str, Any]:
        """
        CRUD function which makes the request to the API based on the given parameters.

        :param folder_share_link: FolderShareLink object containing the formatted request object.
        :param as_user: str - The ID of the user making the request.
        :param is_delete: bool - Indicates if the request should result in the deletion of the
        share link.
        :return: dict containing the results from the http request.
        """
        url_suffix = f'/folders/{folder_share_link.folder_id}/'
        if not is_delete:
            request_body = folder_share_link.prepare_request_object()
        else:
            request_body = None
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='PUT',
            url_suffix=url_suffix,
            json_data={"shared_link": request_body},
            params={
                'fields': 'shared_link'
            }
        )

    def get_folder(self, folder_id: str, as_user: str):
        """
        Retrieves the folder's details based on the ID associated with the folder.

        :param folder_id: str - UUID for the folder.
        :param as_user: str - The ID of the user making the request.
        :return: dict containing the results from the http request.
        """
        url_suffix = f'/folders/{folder_id}/'

        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_folder_items(self, folder_id: str, as_user: str, limit: int, offset: int, sort: str):
        """
        Lists the items contained in a folder. Default limit established by Box is 50 items.

        :param folder_id: str - UUID for the folder.
        :param as_user: str - The ID of the user making the request.
        :param limit: - int - Limits the amount of results returned.
        :param offset: - int - Handles the index offset. Used for rudimentary pagination.
        :param sort: - str - ASC or DESC indicates the order to return results.
        :return: dict containing the results from the http request.
        """
        url_suffix = f'/folders/{folder_id}/'
        request_params = {
            'limit': limit,
            'offset': offset,
            'sort': sort
        }
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=request_params
        )

    def folder_create(self, name: str, parent_id: str, as_user: str):
        """
        Creates a folder with the given name. For files residing under the root of the users
        directory, please use '0'.

        :param name: str - The name of the folder. Must be ASCII characters and devoid of `/` or
        `\`.
        :param parent_id: - The ID of the folder which the folder will be created under.
        :param as_user: str - The ID of the user making the request.
        :return: dict containing the results from the http request.
        """
        url_suffix = '/folders/'
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data={
                "name": name,
                "parent": {
                    "id": parent_id
                }
            },
            params={
                'fields': 'shared_link'
            }
        )

    def file_delete(self, file_id: str, as_user: str):
        """
        Deletes a file when given the file's UUID.

        :param file_id: str - UUID for the file.
        :param as_user: str - The ID of the user making the request.
        :return: Status code indicating success or not.
        """
        url_suffix = f'/files/{file_id}'
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='DELETE',
            url_suffix=url_suffix,
            return_empty_response=True
        )

    def list_users(self, fields: str = None, filter_term: str = None, limit: int = None,
                   offset: int = None, user_type: str = None):
        """
        Lists the users found in the enterprise. Used for finding the `as_user` argument/parameter
        which is required to make requests on behalf of that user.

        :param fields: str - CSV string indicating which fields to search within - id,type,name.
        :param filter_term: str - The term used in the search.
        :param limit: int - limits the returned results.
        :param offset: int - Used for rudimentary pagination of results.
        :param user_type: str - Indicates the type of user being searched for.
        :return: dict containing the results from the http request.
        """
        url_suffix = '/users/'
        query_params = {
            'fields': fields,
            'filter_term': filter_term,
            'limit': limit,
            'offset': offset,
            'user_type': user_type
        }
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=remove_empty_elements(query_params)
        )

    def _create_upload_session(self, file_name: Optional[str], file_size: int, folder_id: Optional[str],
                               as_user: Optional[str]) -> dict:
        """
        Each file upload where the file is greater than the maximum_chunk_size of 50MBs requires a
        session to be created. This session returns the endpoints and determined chunk size required
        by the Box API for chunked uploads.

        :param file_name: str - The name of the file being uploaded. Must contain an extension.
        :param file_size: int - Size of the file as determined by os.path.getsize()
        :param folder_id: str - The ID of the folder where the file will be uploaded to.
        :param as_user: str - The ID of the user making the request.
        :return: dict containing the details of the upload session.
        """
        url_suffix = '/files/upload_sessions'
        self._base_url = 'https://upload.box.com/api/2.0'
        self._headers.update({'As-User': as_user})
        upload_data = {
            'file_name': file_name,
            'file_size': file_size,
            'folder_id': folder_id
        }
        return self._http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=upload_data
        )

    @staticmethod
    def read_in_chunks(file_object: BinaryIO, chunk_size: int = 65536):
        """
        Generator function used to read the file according to the chunk_size given by the Box API.

        :param file_object: BinaryIO object of the file.
        :param chunk_size: int - Size of the required chunks
        :return: Iterator containing file objects of the determined size.
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def chunk_upload(self, file_name: Optional[str], file_size: int, file_path: str,
                     folder_id: Optional[str], as_user: Optional[str]):
        """
        Handles the uploading of the file parts to the session endpoint. Box requires a SHA1 digest
        hash to be included as part of the request headers. This function handles that as it
        iterates
        over the file object.

        :param file_name: str - The name of the file.
        :param file_size: int - The size of the file in bytes.
        :param file_path: str - The path of where the file is located. Used for reading the file.
        :param folder_id: str - The folder ID for the parent folder which will contain the file.
        :param as_user: str - The ID of the user making the request.
        :return: tuple - parts - list - an array of dictionaries containing details of the part
                                        which was uploaded.
                       - upload_url_suffix - str - The endpoint used for uploading the file. Used in
                                                   the request made to commit the file once it has
                                                   been uploaded.
        """
        upload_session_data = self._create_upload_session(file_name=file_name, file_size=file_size,
                                                          folder_id=folder_id, as_user=as_user)
        session_id: str = upload_session_data.get('id')  # type:ignore
        part_size: int = upload_session_data.get('part_size')  # type:ignore
        upload_url_suffix = f'/files/upload_sessions/{session_id}'
        parts = []
        index = 0
        with open(file_path, 'rb') as file_object:
            for chunk in self.read_in_chunks(file_object, part_size):
                content_sha1 = sha1()
                content_sha1.update(chunk)
                part_content_sha1 = content_sha1.digest()
                offset = index + len(chunk)
                self._headers.update({
                    'Content-Type': 'application/octet-stream',
                    'As-User': as_user,
                    'Content-length': str(file_size),
                    'Content-Range': 'bytes %s-%s/%s' % (index, offset - 1, file_size),
                    'Digest': f"SHA={base64.b64encode(part_content_sha1).decode('utf-8')}"
                })

                r = self._http_request(
                    method='PUT',
                    url_suffix=upload_url_suffix,
                    data=chunk
                )
                parts.append(r.get('part'))
                index = offset
        return parts, upload_url_suffix

    def commit_file(self, file_path: str, as_user: Optional[str], parts: List[Dict],
                    upload_url_suffix: str) -> dict:
        """
        Once a file has been uploaded, the file must be committed. This request requires the SHA1
        digest of the entire file to be sent in the header. We reread the file to ensure the SHA is
        calculated properly.

        :param file_path: str - Path of where the file is located.
        :param as_user: str - The ID of the user making the request.
        :param parts: - list[dicts] - Contains information returned by the API for each part which
                                      was uploaded.
        :param upload_url_suffix: - str - The url suffix used to commit the file. (unique and given
                                          only after requesting the upload session)
        :return: dict containing the results of the upload session.
        """
        with open(file_path, 'rb') as file_obj:
            final_sha = sha1()
            final_sha.update(file_obj.read())
            whole_file_sha_digest = final_sha.digest()
            final_headers = {
                'Content-Type': 'application/json',
                'As-User': as_user,
                'Digest': f"SHA={base64.b64encode(whole_file_sha_digest).decode('utf-8')}",
                'Authorization': self._headers.get('Authorization')
            }
            return self._http_request(
                method='POST',
                url_suffix=upload_url_suffix + '/commit',
                json_data={'parts': parts},
                headers=final_headers
            )

    def upload_file(self, entry_id: str, file_name: Optional[str] = None, folder_id: Optional[str] = None,
                    as_user: Optional[str] = None) -> dict:
        """
        Main function used to handle the `box-upload-file` command. Box enforces size limitations
        which determines which endpoint is used to upload a file. for files under 50MB, the generic
        endpoint is used. For files over 50MB, an upload session must be requested.

        :param entry_id: str - Entry ID of the file uploaded to the war room.
        :param file_name: str - Name which the file will be saved as. Must contain an extension.
        :param folder_id: str - The UUID of the folder which the file will be contained in.
        :param as_user: str - The ID of the user making the request.
        :return: dict containing the results of the upload request.
        """
        self._base_url = 'https://upload.box.com/api/2.0'
        #  Because of _course_ they have a separate base_url for uploads
        maximum_chunk_size = 20000000
        demisto_file_object = demisto.getFilePath(entry_id)
        if not file_name:
            file_name = demisto_file_object.get('name')
        #  Box requires files to have a file extension. We validate that here.
        if '.' not in file_name:  # type: ignore
            raise DemistoException('A file extension is required in the filename.')
        file_path = demisto_file_object.get('path')
        file_size = os.path.getsize(file_path)
        if file_size > maximum_chunk_size:
            parts, upload_url_suffix = self.chunk_upload(file_name, file_size, file_path, folder_id,
                                                         as_user)
            return self.commit_file(file_path, as_user, parts, upload_url_suffix)
        else:
            with open(file_path, 'rb') as file:
                self._headers.update({
                    'As-User': as_user
                })
                upload_url_suffix = '/files/content'
                attributes = {
                    'name': file_name,
                    'parent': {'id': '0'}
                }
                data = {'attributes': json.dumps(attributes)}
                files = {'file': ('unused', file)}
                return self._http_request(
                    method='POST',
                    url_suffix=upload_url_suffix,
                    data=data,
                    files=files
                )

    def trashed_items_list(self, as_user: str, limit: int, offset: int):
        """
        Lists the items which have been sent to trash by the user making the request.

        :param as_user: str - The ID of the user making the request.
        :param limit: int - The maximum amount of results to return.
        :param offset: int - Used for rudimentary pagination.
        :return: dict containing the results of the request.
        """
        url_suffix = '/folders/trash/items/'
        request_params = {
            'limit': limit,
            'offset': offset
        }
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=request_params
        )

    def trashed_item_restore(self, item_id: str, type: str, as_user: str):
        """
        Uses the item_id and item type to restore the item once it has been deleted.

        :param item_id: str - The UUID of the item being restored.
        :param type: str - The type of item being restored. file or folder.
        :param as_user: str - The ID of the user making the request.
        :return: dict containing the results of the request.
        """
        # The url requires a plural version of the item.
        url_suffix = f'/{type + "s"}/{item_id}'
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='POST',
            url_suffix=url_suffix
        )

    def trashed_item_permanently_delete(self, item_id: str, type: str, as_user: str):
        """
        Permanently deletes an item which has been trashed. Please note this can only be performed
        on items which have already been trashed.

        :param item_id: str - UUID of the item to be permanently deleted.
        :param type: str - The type of the item.
        :param as_user: str - The ID of the user making the request.
        :return: Status code indicating success/failure of the request.
        """
        url_suffix = f'/{type + "s"}/{item_id}/trash/'
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='DELETE',
            url_suffix=url_suffix,
            return_empty_response=True
        )

    def list_events(self, as_user: str, stream_type: str, created_after: str = None,
                    limit: int = None):
        """
        Lists the events which have occurred given the as_user argument/parameter. Same endpoint is
        used to also handle the enterprise logs as well.

        :param as_user: str - The ID of the user making the request.
        :param stream_type: str - Indicates the type of logs to be retrieved.
        :param created_after: str - Is used the return only events created after the given time.
        :param limit: int - The maximum amount of events to return.
        :return: dict - The results for the given logs query.
        """
        url_suffix = '/events/'
        self._headers.update({'As-User': as_user})
        request_params = {
            'stream_type': stream_type
        }
        if created_after:
            request_params.update({'created_after': created_after})
        if limit:
            request_params.update({'limit': limit})  # type:ignore
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=request_params
        )

    def get_current_user(self, as_user: str):
        """
        Gets the details for the user currently logged in. The current user is identified by the
        `As-User` header value.

        :param as_user: str - The ID of the user making the request.
        :return: dict - The details for the current user.
        """
        url_suffix = '/users/me/'
        self._headers.update({'As-User': as_user})
        return self._http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def create_update_user(self, as_user: str = None, login: str = None, name: str = None,
                           role: str = None,
                           language: str = None, is_sync_enabled: bool = False,
                           job_title: str = None, phone: str = None, address: str = None,
                           space_amount: int = None, tracking_codes: List[Dict] = None,
                           can_see_managed_users: bool = False, time_zone: str = None,
                           is_exempt_from_device_limits: bool = False,
                           is_exempt_from_login_verification: bool = False,
                           is_external_collab_restricted: bool = False,
                           is_platform_access_only: bool = False, status: str = None,
                           user_id: str = None,
                           update_user: bool = False, is_update: bool = False) -> dict:
        """
        This function handles the creation and update of users for Box. The same request object is
        sent for both calls.

        :param update_user: bool - Indicates if the function should update the user instead of
                                   create one.
        :param user_id: str - The ID of the user. Only used for updates.
        :param as_user: str - The ID of the user making the request.
        :param login: str - The email which will be used to login.
        :param name: str - The name of the user.
        :param role: str - The role for the user's account. (user, admin, etc.)
        :param language: str - ISO639 formatted str for the language (e.g. EN for English)
        :param is_sync_enabled: bool - Indicates if sync will be enabled on the account.
        :param job_title: str - The job title for the user.
        :param phone: int - The user's phone number. Non integer characters are not valid.
        :param address: str - The address for the user.
        :param space_amount: int - Space in bytes which are allocated to the user.
        :param tracking_codes: List[Dict] - Array containing key value pairs as defined by the
                                            admin.
        :param can_see_managed_users: bool - Indicates if this user can see managed users.
        :param time_zone: str - The timezone of the user. e.g. US/Eastern.
        :param is_exempt_from_device_limits: bool - Indicates if user is exempt from device limits.
        :param is_exempt_from_login_verification: bool - Indicates if user is exempt for login
                                                         verification
        :param is_external_collab_restricted: bool - Indicates if user is collab restricted.
        :param is_platform_access_only: bool - Indicates if user has acces to only the platform.
        :param status: str - The account status for the user. e.g. `active`
        :return: dict - The details of the created user.
        """
        if update_user:
            url_suffix = f'/users/{user_id}/'
            method = 'PUT'
        else:
            url_suffix = '/users/'
            method = 'POST'
        self._headers.update({'As-User': as_user})
        request_body = {
            "role": role,
            "address": address,
            "job_title": job_title,
            "language": language,
            "login": login,
            "name": name,
            "phone": phone,
            "space_amount": space_amount,
            "status": status,
            "timezone": time_zone,
            "is_sync_enabled": is_sync_enabled,
            "is_exempt_from_device_limits": is_exempt_from_device_limits,
            "is_external_collab_restricted": is_external_collab_restricted,
            "is_exempt_from_login_verification": is_exempt_from_login_verification,
            "can_see_managed_users": can_see_managed_users,
            "tracking_codes": tracking_codes
        }
        if is_update is False:
            request_body.update({"is_platform_access_only": is_platform_access_only})

        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            json_data=remove_empty_elements(request_body)
        )

    def delete_user(self, as_user: str, user_id: str, force: bool = False):
        """
        Deletes a user with the given `user_id`. If force is True, then the user will be deleted
        including all of their files. If not, then all files must be moved before deletion.

        :param as_user: str - The user who is making the request.
        :param user_id: str - The ID of the user who is being deleted.
        :param force: bool - Indicates if the command will be executed forcefully.
        :return: Status code indicating success or not.
        """
        url_suffix = f'/users/{user_id}/'
        self._headers.update({'As-User': as_user})
        query_params = {'force': force}
        return self._http_request(
            method='DELETE',
            url_suffix=url_suffix,
            params=query_params,
            return_empty_response=True
        )

    def download_file(self, file_id: str):
        """
        Downloads a file with the given `file_id`.

        :param file_id: str - The ID of the file to download.

        :return: Status code indicating success or not.
        """
        url_suffix = f'/files/{file_id}/content/'
        return self._http_request(
            method='GET',
            resp_type='response',
            url_suffix=url_suffix,
            return_empty_response=True
        )


''' HELPER FUNCTIONS '''


def get_filename(header_string: str):
    """
    Retrieves the file name from a header response.

    :param header_string: String containing the header object.
    :return: name of file if found, if not returns temp name.
    """
    try:
        file_name = re.findall(r"filename\*?=([^;]+)", header_string, flags=re.IGNORECASE)
        return file_name[0].strip().strip('"')
    except ValueError:
        return 'retrieved_file'


def arg_to_int(arg: Any, arg_name: str, default: int = None) -> int:
    """Converts an XSOAR argument to a Python int

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` type.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type default: ``int``
    :param default:
        Provides a default value if the arg is None.

    :return:
        returns an ``int`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``int``
    """

    if arg is None:
        return default  # type:ignore
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def format_time_range(range_arg: str):
    """
    Formats time range arguments since Box requires the format as a CSV string.

    :param range_arg:
    :return: Returns a formatted string or None depending on the input.
    """
    if range_arg:
        dt_from, dt_to = parse_date_range(
            date_range=range_arg,
            date_format=DATE_FORMAT
        )
        return f"{dt_from},{dt_to}"
    else:
        return None


def handle_default_user(args: dict, params: dict) -> None:
    """
    When the as-user argument is absent when executing a command, the argument will be updated to
    use the value given as the default user.

    :param args: demisto.args() object
    :param params:  demisto.params() object
    :return: None - Updates the args object in place.
    """
    if 'as_user' not in args:
        if 'default_user' not in params:
            raise DemistoException("A user ID has not been specified. Please configure a default, or"
                                   " add the user ID in the as_user argument.")
        args.update({'as_user': params.get('default_user')})


def parse_key_value_arg(arg_str: Optional[Any]):
    """
    In some cases it is necessary to pass an argument with a specific name. The common usecase is
    for Tags. This function allows a user to create their own key value pairs.

    :param arg_str: Argument given as a string in the format `key=SomeKey,value=SomeValue`
    :return: List of sets.
    """
    if arg_str:
        tags = []
        regex = re.compile(r'key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)', flags=re.I)
        for f in arg_str.split(';'):
            match = regex.match(f)
            if match is None:
                raise DemistoException(
                    'Unable to parse the given key value pair argument. Please verify'
                    ' the argument is formatted correctly. '
                    '`key=ExampleKey,value=ExampleValue`. For more than one KV pair,'
                    ' please use the separator `;`')
            tags.append({
                match.group(1): match.group(2)
            })

        return tags
    else:
        return None


''' COMMAND FUNCTIONS '''


def find_file_folder_by_share_link_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command function which retrieves the file or folder for a given share link.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.

    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    share_link: str = args.get('shared_link')  # type:ignore
    password: str = args.get('password', None)
    response: dict = client.find_file_folder_by_share_link(shared_link=share_link, password=password)
    readable_output = tableToMarkdown(
        name=f'File/Folder Share Link for {share_link}',
        t=response,
        removeNull=True,
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.ShareLink',
        outputs_key_field='shared_link',
        outputs=response
    )


def search_content_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command function which uses the `search_content` client function to query for an item.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.

    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    query_object = QueryHandler(args=args)
    as_user: str = args.get('as_user')  # type:ignore
    response = client.search_content(as_user=as_user, query_object=query_object)
    readable_output = tableToMarkdown(
        name='Search results',
        t=response.get('entries'),
        removeNull=True,
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.Query',
        outputs_key_field='id',
        outputs=response.get('entries')
    )


def create_update_file_share_link_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command function which uses the `crud_file_share_link` client function to create or update a
    file's share link. Since the API does not differentiate between creation or update of the links,
    this function handles both use-cases.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to initiate the FileShareLink object and pass the
                                             `as_user` argument to the client function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    file_share_link_obj: FileShareLink = FileShareLink(args)
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.crud_file_share_link(file_share_link=file_share_link_obj, as_user=as_user)
    readable_output = tableToMarkdown(
        name=f'File Share Link was created/updated for file_id: {file_share_link_obj.file_id}',
        t=response.get('shared_link'),
        removeNull=True,
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.ShareLink',
        outputs_key_field='id',
        outputs=response
    )


def remove_file_share_link_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command function which uses the `crud_file_share_link` client function to delete/remove a
    file's share link. This is done by passing the `is_delete` parameter to the crud function which
    sends an empty JSON object to the API.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to initiate the FileShareLink object and pass the
                                             `as_user` argument to the client function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    file_share_link_obj: FileShareLink = FileShareLink(args)
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.crud_file_share_link(file_share_link=file_share_link_obj, as_user=as_user,
                                                 is_delete=True)

    return CommandResults(
        readable_output=f'File Share Link for the file_id {file_share_link_obj.file_id} was '
                        f'removed.',
        outputs_prefix='Box.ShareLink',
        outputs_key_field='id',
        outputs=response
    )


def get_shared_link_for_file_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command function which retrieves the shared link for a given file.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the `as_user` and `file_id` argument to
                                             the client function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    file_id: str = args.get('file_id')  # type:ignore
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.get_shared_link_by_file(file_id=file_id, as_user=as_user)
    if response.get('shared_link') is None:
        readable_output: str = f"There currently is no shared link assigned to the file {file_id}."
    else:
        readable_output: str = tableToMarkdown(  # type:ignore
            name=f'Shared link information for the file {file_id}',
            t=response.get('shared_link'),
            removeNull=True,
            headerTransform=string_to_table_header
        )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.ShareLink',
        outputs_key_field='id',
        outputs=response
    )


def get_shared_link_by_folder_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command function which retrieves the shared link for a given folder.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the `as_user` and `folder_id` argument to
                                             the client function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    folder_id: str = args.get('folder_id')  # type:ignore
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.get_shared_link_by_folder(folder_id=folder_id, as_user=as_user)
    readable_output: str = tableToMarkdown(
        name=f'Shared link information for the folder {folder_id}',
        t=response,
        removeNull=True,
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.FolderShareLink',
        outputs_key_field='id',
        outputs=response
    )


def create_update_folder_share_link_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command function which uses the `crud_folder_share_link` client function to create or update a
    folder's share link. Since the API does not differentiate between creation or update of the
    links, this function handles both use-cases.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to initiate the FolderShareLink object and pass
    the `as_user` argument to the client function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    folder_share_link_obj: FolderShareLink = FolderShareLink(args)
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.crud_folder_share_link(folder_share_link=folder_share_link_obj,
                                                   as_user=as_user)
    readable_output: str = tableToMarkdown(
        name=f'Folder Share Link for {folder_share_link_obj.folder_id}',
        t=response,
        removeNull=True,
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.ShareLink',
        outputs_key_field='id',
        outputs=response
    )


def remove_folder_share_link_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command function which uses the `crud_folder_share_link` client function to delete/remove a
    folder's share link. This is done by passing the `is_delete` parameter to the crud function
    which sends an empty JSON object to the API.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to initiate the FolderShareLink object and pass
    the `as_user` argument to the client function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    folder_share_link_obj: FolderShareLink = FolderShareLink(args)
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.crud_folder_share_link(folder_share_link=folder_share_link_obj,
                                                   as_user=as_user, is_delete=True)
    readable_output: str = tableToMarkdown(
        name=f'Folder Share Link for {folder_share_link_obj.folder_id} was removed.',
        t=response,
        removeNull=True,
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.ShareLink',
        outputs_key_field='id',
        outputs=response
    )


def get_folder_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command which retrieves details about a given folder.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the `as_user` and `folder_id` argument to
                                             the client function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    folder_id: str = args.get('folder_id')  # type:ignore
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.get_folder(folder_id=folder_id, as_user=as_user)
    folder_item_collection: dict = response.get('item_collection')  # type:ignore
    folders_output: str = tableToMarkdown(
        name=f"File contents for the folder {folder_id}",
        t=folder_item_collection.get('entries'),
        removeNull=True,
        headerTransform=string_to_table_header
    )
    overview_response = response.copy()
    overview_response.pop('item_collection')
    overview_output: str = tableToMarkdown(
        name=f'Folder overview for {folder_id}.',
        t=overview_response,
        removeNull=True,
        headerTransform=string_to_table_header
    )
    readable_output: str = overview_output + folders_output
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.Folder',
        outputs_key_field='id',
        outputs=response
    )


def list_folder_items_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command which lists the items within a given folder.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    folder_id: str = args.get('folder_id')  # type:ignore
    as_user: str = args.get('as_user')  # type:ignore
    limit: int = arg_to_int(arg_name='limit', arg=args.get('limit'), default=100)
    offset: int = arg_to_int(arg_name='offset', arg=args.get('offset'), default=0)
    sort: str = args.get('sort')  # type:ignore
    response: dict = client.list_folder_items(folder_id=folder_id, as_user=as_user, limit=limit,
                                              offset=offset, sort=sort)
    folder_item_collection: dict = response.get('item_collection')  # type:ignore
    folders_output: str = tableToMarkdown(
        name=f"File contents for the folder {folder_id}",
        t=folder_item_collection.get('entries'),
        removeNull=True,
        headerTransform=string_to_table_header
    )
    overview_response = response.copy()
    overview_response.pop('item_collection')
    overview_output: str = tableToMarkdown(
        name=f'Folder overview for {folder_id}.',
        t=overview_response,
        removeNull=True,
        headerTransform=string_to_table_header
    )
    readable_output: str = overview_output + folders_output
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.Folder',
        outputs_key_field='id',
        outputs=response
    )


def folder_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command which creates a folder under the given parent folder. If no parent is given, the folder
    will be created under the root (0) folder.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    name: str = args.get('name')  # type:ignore
    parent_id: str = args.get('parent_id')  # type:ignore
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.folder_create(name=name, parent_id=parent_id, as_user=as_user)
    readable_output: str = f'Folder named {name}, was successfully created.'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.Folder',
        outputs_key_field='id',
        outputs=response
    )


def file_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command which when given a file_id will delete the file. The deleted file will be sent to the
    Trash folder. If the file is to be deleted permanently, then it is necessary to use the
    `box-trashed-item-delete-permanently` command after executing this command.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    file_id: str = args.get('file_id')  # type:ignore
    as_user: str = args.get('as_user')  # type:ignore
    response: Response = client.file_delete(file_id=file_id, as_user=as_user)
    if response.status_code == 204:
        readable_output: str = f'The file {file_id} was successfully deleted.'
    else:
        readable_output: str = f'The file {file_id} was not deleted successfully.'  # type:ignore
        raise DemistoException(readable_output)
    return CommandResults(
        readable_output=readable_output
    )


def list_users_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command which will list all users for which the query applies. The retrieved user_ids are
    necessary for subsequent calls made to the API.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    fields: str = args.get('fields')  # type:ignore
    filter_term: str = args.get('filter_term')  # type:ignore
    limit: int = arg_to_int(arg_name='limit', arg=args.get('limit'), default=100)
    offset: int = arg_to_int(arg_name='offset', arg=args.get('offset'), default=0)
    user_type: str = args.get('user_type')  # type:ignore
    response: dict = client.list_users(fields=fields, filter_term=filter_term, limit=limit,
                                       offset=offset, user_type=user_type)
    readable_output: str = tableToMarkdown(
        name='The following users were found.',
        t=response.get('entries'),
        removeNull=True,
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.Users',
        outputs_key_field='id',
        outputs=response.get('entries')
    )


def upload_file_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Uploads a file to Box. For files with a size over the set limit, the file will be uploaded in
    chunks. For files which are under the limit, they will be submitted using a POST request.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    entry_id: str = args.get('entry_id')  # type:ignore
    file_name: str = args.get('file_name')  # type:ignore
    folder_id: str = args.get('folder_id')  # type:ignore
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.upload_file(entry_id=entry_id, file_name=file_name, folder_id=folder_id,
                                        as_user=as_user)
    readable_output = "File was successfully uploaded"
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.File',
        outputs_key_field='id',
        outputs=response.get('entities')
    )


def trashed_items_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Lists items which have been trashed.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    limit: int = arg_to_int(arg_name='limit', arg=args.get('limit'), default=100)
    offset: int = arg_to_int(arg_name='offset', arg=args.get('offset'), default=0)
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.trashed_items_list(limit=limit, offset=offset, as_user=as_user)
    if len(response.get('entries')) == 0:  # type:ignore
        readable_output = "No trashed items were found."
    else:
        readable_output = tableToMarkdown(
            name='Trashed items were found.',
            t=response.get('entries'),
            removeNull=True,
            headerTransform=string_to_table_header
        )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.Trash',
        outputs_key_field='id',
        outputs=response.get('entries')
    )


def trashed_item_restore_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Restores an item which has been trashed.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    item_id: str = args.get('item_id')  # type:ignore
    type: str = args.get('type')  # type:ignore
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.trashed_item_restore(item_id=item_id, type=type, as_user=as_user)
    readable_output = f'Item with the ID {item_id} was restored.'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.Item',
        outputs_key_field='id',
        outputs=response
    )


def trashed_item_delete_permanently_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Permanently deletes a file. Please note, the file must be sent to trash prior to permanent
    deletion.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    item_id: str = args.get('item_id')  # type:ignore
    type: str = args.get('type')  # type:ignore
    as_user: str = args.get('as_user')  # type:ignore
    response: Response = client.trashed_item_permanently_delete(item_id=item_id, type=type, as_user=as_user)
    if response.status_code == 204:
        readable_output = f'Item with the ID {item_id} was deleted permanently.'
    else:
        readable_output = 'Failed to delete the item.'
    return CommandResults(
        readable_output=readable_output
    )


def list_user_events_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """

    Retrieves events which were generated by a specific user.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    as_user: str = args.get('as_user')  # type:ignore
    stream_type: str = args.get('stream_type')  # type:ignore
    limit: int = arg_to_int(arg_name='limit', arg=args.get('limit'), default=10)
    response: dict = client.list_events(as_user=as_user, stream_type=stream_type, limit=limit)
    events = response.get('entries', [])
    if len(events) == 0:  # type:ignore
        readable_output = f'No events were found for the user {as_user}.'
    else:
        readable_output = tableToMarkdown(
            name=f'Events found for the user: {as_user}',
            t=events,
            removeNull=True,
            headerTransform=string_to_table_header
        )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.Events',
        outputs_key_field='event_id',
        outputs=events
    )


def list_enterprise_events_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """

    Retrieves enterprise level events from the Box service.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    as_user: str = args.get('as_user')  # type:ignore
    limit: int = arg_to_int(arg_name='limit', arg=args.get('limit'), default=10)
    created_after: str = arg_to_datetime(  # type:ignore
        arg=args.get('created_after'),
        arg_name='Created after',
        required=False
    ).strftime(DATE_FORMAT)
    response: dict = client.list_events(as_user=as_user, stream_type='admin_logs',
                                        created_after=created_after, limit=limit)
    events = response.get('entries', [])
    if len(events) == 0:  # type:ignore
        readable_output = 'No enterprise events were found.'
    else:
        readable_output = tableToMarkdown(
            name='Enterprise Events found.',
            t=events,
            removeNull=True,
            headerTransform=string_to_table_header
        )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.Events',
        outputs_key_field='event_id',
        outputs=events
    )


def get_current_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command executed when `box-get-current-user` is called. Uses the `As-User` header parameter to
    set the current user for the request.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    as_user: str = args.get('as_user')  # type:ignore
    response: dict = client.get_current_user(as_user=as_user)

    readable_output = tableToMarkdown(
        name=f'The current user is {response.get("login")}.',
        t=response,
        removeNull=True,
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.User',
        outputs_key_field='id',
        outputs=response
    )


def create_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command executed when `box-create_user` is called. Will create a user based on the given
    arguments.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    as_user: str = args.get('as_user')  # type:ignore
    login: str = args.get('login')  # type:ignore
    name: str = args.get('name')  # type:ignore
    role: str = args.get('role')  # type:ignore
    language: str = args.get('language')  # type:ignore
    is_sync_enabled: bool = argToBoolean(args.get('is_sync_enabled'))
    job_title: str = args.get('job_title')  # type:ignore
    phone: str = args.get('phone')  # type:ignore
    address: str = args.get('address')  # type:ignore
    space_amount: int = arg_to_int(arg_name='space_amount', arg=args.get('space_amount'), default=-1)
    tracking_codes: List[Dict] = parse_key_value_arg(arg_str=args.get('tracking_codes'))
    can_see_managed_users: bool = argToBoolean(args.get('can_see_managed_users'))
    time_zone: str = args.get('timezone')  # type:ignore
    is_exempt_from_device_limits: bool = argToBoolean(args.get('is_exempt_from_device_limits'))
    is_exempt_from_login_verification: bool = argToBoolean(args.get('is_exempt_from_login_verification'))
    is_external_collab_restricted: bool = argToBoolean(args.get('is_external_collab_restricted'))
    is_platform_access_only: bool = argToBoolean(args.get('is_platform_access_only'))
    status: str = args.get('status')  # type:ignore

    if is_platform_access_only is False and login is None:
        raise DemistoException("Box requires the Login argument when the argument"
                               " `is_platform_access_only` is False")

    response = client.create_update_user(as_user=as_user, login=login, name=name, role=role,
                                         language=language, is_sync_enabled=is_sync_enabled,
                                         job_title=job_title, phone=phone, address=address,
                                         space_amount=space_amount, tracking_codes=tracking_codes,
                                         can_see_managed_users=can_see_managed_users,
                                         time_zone=time_zone,
                                         is_exempt_from_device_limits=is_exempt_from_device_limits,
                                         is_exempt_from_login_verification=is_exempt_from_login_verification,
                                         is_external_collab_restricted=is_external_collab_restricted,
                                         is_platform_access_only=is_platform_access_only,
                                         status=status)
    readable_output = tableToMarkdown(
        name=f'The user {response.get("login")} has been created.',
        t=response,
        removeNull=True,
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.User',
        outputs_key_field='id',
        outputs=response
    )


def update_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command executed when `box-create_user` is called. Will create a user based on the given
    arguments.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    as_user: str = args.get('as_user')  # type:ignore
    user_id: str = args.get('user_id')  # type:ignore
    login: str = args.get('login')  # type:ignore
    name: str = args.get('name')  # type:ignore
    role: str = args.get('role')  # type:ignore
    language: str = args.get('language')  # type:ignore
    is_sync_enabled: bool = argToBoolean(args.get('is_sync_enabled', 'false'))  # type:ignore
    job_title: str = args.get('job_title')  # type:ignore
    phone: str = args.get('phone')  # type:ignore
    address: str = args.get('address')  # type:ignore
    space_amount: int = arg_to_int(arg_name='space_amount', arg=args.get('space_amount'), default=-1)
    tracking_codes: Optional[Any] = parse_key_value_arg(arg_str=args.get('tracking_codes'))
    can_see_managed_users: bool = argToBoolean(
        args.get('can_see_managed_users', 'false'))  # type:ignore
    time_zone: Optional[Any] = args.get('timezone')
    is_exempt_from_device_limits: bool = argToBoolean(
        args.get('is_exempt_from_device_limits', 'false'))  # type:ignore
    is_exempt_from_login_verification: bool = argToBoolean(
        args.get('is_exempt_from_login_verification', 'false'))  # type:ignore
    is_external_collab_restricted: bool = argToBoolean(
        args.get('is_external_collab_restricted', 'false'))  # type:ignore
    status: Optional[Any] = args.get('status')

    response = client.create_update_user(as_user=as_user, login=login, name=name, role=role,
                                         language=language, is_sync_enabled=is_sync_enabled,
                                         job_title=job_title, phone=phone, address=address,
                                         space_amount=space_amount, tracking_codes=tracking_codes,
                                         can_see_managed_users=can_see_managed_users,
                                         time_zone=time_zone,
                                         is_exempt_from_device_limits=is_exempt_from_device_limits,
                                         is_exempt_from_login_verification=is_exempt_from_login_verification,
                                         is_external_collab_restricted=is_external_collab_restricted,
                                         status=status, user_id=user_id, update_user=True, is_update=True)
    readable_output = tableToMarkdown(
        name=f'The user {response.get("login")} has been updated.',
        t=response,
        removeNull=True,
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Box.User',
        outputs_key_field='id',
        outputs=response
    )


def delete_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Command executed when `box-create_user` is called. Will create a user based on the given
    arguments.

    :param client: Client - Initialized Client object.
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    as_user: str = args.get('as_user')  # type:ignore
    user_id: str = args.get('user_id')  # type:ignore
    force: bool = bool(strtobool(args.get('force', 'false')))

    response = client.delete_user(as_user=as_user, user_id=user_id, force=force)

    if response.status_code == 204:
        readable_output: str = f'The user {user_id} was successfully deleted.'
    else:
        readable_output: str = f'The user {user_id} was not deleted successfully.'  # type: ignore
        raise DemistoException(readable_output)
    return CommandResults(
        readable_output=readable_output
    )


def download_file_command(auth_params: dict, base_url: str, verify: bool, proxy: bool,
                          args: Dict[str, Any]) -> dict:
    """
    Command executed when `box-download-file` is called. Will download a file based on the given
    arguments.

    This function requires a new JWT grant to be created with the explicit permissions of the user
    who is downloading the file. This is why we are throwing away the main client and building a new
    one here.

    :param proxy: Indicates if using a proxy.
    :param verify: Indicates if the client will verify self signed certs
    :param base_url: Base URL for the service
    :param auth_params: Args used for the authentication
    :param args: demisto.args() dictionary - Used to pass the necessary arguments to the client
    function.
    :return: CommandResults - Returns a CommandResults object which is consumed by the
    return_results function in main()
    """
    file_id: str = args.get('file_id')  # type:ignore
    as_user: str = args.get('as_user')  # type:ignore

    download_client = Client(
        auth_params=auth_params,
        base_url=base_url,
        verify=verify,
        proxy=proxy,
        as_user=as_user
    )

    response = download_client.download_file(file_id=file_id)

    d = response.headers['content-disposition']
    file_name = get_filename(d)
    return fileResult(filename=file_name, data=response.content)


''' MAIN FUNCTION '''


def test_module(client: Client) -> str:
    """
    This test assumes that the account has at least one user. By definition, if the instance is
    configured correctly, there will always be a minimum of one user.

    :param client:
    :return:
    """
    response: Response = client.list_users(limit=1)
    if response:
        return 'ok'
    else:
        return 'An error occurred.'


def fetch_incidents(client: Client, max_results: int, last_run: dict, first_fetch_time: int,
                    as_user: str) -> Tuple[str, List[Dict]]:
    """

    :param client:
    :param max_results:
    :param last_run:
    :param first_fetch_time:
    :param as_user:
    :return:
    """
    created_after = last_run.get('time', None)
    incidents = []
    if not created_after:
        created_after = datetime.fromtimestamp(first_fetch_time, tz=timezone.utc).strftime(
            DATE_FORMAT)
    results = client.list_events(stream_type='admin_logs', as_user=as_user, limit=max_results,
                                 created_after=created_after)
    raw_incidents = results.get('entries', [])
    next_run = datetime.now(tz=timezone.utc).strftime(DATE_FORMAT)
    for raw_incident in raw_incidents:
        event = Event(raw_input=raw_incident)
        xsoar_incident = event.format_incident()
        incidents.append(xsoar_incident)
        if event.created_at > created_after:
            next_run = event.created_at

    return next_run, incidents


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    # get the service API url
    base_url = urljoin('https://api.box.com', '2.0')
    verify_certificate = not demisto.params().get('insecure', False)

    # Determine first fetch time if none is found.
    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get('first_fetch', '1 day'),
        arg_name='First fetch time',
        required=True
    )
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_time, int)
    proxy = demisto.params().get('proxy', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            auth_params=demisto.params(),
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)
        if not any(command in demisto.command() for command in ['test-module', 'fetch-incidents',
                                                                'box-find-file-folder-by-share-link']):
            # Both commands should only use the explicit user they were assigned and not inherit
            # the default user. This ensures as-user is used every time.
            handle_default_user(args=demisto.args(), params=demisto.params())
            if demisto.params().get('search_user_id', False) is True:
                # If the integration is configured to allow auto-detection of User IDs based on
                # emails, then the match is performed here.
                as_user_arg = demisto.args().get('as_user', None)
                if re.match(emailRegex, as_user_arg):
                    matched_user_id = None
                    try:
                        response = client.list_users(fields='id,name', filter_term=as_user_arg,
                                                     limit=1,
                                                     offset=0)
                        # In all cases, we retrieve the first (and ideally only) entry from the
                        # query.
                        matched_user_id = response.get('entries')[0].get('id')
                    except Exception as exception:
                        raise DemistoException(
                            "An error occurred while attempting to match the as_user to a"
                            " valid ID", exception)
                    demisto.args().update({'as_user': str(matched_user_id)})

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            as_user = demisto.params().get('as_user', None)
            max_results = arg_to_int(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch'
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                as_user=as_user
            )
            demisto.setLastRun({'time': next_run})
            demisto.incidents(incidents)

        elif demisto.command() == 'box-create-file-share-link' or \
                demisto.command() == 'box-update-file-share-link':
            return_results(
                create_update_file_share_link_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-remove-file-share-link':
            return_results(remove_file_share_link_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-find-file-folder-by-share-link':
            return_results(
                find_file_folder_by_share_link_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-get-shared-link-by-file':
            return_results(get_shared_link_for_file_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-get-shared-link-by-folder':
            return_results(get_shared_link_by_folder_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-create-folder-share-link' or \
                demisto.command() == 'box-update-folder-share-link':
            return_results(
                create_update_folder_share_link_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-remove-folder-share-link':
            return_results(remove_folder_share_link_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-get-folder':
            return_results(get_folder_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-list-folder-items':
            return_results(list_folder_items_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-folder-create':
            return_results(folder_create_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-file-delete':
            return_results(file_delete_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-list-users':
            return_results(list_users_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-upload-file':
            return_results(upload_file_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-trashed-items-list':
            return_results(trashed_items_list_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-trashed-item-restore':
            return_results(trashed_item_restore_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-trashed-item-delete-permanently':
            return_results(
                trashed_item_delete_permanently_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-list-user-events':
            return_results(list_user_events_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-list-enterprise-events':
            return_results(list_enterprise_events_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-get-current-user':
            return_results(get_current_user_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-create-user':
            return_results(create_user_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-update-user':
            return_results(update_user_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-delete-user':
            return_results(delete_user_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-search-content':
            return_results(search_content_command(client=client, args=demisto.args()))

        elif demisto.command() == 'box-download-file':
            return_results(download_file_command(
                auth_params=demisto.params(),
                base_url=base_url,
                verify=verify_certificate,
                proxy=proxy,
                args=demisto.args()
            ))

        else:
            raise NotImplementedError

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
