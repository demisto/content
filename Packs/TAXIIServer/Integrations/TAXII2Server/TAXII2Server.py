import functools
import uuid
from copy import copy
from tempfile import NamedTemporaryFile
from typing import Callable
from urllib.parse import ParseResult, urlparse
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasicCredentials, HTTPBasic, APIKeyHeader
from secrets import compare_digest

from uvicorn.logging import AccessFormatter

import demistomock as demisto
from CommonServerPython import *
from fastapi import FastAPI, Response, Depends, status, Request
import uvicorn

''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'TAXII Server'
API_ROOT = 'threatintel'
APP: FastAPI = FastAPI()
NAMESPACE_URI = 'https://www.paloaltonetworks.com/cortex'
MEDIA_TYPE_TAXII_ANY = "application/taxii+json"
MEDIA_TYPE_STIX_ANY = "application/stix+json"
MEDIA_TYPE_TAXII_V21 = 'application/taxii+json;version=2.1'
MEDIA_TYPE_STIX_V21 = 'application/stix+json;version=2.1'
MEDIA_TYPE_TAXII_V20 = 'application/vnd.oasis.taxii+json; version=2.0'
MEDIA_TYPE_STIX_V20 = "application/vnd.oasis.stix+json; version=2.0"
ACCEPT_TYPE_ALL = '*/*'
TAXII_VER_2_0 = "2.0"
TAXII_VER_2_1 = "2.1"
PAWN_UUID = uuid.uuid5(uuid.NAMESPACE_URL, 'https://www.paloaltonetworks.com')
SCO_DET_ID_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class TAXII2ServerAccessFormatter(AccessFormatter):
    def get_user_agent(self, scope: Dict) -> str:
        headers = scope.get('headers', [])
        user_agent_header = list(filter(lambda header: header[0].decode() == 'user-agent', headers))
        user_agent = ''
        if len(user_agent_header) == 1:
            user_agent = user_agent_header[0][1].decode()
        return user_agent

    def formatMessage(self, record):
        recordcopy = copy(record)
        scope = recordcopy.__dict__['scope']
        user_agent = self.get_user_agent(scope)
        recordcopy.__dict__.update({'user_agent': user_agent})
        return super().formatMessage(recordcopy)


''' TAXII2 Server '''


class TAXII2Server:
    def __init__(self, url_scheme: str, host: str, port: int, collections: dict, certificate: str, private_key: str,
                 http_server: bool, credentials: dict, version: str, service_address: Optional[str] = None):
        """
        Class for a TAXII2 Server configuration.
        Args:
            url_scheme: The URL scheme (http / https)
            host: The server address.
            port: The server port.
            collections: The JSON string of collections of indicator queries.
            certificate: The server certificate for SSL.
            private_key: The private key for SSL.
            http_server: Whether to use HTTP server (not SSL).
            credentials: The user credentials.
            version: API version.
        """
        self._url_scheme = url_scheme
        self._host = host
        self._port = port
        self._certificate = certificate
        self._private_key = private_key
        self._http_server = http_server
        self._service_address = service_address
        self._auth = None
        if credentials:
            self._auth = (credentials.get('identifier', ''), credentials.get('password', ''))
        self._api_root = API_ROOT
        self.version = version
        if not (version == TAXII_VER_2_0 or version == TAXII_VER_2_1):
            raise Exception(f'Wrong TAXII 2 Server version: {version}. '
                            f'Possible values: {TAXII_VER_2_0}, {TAXII_VER_2_1}.')
        self._collections_resource = []
        self._collections_by_id = dict()
        self._seed = uuid.uuid5(PAWN_UUID, demisto.getLicenseID())
        self.create_collections(collections)

    @property
    def taxii_collections_media_type(self):
        media_type = MEDIA_TYPE_STIX_ANY
        if self.version == TAXII_VER_2_0:
            media_type = MEDIA_TYPE_STIX_V20
        elif self.version == TAXII_VER_2_1:
            media_type = MEDIA_TYPE_STIX_V21
        return media_type

    @property
    def taxii_content_type(self):
        content_type = MEDIA_TYPE_TAXII_ANY
        if self.version == TAXII_VER_2_0:
            content_type = MEDIA_TYPE_TAXII_V20
        elif self.version == TAXII_VER_2_1:
            content_type = MEDIA_TYPE_TAXII_V21
        return content_type

    @property
    def discovery_route(self):
        discovery_route = '/taxii/'
        if self.version == TAXII_VER_2_1:
            discovery_route = '/taxii2/'
        return discovery_route

    @property
    def api_version(self):
        api_root_version = 'taxii-2.0'
        if self.version == TAXII_VER_2_1:
            api_root_version = MEDIA_TYPE_TAXII_V21
        return api_root_version

    @property
    def auth(self):
        return self._auth

    def create_collections(self, collections):
        collections_resource = []
        collections_by_id = dict()
        for name, query in collections.items():
            collection_uuid = str(uuid.uuid5(self._seed, 'Collection_' + name))
            collection = {
                'id': collection_uuid,
                'title': name,
                'description': query,
                'can_read': True,
                'can_write': False,
                'media_types': [self.taxii_collections_media_type]
            }
            collections_resource.append(collection)
            collections_by_id[collection_uuid] = collection

        self._collections_resource = collections_resource
        self._collections_by_id = collections_by_id

    def get_discovery_service(self):
        """
        Handle discovery request.

        Returns:
            The discovery response.
        """
        default = urljoin(self._service_address, self._api_root)
        default = urljoin(default, '/')

        return {
            'title': 'XSOAR TAXII2 Server',
            'description': 'This integration provides TAXII Services for system indicators (Outbound feed).',
            'default': default,
            'api_roots': [default]
        }

    def get_api_root(self, api_root):
        """
        Handle API Root request.

        Returns:
            The API ROOT response.
        """
        if not api_root == self._api_root:
            raise Exception(f"Unknown API Root {api_root}. Check possible API Roots using '{self.discovery_route}'")

        return {
            'title': 'XSOAR TAXII2 Server ThreatIntel',
            'description': 'This API Root provides TAXII Services for system indicators.',
            'versions': [SERVER.api_version],
            'max_content_length': 9765625  # TODO: Ask what is this
        }

    def get_collections(self, api_root):
        """
        Handle Collections request.

        Returns:
            The Collections response.
        """
        if not api_root == self._api_root:
            raise Exception(f"Unknown API Root {api_root}. Check possible API Roots using '{self.discovery_route}'")

        return self._collections_resource

    def get_collection_by_id(self, api_root, collection_id):
        """
        Handle Collection ID request.

        Returns:
            The Collection with given ID response.
        """
        if not api_root == self._api_root:
            raise Exception(f"Unknown API Root {api_root}. Check possible API Roots using '{self.discovery_route}'")
        found_collection = self._collections_by_id.get(collection_id)

        if not found_collection:
            raise Exception(f'No collection with id "{collection_id}". '
                            f'Use "/{api_root}/collections/" to get all existing collections.')
        return found_collection

    def get_objects(self, api_root: str, collection_id: str, added_after, limit: int, offset: int,):
        # TODO: change added after to timestamp param
        if not api_root == self._api_root:
            raise Exception(f"Unknown API Root {api_root}. Check possible API Roots using '{self.discovery_route}'")
        found_collection = self._collections_by_id.get(collection_id)

        if not found_collection:
            raise Exception(f'No collection with id "{collection_id}". '
                            f'Use "/{api_root}/collections/" to get all existing collections.')

        query = found_collection.get('description')

        # TODO: change limit to requested limit
        new_limit = offset + limit
        ios = find_indicators(query, added_after, new_limit)
        return ios, '', ''


SERVER: TAXII2Server
basic_auth = HTTPBasic()
token_auth = APIKeyHeader(auto_error=False, name='Authorization')

''' HELPER FUNCTIONS '''


def taxii_validate_request(f):
    @functools.wraps(f)
    async def validate_request(*args, **kwargs):
        """
        function of HTTP requests to validate authentication and Accept headers.
        """
        request: Request = kwargs.get('request')
        credentials: HTTPBasicCredentials = kwargs.get('credentials')
        accept_headers = [MEDIA_TYPE_TAXII_ANY, MEDIA_TYPE_TAXII_V20, MEDIA_TYPE_TAXII_V21,
                          MEDIA_TYPE_STIX_V20, ACCEPT_TYPE_ALL]
        if SERVER.auth:
            auth_success = (compare_digest(credentials.username, SERVER.auth[0])
                            and compare_digest(credentials.password, SERVER.auth[1]))
            if not auth_success:
                handle_long_running_error('Authorization failed')
                return handle_response(status.HTTP_401_UNAUTHORIZED, {'title': 'Authorization failed'})
        request_headers = request.headers
        if (accept_header := request_headers.get('Accept')) not in accept_headers:
            handle_long_running_error('Invalid TAXII Headers')
            return handle_response(status.HTTP_400_BAD_REQUEST,
                                   {'title': 'Invalid TAXII Headers',
                                    'description': f'Invalid Accept header: {accept_header}, '
                                                   f'please use one ot the following Accept headers: '
                                                   f'{accept_headers}'})
        return await f(*args, **kwargs)

    return validate_request


def handle_long_running_error(error: str):
    """
    Handle errors in the long running process.
    Args:
        error: The error message.
    """
    demisto.error(error)
    demisto.updateModuleHealth(error)


def handle_response(status_code, content, date_added_first=None, date_added_last=None,
                    content_type=None):
    """
    Create an HTTP taxii response from a taxii message.
    Args:
        status_code:
        content_type:
        date_added_last:
        date_added_first:
        content:

    Returns:
        A taxii HTTP response.
    """
    if not content_type:
        content_type = SERVER.taxii_content_type
    headers = {
        'Content-Type': content_type,
    }
    if status_code == status.HTTP_401_UNAUTHORIZED:
        headers['WWW-Authenticate'] = f'Basic realm="Authentication Required"'
    if date_added_first:
        headers['X-TAXII-Date-Added-First'] = date_added_first
    if date_added_last:
        headers['X-TAXII-Date-Added-Last'] = date_added_last

    return JSONResponse(
        status_code=status_code,
        content=content,
        media_type=content_type,
        headers=headers
    )


def find_indicators(indicator_query: str) -> list:
    # TODO: create indicator searcher
    # TODO: parse all queries
    # TODO: build functions for each indicator type
    pass


def get_collections(params: dict = demisto.params()) -> dict:
    """
    Gets the indicator query collections from the integration parameters.
    """
    collections_json: str = params.get('collections', '')

    try:
        collections = json.loads(collections_json)
    except Exception:
        raise ValueError('The collections string must be a valid JSON object.')

    return collections


''' ROUTE FUNCTIONS '''


@APP.get('/taxii/')  # TAXII v2.0
@APP.get('/taxii2/')  # TAXII v2.1
@taxii_validate_request
async def taxii2_server_discovery(request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth)):
    """
    Defines TAXII API - Server Information:
    Server Discovery section (4.1) `here  for v2.1 <https://docs.oasis-open.org/cti/taxii/v2.1/cs01/taxii-v2.1-cs01.html#_Toc31107526>`__
    and `here for v2.0 <http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542727>`__
    Returns:
        discovery: A Discovery Resource upon successful requests. Additional information..
    """
    try:
        discovery_response = SERVER.get_discovery_service()
    except Exception as e:
        error = f'Could not perform the discovery request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(status.HTTP_400_BAD_REQUEST, {'title': 'Discovery Request Error',
                                                             'description': error})

    return handle_response(status.HTTP_200_OK, discovery_response)


@APP.get('/{api_root}/')
@taxii_validate_request
async def taxii2_api_root(api_root, request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth)):
    """
     Defines TAXII API - Server Information:
     Get API Root Information section (4.2) `here <https://docs.oasis-open.org/cti/taxii/v2.1/cs01/taxii-v2.1-cs01.html#_Toc31107528>`__
     Args:
         credentials:
         request:
         api_root (str): the base URL of the API Root
     Returns:
         api-root: An API Root Resource upon successful requests.
     """
    try:
        api_root_response = SERVER.get_api_root(api_root)
    except Exception as e:
        error = f'Could not perform the API Root request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(status.HTTP_400_BAD_REQUEST, {'title': 'API Root Request Error',
                                                             'description': error})

    return handle_response(status.HTTP_200_OK, api_root_response)


@APP.get('/{api_root}/status/{status_id}/')
@taxii_validate_request
async def taxii2_status(api_root, status_id, request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth)):
    # TODO: Not allowed
    pass


@APP.get('/{api_root}/collections/')
@taxii_validate_request
async def taxii2_collections(request: Request, api_root: str, credentials: HTTPBasicCredentials = Depends(basic_auth)):
    """
    Defines TAXII API - Collections:
    Get Collection section (5.1) `here for v.2 <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988049>`__
    Args:
        request:
        credentials:
        api_root (str): the base URL of the API Root
    Returns:
        collections: A Collections Resource upon successful requests. Additional information
        `here <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988050>`__.
    """
    try:
        collections_response = SERVER.get_collections(api_root)
    except Exception as e:
        error = f'Could not perform the collections request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(status.HTTP_400_BAD_REQUEST, {'title': 'Collections Request Error',
                                                             'description': error})
    return handle_response(status.HTTP_200_OK, collections_response)


@APP.get('/{api_root}/collections/{collection_id}')
@taxii_validate_request
async def taxii2_collection_by_id(request: Request, api_root: str, collection_id: str,
                                  credentials: HTTPBasicCredentials = Depends(basic_auth)):
    """
    Defines TAXII API - Collections:
    Get Collection section (5.2) `here for v.2.0 <http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542736>`__
    and `here for v.2.1 <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988051>`__
    Args:
        request:
        collection_id:
        credentials:
        api_root (str): the base URL of the API Root
    Returns:
        collections: A Collection Resource with given id upon successful requests.
    """
    try:
        collection_response = SERVER.get_collection_by_id(api_root, collection_id)
    except Exception as e:
        error = f'Could not perform the collection request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(status.HTTP_400_BAD_REQUEST, {'title': 'Collection Request Error',
                                                             'description': error})
    return handle_response(status.HTTP_200_OK, collection_response)


@APP.get('/{api_root}/collections/{collection_id}/manifest/')
@taxii_validate_request
async def taxii2_manifest(request: Request, api_root: str, collection_id: str, added_after: int = None,
                          limit: int = 500,
                          credentials: HTTPBasicCredentials = Depends(basic_auth)):
    # TODO: implement
    pass


@APP.get('/{api_root}/collections/{collection_id}/objects/')
@taxii_validate_request
async def taxii2_objects(request: Request, api_root: str, collection_id: str, added_after: int = None, limit: int = 500,
                         offset: int = 0, credentials: HTTPBasicCredentials = Depends(basic_auth)):
    """
    Defines TAXII API - Collections Objects:
    Get Collection section (5.4) `here <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988055>`__
    Args:
        offset:
        credentials:
        limit:
        added_after:
        collection_id:
        api_root (str): the base URL of the API Root
    Returns:
        envelope: A Envelope Resource upon successful requests. Additional information
        `here <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988038>`__.
    """
    # TODO: Parse match arguments
    ids = request.query_params.get('match[id]'),
    types = request.query_params.get('match[type]'),
    versions = request.query_params.get('match[version]'),
    spec_versions = request.query_params.get('match[spec_version]')
    # TODO: get limit and offset for v2.0 or v2.1
    try:
        objects_response, date_added_first, date_added_last = SERVER.get_objects(
            api_root=api_root,
            collection_id=collection_id,
            added_after=added_after,
            offset=offset,
            limit=limit,
        )
    except Exception as e:
        error = f'Could not perform the objects request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(status.HTTP_400_BAD_REQUEST, {'title': 'Objects Request Error',
                                                             'description': error})

    return handle_response(
        status_code=status.HTTP_200_OK,
        content=objects_response,
        date_added_first=date_added_first,
        date_added_last=date_added_last,
        content_type=MEDIA_TYPE_STIX_V20 if SERVER.version == TAXII_VER_2_0 else MEDIA_TYPE_TAXII_V21
    )


''' COMMAND FUNCTIONS '''


def run_server(taxii_server: TAXII2Server, port: int, certificate: str, private_key: str):
    """
    Start the taxii server.
    """
    ssl_args = dict()
    if certificate and private_key:
        certificate_file = NamedTemporaryFile(delete=False)
        certificate_path = certificate_file.name
        certificate_file.write(bytes(certificate, 'utf-8'))
        certificate_file.close()
        ssl_args['ssl_certfile'] = certificate_path

        private_key_file = NamedTemporaryFile(delete=False)
        private_key_path = private_key_file.name
        private_key_file.write(bytes(private_key, 'utf-8'))
        private_key_file.close()
        ssl_args['ssl_keyfile'] = private_key_path

        demisto.debug('Starting HTTPS Server')
    else:
        demisto.debug('Starting HTTP Server')

    # integration_logger = IntegrationLogger()
    # integration_logger.buffering = False
    # log_config = dict(uvicorn.config.LOGGING_CONFIG)
    # log_config['handlers']['default']['stream'] = integration_logger
    # log_config['handlers']['access']['stream'] = integration_logger
    # log_config['formatters']['access'] = {
    #     '()': TAXII2ServerAccessFormatter,
    #     'fmt': '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"'
    # }

    uvicorn.run(APP, host='0.0.0.0', port=port, **ssl_args)


def main():
    """
    Main
    """
    global SERVER

    params = demisto.params()
    command = demisto.command()

    try:
        port = int(params.get('longRunningPort'))
    except ValueError as e:
        raise ValueError(f'Invalid listen port - {e}')

    collections = get_collections(params)
    version = params.get('version')
    credentials = params.get('credentials', None)

    server_links = demisto.demistoUrls()
    server_link_parts: ParseResult = urlparse(server_links.get('server'))
    host_name = server_link_parts.hostname

    if service_address_param := params.get('service_address'):
        service_address = service_address_param
    else:
        service_address = server_links.get('server')

    certificate = params.get('certificate', '')
    private_key = params.get('key', '')

    if (certificate and not private_key) or (private_key and not certificate):
        raise ValueError('When using HTTPS connection, both certificate and private key must be provided.')

    http_server = not (certificate and private_key)  # False if (certificate and private_key) else True

    scheme = 'https' if not http_server else 'http'

    demisto.debug(f'Command being called is {command}')

    try:
        SERVER = TAXII2Server(scheme, str(host_name), port, collections,
                              certificate, private_key, http_server, credentials, version, service_address)

        if command == 'long-running-execution':
            run_server(SERVER, port, certificate, private_key)

        elif command == 'test-module':
            return_results('ok')

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
