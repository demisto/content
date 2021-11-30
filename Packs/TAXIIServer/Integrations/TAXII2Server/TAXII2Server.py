import functools
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
API_ROOT = '/threatintel/'
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
        self.url_scheme = url_scheme
        self.host = host
        self.port = port
        self.certificate = certificate
        self.private_key = private_key
        self.http_server = http_server
        self.service_address = service_address
        self.auth = None
        if credentials:
            self.auth = (credentials.get('identifier', ''), credentials.get('password', ''))
        self.api_root = API_ROOT
        self.version = version
        if not (version == TAXII_VER_2_0 or version == TAXII_VER_2_1):
            raise Exception(f'Wrong TAXII 2 Server version: {version}. '
                            f'Possible values: {TAXII_VER_2_0}, {TAXII_VER_2_1}.')
        collections_resource = []
        for name, query in collections.items():
            collection = {
                'id': 123,  # TODO: RFC 4122-compliant Version 4 UUID
                'title': name,
                'description': query,
                'can_read': True,
                'can_write': False,
                'media_types': [SERVER.taxii_collections_media_type]
            }
            collections_resource.append(collection)

        self.collections = collections

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

    def get_discovery_service(self):
        """
        Handle discovery request.

        Returns:
            The discovery response.
        """
        default = urljoin(self.service_address, self.api_root)

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
        if not api_root == self.api_root:
            raise Exception(f'Unknown API Root {api_root}. Check possible API Roots using "{self.discovery_route}"')

        return {
            'title': 'XSOAR TAXII2 Server ThreatIntel',
            'description': 'This API Root provides TAXII Services for system indicators.',
            'versions': [SERVER.api_version],
            'max_content_length': 9765625  # TODO: Ask what is this
        }

    def get_collections(self, api_root):
        if not api_root == self.api_root:
            raise Exception(f'Unknown API Root {api_root}. Check possible API Roots using "{self.discovery_route}"')
        # TODO Implement collections

        return {'collection': 'darya'}

    def get_objects(self, api_root, collection_id, added_after, limit):
        # TODO Implement indicators
        return '', '', ''


SERVER: TAXII2Server
basic_auth = HTTPBasic()
token_auth = APIKeyHeader(auto_error=False, name='Authorization')

''' HELPER FUNCTIONS '''


def taxii_validate_request(f):
    @functools.wraps(f)
    async def validate_request(*args, **kwargs):
        """
        function of HTTP requests to validate authentication headers.
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
                    content_type=SERVER.taxii_content_type):
    """
    Create an HTTP taxii response from a taxii message.
    Args:
        content_type:
        date_added_last:
        date_added_first:
        content:

    Returns:
        A taxii HTTP response.
    """
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


@APP.get('/{api_root}/')  # TAXII v2.1
@taxii_validate_request
async def taxii2_api_root(api_root, request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth)):
    """
     Defines TAXII API - Server Information:
     Get API Root Information section (4.2) `here <https://docs.oasis-open.org/cti/taxii/v2.1/cs01/taxii-v2.1-cs01.html#_Toc31107528>`__
     Args:
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


@APP.get('/{api_root}/collections/')
@taxii_validate_request
async def taxii2_collections(request: Request, api_root: str, credentials: HTTPBasicCredentials = Depends(basic_auth)):
    """
    Defines TAXII API - Collections:
    Get Collection section (5.4) `here for v.2 <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988049>`__
    Args:
        credentials:
        api_root (str): the base URL of the API Root
    Returns:
        collections: A Collections Resource upon successful requests. Additional information
        `here <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988050>`__.
    """
    try:
        collection_response = SERVER.get_collections(api_root)
    except Exception as e:
        error = f'Could not perform the collections request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(status.HTTP_400_BAD_REQUEST, {'title': 'Collections Request Error',
                                                             'description': error})
    return handle_response(status.HTTP_200_OK, collection_response)


@APP.get('/{api_root}/collections/{collection_id}/objects/')
async def taxii2_objects(api_root: str, collection_id: str, added_after: int = None, limit: int = 500,
                         credentials: HTTPBasicCredentials = Depends(basic_auth)):
    """
    Defines TAXII API - Collections Objects:
    Get Collection section (5.1) `here <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988055>`__
    Args:
        credentials:
        limit:
        added_after:
        collection_id:
        api_root (str): the base URL of the API Root
    Returns:
        envelope: A Envelope Resource upon successful requests. Additional information
        `here <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988038>`__.
    """
    try:
        objects_response, date_added_first, date_added_last = SERVER.get_objects(
            api_root,
            collection_id,
            added_after,
            limit
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

    integration_logger = IntegrationLogger()
    integration_logger.buffering = False
    log_config = dict(uvicorn.config.LOGGING_CONFIG)
    log_config['handlers']['default']['stream'] = integration_logger
    log_config['handlers']['access']['stream'] = integration_logger
    log_config['formatters']['access'] = {
        '()': TAXII2ServerAccessFormatter,
        'fmt': '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"'
    }

    uvicorn.run(APP, host='127.0.0.1', port=port)


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
        print(err_msg)
        return_error(err_msg)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
