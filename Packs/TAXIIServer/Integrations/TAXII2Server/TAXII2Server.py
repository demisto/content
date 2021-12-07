import functools
import uuid
from ssl import SSLContext, PROTOCOL_TLSv1_2
from tempfile import NamedTemporaryFile
from flask import Flask, request, make_response, jsonify
from gevent.pywsgi import WSGIServer
from urllib.parse import ParseResult, urlparse
from secrets import compare_digest

import demistomock as demisto
from CommonServerPython import *

''' GLOBAL VARIABLES '''
HTTP_200_OK = 200
HTTP_400_BAD_REQUEST = 400
HTTP_401_UNAUTHORIZED = 401
INTEGRATION_NAME: str = 'TAXII Server'
API_ROOT = 'threatintel'
APP: Flask = Flask('demisto-taxii2Z')
NAMESPACE_URI = 'https://www.paloaltonetworks.com/cortex'
MEDIA_TYPE_TAXII_ANY = 'application/taxii+json'
MEDIA_TYPE_STIX_ANY = 'application/stix+json'
MEDIA_TYPE_TAXII_V21 = 'application/taxii+json;version=2.1'
MEDIA_TYPE_STIX_V21 = 'application/stix+json;version=2.1'
MEDIA_TYPE_TAXII_V20 = 'application/vnd.oasis.taxii+json; version=2.0'
MEDIA_TYPE_STIX_V20 = 'application/vnd.oasis.stix+json; version=2.0'
ACCEPT_TYPE_ALL = '*/*'
TAXII_VER_2_0 = '2.0'
TAXII_VER_2_1 = '2.1'
PAWN_UUID = uuid.uuid5(uuid.NAMESPACE_URL, 'https://www.paloaltonetworks.com')
SCO_DET_ID_NAMESPACE = uuid.UUID('00abedb4-aa42-466c-9c01-fed23315a9b7')

XSOAR_TYPES_TO_STIX_SCO = {
    FeedIndicatorType.CIDR: 'ipv4-addr',
    FeedIndicatorType.DomainGlob: 'domain-name',
    FeedIndicatorType.IPv6: 'ipv6-addr',
    FeedIndicatorType.IPv6CIDR: 'ipv6-addr',
    FeedIndicatorType.Account: 'user-account',
    FeedIndicatorType.Domain: 'domain-name',
    FeedIndicatorType.Email: 'email-addr',
    FeedIndicatorType.Host: '?????',  # TODO: Check what to do.
    FeedIndicatorType.IP: 'ipv4-addr',
    FeedIndicatorType.Registry: 'windows-registry-key',
    FeedIndicatorType.File: 'file',
    FeedIndicatorType.URL: 'url',
}

XSOAR_TYPES_TO_STIX_SDO = {
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: 'attack-pattern',
    ThreatIntel.ObjectsNames.CAMPAIGN: 'campaign',
    ThreatIntel.ObjectsNames.COURSE_OF_ACTION: 'course-of-action',
    ThreatIntel.ObjectsNames.INFRASTRUCTURE: 'infrastructure',
    ThreatIntel.ObjectsNames.INTRUSION_SET: 'instruction-set',
    ThreatIntel.ObjectsNames.REPORT: 'report',
    ThreatIntel.ObjectsNames.THREAT_ACTOR: 'threat-actor',
    ThreatIntel.ObjectsNames.TOOL: 'tool',
    ThreatIntel.ObjectsNames.MALWARE: 'malware',
    FeedIndicatorType.CVE: 'vulnerability',
}

STIX2_TYPES_TO_XSOAR = {
    'campaign': ThreatIntel.ObjectsNames.CAMPAIGN,
    'attack-pattern': ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    'report': ThreatIntel.ObjectsNames.REPORT,
    'malware': ThreatIntel.ObjectsNames.MALWARE,
    'course-of-action': ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    'intrusion-set': ThreatIntel.ObjectsNames.INTRUSION_SET,
    'tool': ThreatIntel.ObjectsNames.TOOL,
    'threat-actor': ThreatIntel.ObjectsNames.THREAT_ACTOR,
    'infrastructure': ThreatIntel.ObjectsNames.INFRASTRUCTURE,
    'vulnerability': FeedIndicatorType.CVE,
    "ipv4-addr": FeedIndicatorType.IP,
    "ipv6-addr": FeedIndicatorType.IPv6,
    "domain-name": [FeedIndicatorType.DomainGlob, FeedIndicatorType.Domain],
    'user-account': FeedIndicatorType.Account,
    'email-addr': FeedIndicatorType.Email,
    "url": FeedIndicatorType.URL,
    "file": FeedIndicatorType.File,
    'windows-registry-key': FeedIndicatorType.Registry,
}

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
        self.namespace_uuid = uuid.uuid5(PAWN_UUID, demisto.getLicenseID())
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
            collection_uuid = str(uuid.uuid5(self.namespace_uuid, 'Collection_' + name))
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

    def get_objects(self, api_root: str, collection_id: str, added_after, limit: int, offset: int, ids: list,
                    types: list, versions: list):
        if not api_root == self._api_root:
            raise Exception(f"Unknown API Root {api_root}. Check possible API Roots using '{self.discovery_route}'")
        found_collection = self._collections_by_id.get(collection_id)

        if not found_collection:
            raise Exception(f'No collection with id "{collection_id}". '
                            f'Use "/{api_root}/collections/" to get all existing collections.')

        query = found_collection.get('description')
        new_limit = offset + limit
        new_query = create_query(query, ids, types, versions)
        ios = find_indicators(query=new_query, added_after=added_after, limit=new_limit)

        first_added = None
        last_added = None
        objects = ios[offset:offset + limit]

        if objects:
            first_added = objects[0].get('created')
            last_added = objects[-1].get('created')

        bundle = {
            'type': 'bundle',
            'objects': objects,
            'id': '123'  # TODO: what is a bundle id?
        }
        response = bundle
        if self.version == TAXII_VER_2_1:
            response = {
                'data': bundle
            }

        return response, first_added, last_added


SERVER: TAXII2Server

''' HELPER FUNCTIONS '''


def taxii_validate_request(f):
    @functools.wraps(f)
    def validate_request(*args, **kwargs):
        """
        function of HTTP requests to validate authentication and Accept headers.
        """
        accept_headers = [MEDIA_TYPE_TAXII_ANY, MEDIA_TYPE_TAXII_V20, MEDIA_TYPE_TAXII_V21,
                          MEDIA_TYPE_STIX_V20, ACCEPT_TYPE_ALL]
        credentials = request.authorization
        if SERVER.auth:
            auth_success = (compare_digest(credentials.username, SERVER.auth[0])
                            and compare_digest(credentials.password, SERVER.auth[1]))
            if not auth_success:
                handle_long_running_error('Authorization failed')
                return handle_response(HTTP_401_UNAUTHORIZED, {'title': 'Authorization failed'})
        request_headers = request.headers
        if (accept_header := request_headers.get('Accept')) not in accept_headers:
            handle_long_running_error('Invalid TAXII Headers')
            return handle_response(HTTP_400_BAD_REQUEST,
                                   {'title': 'Invalid TAXII Headers',
                                    'description': f'Invalid Accept header: {accept_header}, '
                                                   f'please use one ot the following Accept headers: '
                                                   f'{accept_headers}'})
        return f(*args, **kwargs)

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
    if status_code == HTTP_401_UNAUTHORIZED:
        headers['WWW-Authenticate'] = f'Basic realm="Authentication Required"'
    if date_added_first:
        headers['X-TAXII-Date-Added-First'] = date_added_first
    if date_added_last:
        headers['X-TAXII-Date-Added-Last'] = date_added_last

    return make_response(jsonify(content), status_code, headers)


def create_query(query, ids, types, versions):
    new_query = query + ' '
    if ids:
        # TODO: add filtering by id.
        pass
    if types:
        try:
            xsoar_types = [STIX2_TYPES_TO_XSOAR[t] for t in types]
        except KeyError as e:
            raise Exception(f'Unsupported object type: {e}.')
        new_query += ' or '.join(['type:' + x for x in xsoar_types])
    if versions:
        # TODO: check if we have versions. options: [last, first, all, <value>]
        pass
    return new_query


def find_indicators(query: str, added_after, limit: int) -> list:
    iocs: List[dict] = []
    indicator_searcher = IndicatorsSearcher(
        query=query,
        limit=limit,
        from_date=added_after
    )
    for ioc in indicator_searcher:
        found_indicators = ioc.get('iocs') or []
        for xsoar_indicator in found_indicators:
            xsoar_type = xsoar_indicator.get('indicator_type')
            stix_ioc = FUNCTIONS_FOR_XSOAR_TYPES[xsoar_type](xsoar_indicator, xsoar_type)
            iocs.append(stix_ioc)

    return iocs


def create_sco_stix_uuid(value, stix_type):
    unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, value)
    stix_id = f'{stix_type}--{unique_id}'
    return stix_id


def create_sdo_stix_uuid(value, stix_type):
    unique_id = uuid.uuid5(SERVER.namespace_uuid, value)
    stix_id = f'{stix_type}--{unique_id}'
    return stix_id


def create_stix_ip(xsoar_indicator, xsoar_type):
    stix_type = XSOAR_TYPES_TO_STIX_SCO.get(xsoar_type)
    value = xsoar_indicator.get('value')
    stix_id = create_sco_stix_uuid('{"value":"' + value + '"}', stix_type)
    # TODO: create mapping
    ipv4 = {
        'id': stix_id,
        'value': value,
        'type': stix_type,
        'created': xsoar_indicator.get('firstSeen'),
        'modified': xsoar_indicator.get('modified'),
    }
    return ipv4


# TODO: build functions for each indicator type


def parse_content_range(content_range):
    range_type, range_count = content_range.split(' ', 1)

    if range_type != 'items':
        raise Exception(f'Bad Content-Range header: {content_range}.')

    range_count, _ = range_count.split('/', 1)
    range_begin, range_end = range_count.split('-', 1)

    offset = int(range_begin)
    limit = int(range_end)

    return offset, limit


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


FUNCTIONS_FOR_XSOAR_TYPES = {
    FeedIndicatorType.CIDR: create_stix_ip,
    FeedIndicatorType.DomainGlob: 'domain-name',
    FeedIndicatorType.IPv6: create_stix_ip,
    FeedIndicatorType.IPv6CIDR: create_stix_ip,
    FeedIndicatorType.Account: 'user-account',
    FeedIndicatorType.Domain: 'domain-name',  # TODO: Maybe domain?
    FeedIndicatorType.Email: 'email-addr',
    FeedIndicatorType.Host: '?????',  # TODO: Check what to do.
    FeedIndicatorType.IP: create_stix_ip,
    FeedIndicatorType.Registry: 'windows-registry-key',
    FeedIndicatorType.File: 'file',
    FeedIndicatorType.URL: 'url',
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: 'attack-pattern',
    ThreatIntel.ObjectsNames.CAMPAIGN: 'campaign',
    ThreatIntel.ObjectsNames.COURSE_OF_ACTION: 'course-of-action',
    ThreatIntel.ObjectsNames.INFRASTRUCTURE: 'infrastructure',
    ThreatIntel.ObjectsNames.INTRUSION_SET: 'instruction-set',
    ThreatIntel.ObjectsNames.REPORT: 'report',
    ThreatIntel.ObjectsNames.THREAT_ACTOR: 'threat-actor',
    ThreatIntel.ObjectsNames.TOOL: 'tool',
    ThreatIntel.ObjectsNames.MALWARE: 'malware',
    FeedIndicatorType.CVE: 'vulnerability',
}

''' ROUTE FUNCTIONS '''


@APP.route('/taxii/', methods=['GET'])  # TAXII v2.0
@APP.route('/taxii2/', methods=['GET'])  # TAXII v2.1
@taxii_validate_request
def taxii2_server_discovery():
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
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'Discovery Request Error',
                                                      'description': error})

    return handle_response(HTTP_200_OK, discovery_response)


@APP.route('/<api_root>/', methods=['GET'])
@taxii_validate_request
def taxii2_api_root(api_root):
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
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'API Root Request Error',
                                                      'description': error})

    return handle_response(HTTP_200_OK, api_root_response)


@APP.route('/<api_root>/status/<status_id>/', methods=['GET'])
@taxii_validate_request
def taxii2_status(api_root, status_id):
    # TODO: Not allowed
    pass


@APP.route('/<api_root>/collections/', methods=['GET'])
@taxii_validate_request
def taxii2_collections(api_root: str):
    """
    Defines TAXII API - Collections:
    Get Collection section (5.1) `here for v.2 <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988049>`__
    Args:
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
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'Collections Request Error',
                                                      'description': error})
    return handle_response(HTTP_200_OK, collections_response)


@APP.route('/<api_root>/collections/<collection_id>/', methods=['GET'])
@taxii_validate_request
def taxii2_collection_by_id(api_root: str, collection_id: str):
    """
    Defines TAXII API - Collections:
    Get Collection section (5.2) `here for v.2.0 <http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542736>`__
    and `here for v.2.1 <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988051>`__
    Args:
        collection_id:
        api_root (str): the base URL of the API Root
    Returns:
        collections: A Collection Resource with given id upon successful requests.
    """
    try:
        collection_response = SERVER.get_collection_by_id(api_root, collection_id)
    except Exception as e:
        error = f'Could not perform the collection request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'Collection Request Error',
                                                      'description': error})
    return handle_response(HTTP_200_OK, collection_response)


@APP.route('/<api_root>/collections/<collection_id>/manifest/', methods=['GET'])
@taxii_validate_request
def taxii2_manifest(api_root: str, collection_id: str):
    # TODO: implement
    pass


@APP.route('/<api_root>/collections/<collection_id>/objects/', methods=['GET'])
@taxii_validate_request
def taxii2_objects(api_root: str, collection_id: str):
    """
    Defines TAXII API - Collections Objects:
    Get Collection section (5.4) `here <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988055>`__
    Args:
        collection_id:
        api_root (str): the base URL of the API Root
    Returns:
        envelope: A Envelope Resource upon successful requests. Additional information
        `here <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988038>`__.
    """
    try:
        # TODO: Parse match arguments
        added_after = request.args.get('added_after')
        ids = argToList(request.args.get('match[id]'))  # TODO: Maybe not supported
        types = argToList(request.args.get('match[type]'))
        versions = argToList(request.args.get('match[version]'))
        limit = 500  # TODO: should limit have default param?
        offset = 0

        try:
            if added_after:
                datetime.strptime(added_after, '%Y-%m-%dT%H:%M:%S.%fZ')
        except ValueError as e:
            raise Exception(f'Added after time format should be YYYY-MM-DDTHH:mm:ss.[s+]Z. {e}')

        if SERVER.version == TAXII_VER_2_0:
            if content_range := request.headers.get('Content-Range'):
                offset, limit = parse_content_range(content_range)
            elif range := request.headers.get('Range'):
                offset, limit = parse_content_range(range)

        elif SERVER.version == TAXII_VER_2_1:
            limit = request.args.get('limit')
            limit = int(limit) if limit else None

        objects_response, date_added_first, date_added_last = SERVER.get_objects(
            api_root=api_root,
            collection_id=collection_id,
            added_after=added_after,
            offset=offset,
            limit=limit,
            ids=ids,
            types=types,
            versions=versions,
        )
    except Exception as e:
        error = f'Could not perform the objects request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'Objects Request Error',
                                                      'description': error})

    return handle_response(
        status_code=HTTP_200_OK,
        content=objects_response,
        date_added_first=date_added_first,
        date_added_last=date_added_last,
        content_type=MEDIA_TYPE_STIX_V20 if SERVER.version == TAXII_VER_2_0 else MEDIA_TYPE_TAXII_V21
    )


''' COMMAND FUNCTIONS '''


def run_server(port: int, certificate: str, private_key: str):
    """
    Start the taxii server.
    """
    ssl_args = dict()
    if certificate and private_key:
        certificate_file = NamedTemporaryFile(delete=False)
        certificate_path = certificate_file.name
        certificate_file.write(bytes(certificate, 'utf-8'))
        certificate_file.close()

        private_key_file = NamedTemporaryFile(delete=False)
        private_key_path = private_key_file.name
        private_key_file.write(bytes(private_key, 'utf-8'))
        private_key_file.close()
        context = SSLContext(PROTOCOL_TLSv1_2)
        context.load_cert_chain(certificate_path, private_key_path)
        ssl_args['ssl_context'] = context
        demisto.debug('Starting HTTPS Server')
    else:
        demisto.debug('Starting HTTP Server')

    # log=DEMISTO_LOGGER
    wsgi_server = WSGIServer(('0.0.0.0', port), APP, **ssl_args)
    demisto.updateModuleHealth('')
    wsgi_server.serve_forever()


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
            run_server(port, certificate, private_key)

        elif command == 'test-module':
            return_results('ok')

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


from NGINXApiModule import *  # noqa: E402

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
