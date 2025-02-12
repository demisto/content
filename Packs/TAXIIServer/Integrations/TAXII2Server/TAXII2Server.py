import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import functools
import uuid
import json
from collections.abc import Callable
from flask import Flask, request, make_response, jsonify, Response
from urllib.parse import ParseResult, urlparse
from secrets import compare_digest
from requests.utils import requote_uri
from werkzeug.exceptions import RequestedRangeNotSatisfiable

''' GLOBAL VARIABLES '''
HTTP_200_OK = 200
HTTP_400_BAD_REQUEST = 400
HTTP_401_UNAUTHORIZED = 401
HTTP_404_NOT_FOUND = 404
HTTP_406_NOT_ACCEPTABLE = 406
HTTP_416_RANGE_NOT_SATISFIABLE = 416
INTEGRATION_NAME: str = 'TAXII2 Server'
API_ROOT = 'threatintel'
APP: Flask = Flask('demisto-taxii2Z')
NAMESPACE_URI = 'https://www.paloaltonetworks.com/cortex'
MEDIA_TYPE_TAXII_ANY = 'application/taxii+json'
MEDIA_TYPE_STIX_ANY = 'application/stix+json'
MEDIA_TYPE_TAXII_V21 = 'application/taxii+json;version=2.1'
MEDIA_TYPE_STIX_V21 = 'application/stix+json;version=2.1'
MEDIA_TYPE_TAXII_V20 = 'application/vnd.oasis.taxii+json; version=2.0'
MEDIA_TYPE_STIX_V20 = 'application/vnd.oasis.stix+json; version=2.0'
SCO_DET_ID_NAMESPACE = uuid.UUID('00abedb4-aa42-466c-9c01-fed23315a9b7')
STIX_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
UTC_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
TAXII_V20_CONTENT_LEN = 9765625
TAXII_V21_CONTENT_LEN = 104857600
TAXII_REQUIRED_FILTER_FIELDS = {'name', 'type', 'modified', 'createdTime', 'description',
                                'accounttype', 'userid', 'mitreid', 'stixid', 'reportobjectreferences',
                                'keyvalue', 'tags', 'subject', 'issuer',
                                'validitynotbefore', 'validitynotafter'}
TAXII_V20_REQUIRED_FILTER_FIELDS = {"tags", "identity_class"}
TAXII_V21_REQUIRED_FILTER_FIELDS = {"ismalwarefamily", "published"}
PAGE_SIZE = 2000

''' TAXII2 Server '''


class TAXII2Server:
    def __init__(self, url_scheme: str, host: str, port: int, collections: dict, certificate: str, private_key: str,
                 http_server: bool, credentials: dict, version: str, service_address: Optional[str] = None,
                 fields_to_present: Optional[set] = None, types_for_indicator_sdo: Optional[list] = None):
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
            fields_to_present: indicator fields to return in the request.
            types_for_indicator_sdo: The list of stix types to provide indicator stix domain objects.
        """
        self._url_scheme = url_scheme
        self._host = host.replace('.xdr', '.crtx')
        self._port = port
        self._certificate = certificate
        self._private_key = private_key
        self._http_server = http_server
        self._service_address = service_address
        self.fields_to_present = fields_to_present
        self.has_extension = fields_to_present != {'name', 'type'}
        self._auth = None
        if credentials and (identifier := credentials.get('identifier')) and (password := credentials.get('password')):
            self._auth = (identifier, password)
        self.version = version
        if version not in [TAXII_VER_2_0, TAXII_VER_2_1]:
            raise Exception(f'Wrong TAXII 2 Server version: {version}. '
                            f'Possible values: {TAXII_VER_2_0}, {TAXII_VER_2_1}.')
        self._collections_resource: list = []
        self.collections_by_id: dict = {}
        self.namespace_uuid = uuid.uuid5(PAWN_UUID, demisto.getLicenseID())
        self.create_collections(collections)
        self.types_for_indicator_sdo = types_for_indicator_sdo or []

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

    def create_collections(self, collections: dict):
        """
        Creates collection resources from collection params.
        """
        collections_resource = []
        collections_by_id = {}
        for name, query_dict in collections.items():
            description = ''
            if isinstance(query_dict, dict):
                query = query_dict.get('query')
                description = query_dict.get('description', '')
            else:
                query = query_dict
            if query is None:
                raise Exception('Collection query is required.')
            collection_uuid = str(uuid.uuid5(self.namespace_uuid, 'Collection_' + name))
            collection = {
                'id': collection_uuid,
                'title': name,
                'description': description,
                'can_read': True,
                'can_write': False,
                'media_types': [self.taxii_collections_media_type],
                'query': query
            }
            collections_resource.append(collection)
            collections_by_id[collection_uuid] = collection

        self._collections_resource = collections_resource
        self.collections_by_id = collections_by_id

    def get_discovery_service(self, instance_execute=False) -> dict:
        """
        Handle discovery request.

        Returns:
            The discovery response.
        """
        if self._service_address:
            service_address = self._service_address
        elif instance_execute or (request.headers and '/instance/execute' in request.headers.get('X-Request-URI', '')):
            # if the server rerouting is used, then the X-Request-URI header is added to the request by the server
            # and we should use the /instance/execute endpoint in the address
            self._url_scheme = 'https'
            calling_context = get_calling_context()
            instance_name = calling_context.get('IntegrationInstance', '')
            endpoint = requote_uri(os.path.join('/instance', 'execute', instance_name))
            if is_xsiam_or_xsoar_saas() and not instance_execute:
                service_address = f'{self._url_scheme}://ext-{self._host}/xsoar{endpoint}'
            else:
                service_address = f'{self._url_scheme}://{self._host}{endpoint}'
        else:
            endpoint = f':{self._port}'
            if is_xsiam_or_xsoar_saas() and not instance_execute:
                service_address = f'{self._url_scheme}://ext-{self._host}/xsoar{endpoint}'
            else:
                service_address = f'{self._url_scheme}://{self._host}{endpoint}'

        default = urljoin(service_address, API_ROOT)
        default = urljoin(default, '/')
        return {
            'title': 'Cortex XSOAR TAXII2 Server',
            'description': 'This integration provides TAXII Services for system indicators (Outbound feed).',
            'default': default,
            'api_roots': [default]
        }

    def get_api_root(self) -> dict:
        """
        Handle API Root request.

        Returns:
            The API ROOT response.
        """
        return {
            'title': 'Cortex XSOAR TAXII2 Server ThreatIntel',
            'description': 'This API Root provides TAXII Services for system indicators.',
            'versions': [self.api_version],
            'max_content_length': TAXII_V20_CONTENT_LEN if self.version == TAXII_VER_2_0 else TAXII_V21_CONTENT_LEN
        }

    def get_collections(self) -> dict:
        """
        Handle Collections request.

        Returns:
            The Collections response.
        """
        return {'collections': self._collections_resource}

    def get_collection_by_id(self, collection_id: str) -> Optional[dict]:
        """
        Handle Collection ID request.

        Returns:
            The Collection with given ID response.
        """
        found_collection = self.collections_by_id.get(collection_id)  # type: Optional[dict]
        return found_collection

    def get_manifest(self, collection_id: str, added_after, limit: int, offset: int,
                     types: list) -> tuple:
        """
        Handle Manifest request.

        Returns:
            The objects from given collection ID.
        """
        found_collection = self.collections_by_id.get(collection_id, {})
        query = found_collection.get('query')
        iocs, _, total = find_indicators(
            query=query,
            types=types,
            added_after=added_after,
            limit=limit,
            offset=offset,
            is_manifest=True)

        first_added = None
        last_added = None
        objects = iocs[offset:offset + limit]
        if iocs and not objects:
            raise RequestedRangeNotSatisfiable

        if objects:
            first_added = objects[-1].get('date_added')
            last_added = objects[0].get('date_added')
            demisto.debug(f"T2S: get_manifest {objects=}")

        response = {
            'objects': objects,
        }

        if self.version == TAXII_VER_2_1 and total > offset + limit:
            response['more'] = True
            response['next'] = str(limit + offset)

        content_range = f'items {offset}-{len(objects)}/{total}'
        return response, first_added, last_added, content_range

    def get_objects(self, collection_id: str, added_after, limit: int, offset: int, types: list) -> tuple:
        """
        Handle Objects request.

        Returns:
            The objects from given collection ID.
        """
        found_collection = self.collections_by_id.get(collection_id, {})
        query = found_collection.get('query')
        demisto.debug(f"T2S: calling find_indicators with {query=} {types=} {added_after=} {limit=} {offset=}")
        iocs, extensions, total = find_indicators(
            query=query,
            types=types,
            added_after=added_after,
            limit=limit,
            offset=offset)
        demisto.debug(f"T2S: after find_indicators {iocs}")

        first_added = None
        last_added = None
        limited_extensions = None

        limited_iocs = iocs[offset:offset + limit]
        if iocs and not limited_iocs:
            raise RequestedRangeNotSatisfiable

        objects = limited_iocs
        demisto.debug(f"T2S: in get_objects {objects=}")

        if SERVER.has_extension:
            limited_extensions = get_limited_extensions(limited_iocs, extensions)
            objects.extend(limited_extensions)

        if limited_iocs:
            first_added = limited_iocs[-1].get('created')
            last_added = limited_iocs[0].get('created')

        response = {}
        if self.version == TAXII_VER_2_0:
            response = {
                'type': 'bundle',
                'objects': objects,
                'id': f'bundle--{uuid.uuid4()}'
            }
        elif self.version == TAXII_VER_2_1:
            response = {
                'objects': objects,
            }
            if total > offset + limit:
                response['more'] = True
                response['next'] = str(limit + offset)

        content_range = f'items {offset}-{len(limited_iocs)}/{total}'

        return response, first_added, last_added, content_range


SERVER: TAXII2Server = None  # type: ignore[assignment]

''' HELPER FUNCTIONS '''


def get_limited_extensions(limited_iocs, extensions):
    """
    Args:
        limited_iocs: List of the limited iocs.
        extensions: List of all the generated extensions to limit.

    Returns: List of the limited extensions related to the limited iocs.
    """
    limited_extensions = []
    required_extensions_ids = []
    for ioc in limited_iocs:
        required_extensions_ids.extend(list(ioc.get('extensions', {}).keys()))
    for extension in extensions:
        if extension.get('id') in required_extensions_ids:
            limited_extensions.append(extension)
    return limited_extensions


def remove_spaces_from_header(header: str | list) -> str | list:
    """ Remove spaces from a header or list of headers.

    Args:
        header (str | list): A single header or a list of headers to remove spaces from.

    Returns:
        str | list: The header or list of headers without spaces.
    """
    if isinstance(header, list):
        return [value.replace(' ', '') for value in header]
    return header.replace(' ', '')


def taxii_validate_request_headers(f: Callable) -> Callable:
    @functools.wraps(f)
    def validate_request_headers(*args, **kwargs):
        """
        function for HTTP requests to validate authentication and Accept headers.
        """
        accept_headers = [MEDIA_TYPE_TAXII_ANY, MEDIA_TYPE_TAXII_V20,
                          MEDIA_TYPE_STIX_V20, MEDIA_TYPE_TAXII_V21, MEDIA_TYPE_STIX_V21]
        credentials = request.authorization

        if SERVER.auth:
            if credentials:
                try:
                    auth_success = (compare_digest(credentials.username, SERVER.auth[0])  # type: ignore[type-var]
                                    and compare_digest(credentials.password, SERVER.auth[1]))  # type: ignore[type-var]
                except TypeError:
                    auth_success = False
            else:
                auth_success = False
            if not auth_success:
                return handle_response(HTTP_401_UNAUTHORIZED, {'title': 'Authorization failed'})

        request_headers = request.headers

        # v2.0 headers has a space while v2.1 does not,
        # this caused confusion with platforms sometimes sending a header with or without space.
        # to avoid issues the Accept header is stripped from the spaces before validation.
        accept_header = request_headers.get('Accept')

        if (not accept_header) or (remove_spaces_from_header(accept_header) not in remove_spaces_from_header(accept_headers)):
            return handle_response(HTTP_406_NOT_ACCEPTABLE,
                                   {'title': 'Invalid TAXII Headers',
                                    'description': f'Invalid Accept header: {accept_header}, '
                                                   f'please use one ot the following Accept headers: '
                                                   f'{accept_headers}'})

        possible_v20_headers = [MEDIA_TYPE_TAXII_V20, MEDIA_TYPE_STIX_V20] + list(remove_spaces_from_header([MEDIA_TYPE_TAXII_V20,
                                                                                                            MEDIA_TYPE_STIX_V20]))
        if SERVER.version == TAXII_VER_2_1 and accept_header in possible_v20_headers:
            return handle_response(HTTP_406_NOT_ACCEPTABLE, {
                'title': 'Invalid TAXII Header',
                'description': 'The media type (version=2.0) provided in the Accept header'
                               ' is not supported on TAXII v2.1.'
            })

        return f(*args, **kwargs)

    return validate_request_headers


def taxii_validate_url_param(f: Callable) -> Callable:
    @functools.wraps(f)
    def validate_url_param(*args, **kwargs):
        """
        function for HTTP/HTTPS requests to validate api_root and collection_id.
        """
        api_root = kwargs.get('api_root')
        collection_id = kwargs.get('collection_id')
        if api_root and api_root != API_ROOT:
            return handle_response(HTTP_404_NOT_FOUND,
                                   {'title': 'Unknown API Root',
                                    'description': f"Unknown API Root {api_root}. Check possible API Roots using "
                                                   f"'{SERVER.discovery_route}'"})

        if collection_id and not SERVER.collections_by_id.get(collection_id):
            return handle_response(HTTP_404_NOT_FOUND,
                                   {'title': 'Unknown Collection',
                                    'description': f'No collection with id "{collection_id}". '
                                                   f'Use "/{api_root}/collections/" to get '
                                                   f'all existing collections.'})

        return f(*args, **kwargs)

    return validate_url_param


def create_fields_list(fields: str) -> set:
    if not fields:
        return {'name', 'type'}
    elif fields.lower() == 'all':
        return set()
    fields_list = argToList(fields)
    new_list = set()
    for field in fields_list:
        if field == 'value':
            field = 'name'
        elif field == 'indicator_type':
            field = 'type'
        new_list.add(field)
    return new_list


def handle_long_running_error(error: str):
    """
    Handle errors in the long running process.
    Args:
        error: The error message.
    """
    demisto.error(traceback.format_exc())
    demisto.updateModuleHealth(error)


def handle_response(status_code: int, content: dict, date_added_first: str = None, date_added_last: str = None,
                    content_type: str = None, content_range: str = None, query_time: str = None) -> Response:
    """
    Create an HTTP taxii response from a taxii message.
    Args:
        query_time: time query took
        content_range: Content-Range response header
        status_code: status code to return
        content_type: response content type to return
        date_added_last: last added item creation time
        date_added_first: first added item creation time
        content: response data

    Returns:
        A taxii HTTP response.
    """
    if not content_type:
        content_type = SERVER.taxii_content_type
    headers = {
        'Content-Type': content_type,
    }
    if status_code == HTTP_401_UNAUTHORIZED:
        headers['WWW-Authenticate'] = 'Basic realm="Authentication Required"'
    if date_added_first:
        headers['X-TAXII-Date-Added-First'] = date_added_first
    if date_added_last:
        headers['X-TAXII-Date-Added-Last'] = date_added_last
    if SERVER.version == TAXII_VER_2_0 and content_range:
        headers['Content-Range'] = content_range
    if query_time:
        headers['X-TAXII2SERVER-Query-Time-Secs'] = query_time

    return make_response(jsonify(content), status_code, headers)


def create_query(query: str, types: list[str], added_after: str) -> str:
    """
    Args:
        query: collections query
        types: indicator types to filter by

    Returns:
        New query with types params
    """
    new_query = ''
    if types:
        demisto.debug(f'{INTEGRATION_NAME}: raw query: {query}')
        xsoar_types: list = []
        for t in types:
            xsoar_type = STIX2_TYPES_TO_XSOAR.get(t, t)
            xsoar_types.extend(xsoar_type if isinstance(xsoar_type, tuple) else (xsoar_type,))

        if query.strip():
            new_query = f'({query})'

        if or_part := (' or '.join(f'type:"{x}"' for x in xsoar_types)):
            new_query += f' and ({or_part})'

        demisto.debug(f'{INTEGRATION_NAME}: modified query, after adding types: {new_query}')
        query = new_query
    return f'{query} and modified:>="{added_after}"' if added_after else f'{query}'


def set_field_filters(is_manifest: bool = False) -> Optional[str]:
    """
    Args:
        is_manifest: whether this call is for manifest or indicators

    Returns: A string of filters.
    """
    if is_manifest:
        field_filters: Optional[str] = ','.join(TAXII_REQUIRED_FILTER_FIELDS)
    elif SERVER.fields_to_present:
        fields_by_version = (TAXII_V20_REQUIRED_FILTER_FIELDS if SERVER.version
                             == TAXII_VER_2_0 else TAXII_V21_REQUIRED_FILTER_FIELDS)
        set_fields = set.union(SERVER.fields_to_present, TAXII_REQUIRED_FILTER_FIELDS, fields_by_version)
        field_filters = ','.join(set_fields)  # type: ignore[arg-type]
    else:
        field_filters = None

    return field_filters


def search_indicators(field_filters: Optional[str], query: str, limit: int) -> IndicatorsSearcher:
    """
    Args:
        field_filters: filter
        query: query
        limit: response items limit

    Returns: IndicatorsSearcher.
    """
    indicator_searcher = IndicatorsSearcher(
        filter_fields=field_filters,
        query=query,
        limit=limit,
        size=PAGE_SIZE,
        sort=[{"field": "modified", "asc": True}],
    )
    return indicator_searcher


def find_indicators(query: str, types: list, added_after, limit: int, offset: int, is_manifest: bool = False) -> tuple:
    """
    Args:
        query: search indicators query
        types: types to query by
        added_after: search indicators after this date
        limit: response items limit
        offset: response offset
        is_manifest: whether this call is for manifest or indicators

    Returns: Created indicators and its extensions.
    """
    new_query = create_query(query, types, added_after)
    new_limit = offset + limit
    field_filters = set_field_filters(is_manifest)
    demisto.info(f"{INTEGRATION_NAME}: search indicators parameters is {field_filters=}, {new_query=}, {new_limit=}")
    indicator_searcher = search_indicators(field_filters, new_query, new_limit)

    XSOAR2STIXParser_client = XSOAR2STIXParser(server_version=SERVER.version, namespace_uuid=SERVER.namespace_uuid,
                                               fields_to_present=SERVER.fields_to_present,
                                               types_for_indicator_sdo=SERVER.types_for_indicator_sdo)
    iocs, extensions, total = XSOAR2STIXParser_client.create_indicators(indicator_searcher, is_manifest)
    demisto.debug(f"T2S: find_indicators {iocs=}")

    return iocs, extensions, total


def parse_content_range(content_range: str) -> tuple:
    """
    Args:
        content_range: the content-range or range header to parse.

    Returns:
        Offset and limit arguments for the command.
    """
    try:
        range_type, range_count = content_range.split(' ', 1)

        range_count_arr = range_count.split('/')
        range_begin, range_end = range_count_arr[0].split('-', 1)

        offset = int(range_begin)
        limit = int(range_end) - offset

        if range_type != 'items' or range_end < range_begin or limit < 0 or offset < 0:
            raise Exception

    except Exception:
        raise RequestedRangeNotSatisfiable(description=f'Range header: {content_range}')

    return offset, limit


def get_collections(params: Optional[dict] = None) -> dict:
    """
    Gets the indicator query collections from the integration parameters.
    """
    params = params or demisto.params()
    collections_json: str = params.get('collections', '')

    try:
        collections = json.loads(collections_json)
    except Exception:
        raise ValueError('The collections string must be a valid JSON object.')

    return collections


def get_calling_context():
    return demisto.callingContext.get('context', {})  # type: ignore[attr-defined]


def parse_manifest_and_object_args() -> tuple:
    """ Parses request args for manifest and objects requests. """
    added_after = request.args.get('added_after')
    types = argToList(request.args.get('match[type]'))
    try:
        res_size = int(demisto.params().get('res_size'))
    except ValueError as e:
        raise ValueError(f'Invalid Response Size - {e}')
    offset = 0
    limit = res_size

    if request.args.get('match[id]') or request.args.get('match[version]'):
        raise NotImplementedError('Filtering by ID or version is not supported.')

    try:
        if added_after:
            datetime.strptime(added_after, UTC_DATE_FORMAT)
    except ValueError:
        try:
            if added_after:
                datetime.strptime(added_after, STIX_DATE_FORMAT)
        except Exception as e:
            raise Exception(f'Added after time format should be YYYY-MM-DDTHH:mm:ss.[s+]Z. {e}')

    if SERVER.version == TAXII_VER_2_0:
        if content_range := request.headers.get('Content-Range'):
            offset, limit = parse_content_range(content_range)
        elif range := request.headers.get('Range'):
            offset, limit = parse_content_range(range)

    elif SERVER.version == TAXII_VER_2_1:
        next = request.args.get('next')
        limit_arg = request.args.get('limit')

        offset = int(next) if next else 0
        limit = int(limit_arg) if limit_arg else limit

    if limit > res_size:
        limit = res_size

    return added_after, offset, limit, types


''' ROUTE FUNCTIONS '''


@APP.route('/taxii/', methods=['GET'])  # TAXII v2.0
@APP.route('/taxii2/', methods=['GET'])  # TAXII v2.1
@taxii_validate_request_headers
def taxii2_server_discovery() -> Response:
    """
    Defines TAXII API - Server Information:
    Server Discovery section (4.1) `here  for v2.1
    <https://docs.oasis-open.org/cti/taxii/v2.1/cs01/taxii-v2.1-cs01.html#_Toc31107526>`__
    and `here for v2.0 <http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542727>`__
    Returns:
        discovery: A Discovery Resource upon successful requests.
    """
    try:
        discovery_response = SERVER.get_discovery_service()
    except Exception as e:
        error = f'Could not perform the discovery request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'Discovery Request Error',
                                                      'description': error})

    return handle_response(HTTP_200_OK, discovery_response)


@APP.route('/<api_root>', methods=['GET'], strict_slashes=False)
@taxii_validate_request_headers
@taxii_validate_url_param
def taxii2_api_root(api_root: str) -> Response:
    """
     Defines TAXII API - Server Information:
     Get API Root Information section (4.2) `here
     <https://docs.oasis-open.org/cti/taxii/v2.1/cs01/taxii-v2.1-cs01.html#_Toc31107528>`__
     Args:
         api_root (str): the base URL of the API Root
     Returns:
         api-root: An API Root Resource upon successful requests.
     """
    try:
        api_root_response = SERVER.get_api_root()
    except Exception as e:
        error = f'Could not perform the API Root request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'API Root Request Error',
                                                      'description': error})

    return handle_response(HTTP_200_OK, api_root_response)


@APP.route('/<api_root>/status/<status_id>', methods=['GET'], strict_slashes=False)
@taxii_validate_request_headers
@taxii_validate_url_param
def taxii2_status(api_root: str, status_id: str) -> Response:  # noqa: F841
    """Status API call used to check status for adding object to the system.
    Our collections are read only. No option to add objects.
    Then All status requests ending with error.

    Returns: Error response.
    """
    return handle_response(HTTP_404_NOT_FOUND, {'title': 'Get Status not allowed.',
                                                'description': 'Status ID is not found, or the client does not have '
                                                               'access to the resource'})


@APP.route('/<api_root>/collections', methods=['GET'], strict_slashes=False)
@taxii_validate_request_headers
@taxii_validate_url_param
def taxii2_collections(api_root: str) -> Response:
    """
    Defines TAXII API - Collections:
    Get Collection section (5.1) `here for v.2
    <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988049>`__
    Args:
        api_root (str): the base URL of the API Root
    Returns:
        collections: A Collections Resource upon successful requests. Additional information
        `here <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988050>`__.
    """
    try:
        collections_response = SERVER.get_collections()
    except Exception as e:
        error = f'Could not perform the collections request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'Collections Request Error',
                                                      'description': error})
    return handle_response(HTTP_200_OK, collections_response)


@APP.route('/<api_root>/collections/<collection_id>', methods=['GET'], strict_slashes=False)
@taxii_validate_request_headers
@taxii_validate_url_param
def taxii2_collection_by_id(api_root: str, collection_id: str) -> Response:
    """
    Defines TAXII API - Collections:
    Get Collection section (5.2) `here for v.2.0
    <http://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html#_Toc496542736>`__
    and `here for v.2.1 <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988051>`__
    Args:
        collection_id: the is of the collection, can be obtained using `collection` request.
        api_root (str): the base URL of the API Root
    Returns:
        collections: A Collection Resource with given id upon successful requests.
    """
    try:
        collection_response = SERVER.get_collection_by_id(collection_id)
    except Exception as e:
        error = f'Could not perform the collection request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'Collection Request Error',
                                                      'description': error})
    return handle_response(HTTP_200_OK, collection_response)  # type: ignore[arg-type]


@APP.route('/<api_root>/collections/<collection_id>/manifest', methods=['GET'], strict_slashes=False)
@taxii_validate_request_headers
@taxii_validate_url_param
def taxii2_manifest(api_root: str, collection_id: str) -> Response:
    """
    Defines TAXII API - Manifest Objects:
    Get Manifest section (5.3) `here
    <https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107537>`__
    Args:
        collection_id: collection id to query it objects
        api_root (str): the base URL of the API Root
    Returns:
        manifest: A Manifest Resource upon successful requests. Additional information
        `here <https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107538>`__.
    """
    try:
        created = datetime.now(timezone.utc)
        added_after, offset, limit, types = parse_manifest_and_object_args()

        manifest_response, date_added_first, date_added_last, content_range = SERVER.get_manifest(
            collection_id=collection_id,
            added_after=added_after,
            offset=offset,
            limit=limit,
            types=types,
        )
    except NotImplementedError as e:
        return handle_response(HTTP_404_NOT_FOUND, {'title': 'Manifest Request Error',
                                                    'description': str(e)})
    except RequestedRangeNotSatisfiable as e:
        return handle_response(HTTP_416_RANGE_NOT_SATISFIABLE, {'title': 'Manifest Request Error',
                                                                'description': f'{e}'})
    except Exception as e:
        error = f'Could not perform the manifest request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'Manifest Request Error',
                                                      'description': error})
    query_time = (datetime.now(timezone.utc) - created).total_seconds()
    query_time_str = f"{query_time:.3f}"

    return handle_response(
        status_code=HTTP_200_OK,
        content=manifest_response,
        date_added_first=date_added_first,
        date_added_last=date_added_last,
        content_range=content_range,
        query_time=query_time_str
    )


@APP.route('/<api_root>/collections/<collection_id>/objects', methods=['GET'], strict_slashes=False)
@taxii_validate_request_headers
@taxii_validate_url_param
def taxii2_objects(api_root: str, collection_id: str) -> Response:
    """
    Defines TAXII API - Collections Objects:
    Get Collection section (5.4) `here
    <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988055>`__
    Args:
        collection_id: collection id to query it objects
        api_root (str): the base URL of the API Root
    Returns:
        envelope: A Envelope Resource upon successful requests. Additional information
        `here <https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.html#_Toc532988038>`__.
    """
    try:
        created = datetime.now(timezone.utc)
        added_after, offset, limit, types = parse_manifest_and_object_args()
        demisto.debug(f"T2S: called objects endpoint {collection_id=}")
        objects_response, date_added_first, date_added_last, content_range = SERVER.get_objects(
            collection_id=collection_id,
            added_after=added_after,
            offset=offset,
            limit=limit,
            types=types,
        )
    except NotImplementedError as e:
        return handle_response(HTTP_404_NOT_FOUND, {'title': 'Objects Request Error',
                                                    'description': str(e)})
    except RequestedRangeNotSatisfiable as e:
        return handle_response(HTTP_416_RANGE_NOT_SATISFIABLE, {'title': 'Objects Request Error',
                                                                'description': f'{e}'})
    except Exception as e:
        error = f'Could not perform the objects request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'Objects Request Error',
                                                      'description': error})

    query_time = (datetime.now(timezone.utc) - created).total_seconds()
    query_time_str = f"{query_time:.3f}"

    return handle_response(
        status_code=HTTP_200_OK,
        content=objects_response,
        date_added_first=date_added_first,
        date_added_last=date_added_last,
        content_type=MEDIA_TYPE_STIX_V20 if SERVER.version == TAXII_VER_2_0 else MEDIA_TYPE_TAXII_V21,
        content_range=content_range,
        query_time=query_time_str
    )


def test_module(params: dict) -> str:
    """
    Integration test module.
    """
    if not params.get('longRunningPort'):
        params['longRunningPort'] = '1111'
    run_long_running(params, is_test=True)
    return 'ok'


def edit_server_info(server_info: dict) -> dict:
    """Edits the server info dictionary if the server version >= 8.0.0

    Args:
        server_info (dict): The server info
    """
    if is_demisto_version_ge('8.0.0'):
        altered_api_roots = []
        for api_root in server_info.get('api_roots', []):
            altered_api_roots.append(alter_url(api_root))
        server_info['api_roots'] = altered_api_roots
        server_info['default'] = alter_url(server_info['default'])

    return server_info


def alter_url(url: str) -> str:
    """Alters the URL's netloc with the "ext-" prefix, and the path with the "/xsoar" path.

    Args:
        url (str): The URL to alter.
    """
    parsed_url = urlparse(url)
    new_netloc = "ext-" + parsed_url.netloc
    new_path = '/xsoar' + parsed_url.path
    new_url = f'{parsed_url.scheme}://{new_netloc}{new_path}'

    return new_url


def get_server_info_command(integration_context):
    server_info = integration_context.get('server_info', None)

    server_info = edit_server_info(server_info)
    metadata = '**In case the default/api_roots URL is incorrect, you can override it by setting' \
               '"TAXII2 Service URL Address" field in the integration configuration**\n\n'
    hr = tableToMarkdown('Server Info', server_info, metadata=metadata)

    result = CommandResults(
        outputs=server_info,
        outputs_prefix='TAXIIServer.ServerInfo',
        readable_output=hr
    )

    return result


def get_server_collections_command(integration_context):
    collections = integration_context.get('collections', None)
    markdown = tableToMarkdown('Collections', collections, headers=['id', 'title', 'query', 'description'])
    result = CommandResults(
        outputs=collections,
        outputs_prefix='TAXIIServer.Collection',
        outputs_key_field='id',
        readable_output=markdown
    )

    return result


def main():  # pragma: no cover
    """
    Main
    """
    global SERVER

    params = demisto.params()
    command = demisto.command()

    fields_to_present = create_fields_list(params.get('fields_filter', ''))
    types_for_indicator_sdo = argToList(params.get('provide_as_indicator'))

    collections = get_collections(params)
    version = params.get('version')
    credentials = params.get('credentials', {})

    server_links = demisto.demistoUrls()
    server_link_parts: ParseResult = urlparse(server_links.get('server'))
    host_name = server_link_parts.hostname

    service_address = params.get('service_address')

    certificate = params.get('certificate', '')
    private_key = params.get('key', '')

    if (certificate and not private_key) or (private_key and not certificate):
        raise ValueError('When using HTTPS connection, both certificate and private key must be provided.')

    http_server = not (certificate and private_key)  # False if (certificate and private_key) else True

    scheme = 'https' if not http_server else 'http'

    demisto.debug(f'Command being called is {command}')

    try:
        if command == 'test-module':
            return_results(test_module(params))
        try:
            port = int(params.get('longRunningPort', ''))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')

        SERVER = TAXII2Server(scheme, str(host_name), port, collections, certificate,
                              private_key, http_server, credentials, version, service_address, fields_to_present,
                              types_for_indicator_sdo)

        if command == 'long-running-execution':
            # save TAXII server info in the integration context to make it available later for other commands
            integration_context = get_integration_context(True)
            integration_context['collections'] = SERVER.get_collections().get('collections', [])
            integration_context['server_info'] = SERVER.get_discovery_service(instance_execute=True)

            set_integration_context(integration_context)

            run_long_running(params)

        elif command == 'taxii-server-list-collections':
            integration_context = get_integration_context(True)
            return_results(get_server_collections_command(integration_context))

        elif command == 'taxii-server-info':
            integration_context = get_integration_context(True)
            return_results(get_server_info_command(integration_context))

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


from TAXII2ApiModule import *  # noqa: E402
from NGINXApiModule import *  # noqa: E402

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
