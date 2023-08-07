import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import functools
import uuid
import json
from collections.abc import Callable
from flask import Flask, request, make_response, jsonify, Response
from urllib.parse import ParseResult, urlparse
from secrets import compare_digest
from dateutil.parser import parse
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
TAXII_VER_2_0 = '2.0'
TAXII_VER_2_1 = '2.1'
PAWN_UUID = uuid.uuid5(uuid.NAMESPACE_URL, 'https://www.paloaltonetworks.com')
SCO_DET_ID_NAMESPACE = uuid.UUID('00abedb4-aa42-466c-9c01-fed23315a9b7')
STIX_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
UTC_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
TAXII_V20_CONTENT_LEN = 9765625
TAXII_V21_CONTENT_LEN = 104857600
TAXII_REQUIRED_FILTER_FIELDS = {'name', 'type', 'modified', 'createdTime', 'description',
                                'accounttype', 'userid', 'mitreid', 'stixid'}
PAGE_SIZE = 2000

XSOAR_TYPES_TO_STIX_SCO = {
    FeedIndicatorType.CIDR: 'ipv4-addr',
    FeedIndicatorType.DomainGlob: 'domain-name',
    FeedIndicatorType.IPv6: 'ipv6-addr',
    FeedIndicatorType.IPv6CIDR: 'ipv6-addr',
    FeedIndicatorType.Account: 'user-account',
    FeedIndicatorType.Domain: 'domain-name',
    FeedIndicatorType.Email: 'email-addr',
    FeedIndicatorType.IP: 'ipv4-addr',
    FeedIndicatorType.Registry: 'windows-registry-key',
    FeedIndicatorType.File: 'file',
    FeedIndicatorType.URL: 'url',
    FeedIndicatorType.Software: 'software',
    FeedIndicatorType.AS: 'asn',
}

XSOAR_TYPES_TO_STIX_SDO = {
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: 'attack-pattern',
    ThreatIntel.ObjectsNames.CAMPAIGN: 'campaign',
    ThreatIntel.ObjectsNames.COURSE_OF_ACTION: 'course-of-action',
    ThreatIntel.ObjectsNames.INFRASTRUCTURE: 'infrastructure',
    ThreatIntel.ObjectsNames.INTRUSION_SET: 'intrusion-set',
    ThreatIntel.ObjectsNames.REPORT: 'report',
    ThreatIntel.ObjectsNames.THREAT_ACTOR: 'threat-actor',
    ThreatIntel.ObjectsNames.TOOL: 'tool',
    ThreatIntel.ObjectsNames.MALWARE: 'malware',
    FeedIndicatorType.CVE: 'vulnerability',
}

STIX2_TYPES_TO_XSOAR: dict[str, Union[str, tuple[str, ...]]] = {
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
    'ipv4-addr': FeedIndicatorType.IP,
    'ipv6-addr': FeedIndicatorType.IPv6,
    'domain-name': (FeedIndicatorType.DomainGlob, FeedIndicatorType.Domain),
    'user-account': FeedIndicatorType.Account,
    'email-addr': FeedIndicatorType.Email,
    'url': FeedIndicatorType.URL,
    'file': FeedIndicatorType.File,
    'windows-registry-key': FeedIndicatorType.Registry,
    'indicator': (FeedIndicatorType.IP, FeedIndicatorType.IPv6, FeedIndicatorType.DomainGlob,
                  FeedIndicatorType.Domain, FeedIndicatorType.Account, FeedIndicatorType.Email,
                  FeedIndicatorType.URL, FeedIndicatorType.File, FeedIndicatorType.Registry),
    'software': FeedIndicatorType.Software,
    'asn': FeedIndicatorType.AS,
}

HASH_TYPE_TO_STIX_HASH_TYPE = {
    'md5': 'MD5',
    'sha1': 'SHA-1',
    'sha256': 'SHA-256',
    'sha512': 'SHA-512',
}


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
        self._host = host
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
            service_address = f'{self._url_scheme}://{self._host}{endpoint}'
        else:
            endpoint = f':{self._port}'
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

        iocs, extensions, total = find_indicators(
            query=query,
            types=types,
            added_after=added_after,
            limit=limit,
            offset=offset)

        first_added = None
        last_added = None
        limited_extensions = None

        limited_iocs = iocs[offset:offset + limit]
        if iocs and not limited_iocs:
            raise RequestedRangeNotSatisfiable

        objects = limited_iocs

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


def create_query(query: str, types: list[str]) -> str:
    """
    Args:
        query: collections query
        types: indicator types to filter by

    Returns:
        New query with types params
    """
    new_query = ''
    if types:
        demisto.debug(f'raw query: {query}')
        xsoar_types: list = []
        for t in types:
            xsoar_type = STIX2_TYPES_TO_XSOAR.get(t, t)
            xsoar_types.extend(xsoar_type if isinstance(xsoar_type, tuple) else (xsoar_type,))

        if query.strip():
            new_query = f'({query})'

        if or_part := (' or '.join(f'type:"{x}"' for x in xsoar_types)):
            new_query += f' and ({or_part})'

        demisto.debug(f'modified query, after adding types: {new_query}')
        return new_query
    else:
        return query


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
    new_query = create_query(query, types)
    new_limit = offset + limit
    iocs = []
    extensions = []

    if is_manifest:
        field_filters: Optional[str] = ','.join(TAXII_REQUIRED_FILTER_FIELDS)
    elif SERVER.fields_to_present:
        field_filters = ','.join(
            set.union(SERVER.fields_to_present, TAXII_REQUIRED_FILTER_FIELDS))  # type: ignore[arg-type]
    else:
        field_filters = None

    demisto.debug(f'filter fields: {field_filters}')

    indicator_searcher = IndicatorsSearcher(
        filter_fields=field_filters,
        query=new_query,
        limit=new_limit,
        size=PAGE_SIZE,
        from_date=added_after,
        sort=[{"field": "modified", "asc": True}],
    )

    total = 0
    extensions_dict: dict = {}
    for ioc in indicator_searcher:
        found_indicators = ioc.get('iocs') or []
        total = ioc.get('total')
        for xsoar_indicator in found_indicators:
            xsoar_type = xsoar_indicator.get('indicator_type')
            if is_manifest:
                manifest_entry = create_manifest_entry(xsoar_indicator, xsoar_type)
                if manifest_entry:
                    iocs.append(manifest_entry)
            else:
                stix_ioc, extension_definition, extensions_dict = create_stix_object(xsoar_indicator, xsoar_type, extensions_dict)
                if XSOAR_TYPES_TO_STIX_SCO.get(xsoar_type) in SERVER.types_for_indicator_sdo:
                    stix_ioc = convert_sco_to_indicator_sdo(stix_ioc, xsoar_indicator)
                if SERVER.has_extension and stix_ioc:
                    iocs.append(stix_ioc)
                    if extension_definition:
                        extensions.append(extension_definition)
                elif stix_ioc:
                    iocs.append(stix_ioc)
    if not is_manifest and iocs \
            and is_demisto_version_ge('6.6.0') and (relationships := create_relationships_objects(iocs, extensions)):
        total += len(relationships)
        iocs.extend(relationships)
        iocs = sorted(iocs, key=lambda k: k['modified'])
    return iocs, extensions, total


def create_sco_stix_uuid(xsoar_indicator: dict, stix_type: str) -> str:
    """
    Create uuid for sco objects.
    """
    if stixid := xsoar_indicator.get('CustomFields', {}).get('stixid'):
        return stixid
    value = xsoar_indicator.get('value')
    if stix_type == 'user-account':
        account_type = xsoar_indicator.get('CustomFields', {}).get('accounttype')
        user_id = xsoar_indicator.get('CustomFields', {}).get('userid')
        unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE,
                               f'{{"account_login":"{value}","account_type":"{account_type}","user_id":"{user_id}"}}')
    elif stix_type == 'windows-registry-key':
        unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"key":"{value}"}}')
    elif stix_type == 'file':
        if get_hash_type(value) == 'md5':
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"MD5":"{value}"}}}}')
        elif get_hash_type(value) == 'sha1':
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"SHA-1":"{value}"}}}}')
        elif get_hash_type(value) == 'sha256':
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"SHA-256":"{value}"}}}}')
        elif get_hash_type(value) == 'sha512':
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"SHA-512":"{value}"}}}}')
        else:
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"value":"{value}"}}')
    else:
        unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"value":"{value}"}}')

    stix_id = f'{stix_type}--{unique_id}'
    return stix_id


def create_sdo_stix_uuid(xsoar_indicator: dict, stix_type: str) -> str:
    """
    Create uuid for sdo objects.
    """
    if stixid := xsoar_indicator.get('CustomFields', {}).get('stixid'):
        return stixid
    value = xsoar_indicator.get('value')
    if stix_type == 'attack-pattern':
        if mitre_id := xsoar_indicator.get('CustomFields', {}).get('mitreid'):
            unique_id = uuid.uuid5(SERVER.namespace_uuid, f'{stix_type}:{mitre_id}')
        else:
            unique_id = uuid.uuid5(SERVER.namespace_uuid, f'{stix_type}:{value}')
    else:
        unique_id = uuid.uuid5(SERVER.namespace_uuid, f'{stix_type}:{value}')

    stix_id = f'{stix_type}--{unique_id}'
    return stix_id


def create_manifest_entry(xsoar_indicator: dict, xsoar_type: str) -> dict:
    """

    Args:
        xsoar_indicator: to create manifest entry from
        xsoar_type: type of indicator in xsoar system

    Returns:
        manifest entry for given indicator.
    """
    if stix_type := XSOAR_TYPES_TO_STIX_SCO.get(xsoar_type):
        stix_id = create_sco_stix_uuid(xsoar_indicator, stix_type)
    elif stix_type := XSOAR_TYPES_TO_STIX_SDO.get(xsoar_type):
        stix_id = create_sdo_stix_uuid(xsoar_indicator, stix_type)
    else:
        demisto.debug(f'No such indicator type: {xsoar_type} in stix format.')
        return {}
    entry = {
        'id': stix_id,
        'date_added': parse(xsoar_indicator.get('timestamp')).strftime(STIX_DATE_FORMAT),  # type: ignore[arg-type]
    }
    if SERVER.version == TAXII_VER_2_1:
        entry['version'] = parse(xsoar_indicator.get('modified')).strftime(STIX_DATE_FORMAT)  # type: ignore[arg-type]
    return entry


def convert_sco_to_indicator_sdo(stix_object: dict, xsoar_indicator: dict) -> dict:
    """
    Create a STIX domain object of 'indicator' type from a STIX Cyber Observable Objects.

    Args:
        stix_object: The STIX Cyber Observable Object
        xsoar_indicator: The stix object entry from which the 'stix_object' has been created.

    Returns:
        Stix indicator domain object for given indicator. Format described here:
        https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_muftrcpnf89v
    """
    try:
        expiration_parsed = parse(xsoar_indicator.get('expiration')).strftime(STIX_DATE_FORMAT)  # type: ignore[arg-type]
    except Exception:
        expiration_parsed = ''

    indicator_value = xsoar_indicator.get('value')
    if isinstance(indicator_value, str):
        indicator_pattern_value: Any = indicator_value.replace("'", "\\'")
    else:
        indicator_pattern_value = json.dumps(indicator_value)

    object_type = stix_object['type']
    stix_type = 'indicator'

    pattern = ''
    if object_type == 'file':
        hash_type = HASH_TYPE_TO_STIX_HASH_TYPE.get(get_hash_type(indicator_value), 'Unknown')
        pattern = f"[file:hashes.'{hash_type}' = '{indicator_pattern_value}']"
    else:
        pattern = f"[{object_type}:value = '{indicator_pattern_value}']"

    labels = get_labels_for_indicator(xsoar_indicator.get('score'))

    stix_domain_object: Dict[str, Any] = assign_params(
        type=stix_type,
        id=create_sdo_stix_uuid(xsoar_indicator, stix_type),
        pattern=pattern,
        valid_from=stix_object['created'],
        valid_until=expiration_parsed,
        description=xsoar_indicator.get('CustomFields', {}).get('description', ''),
        pattern_type='stix',
        labels=labels
    )
    return dict({k: v for k, v in stix_object.items()
                 if k in ('spec_version', 'created', 'modified')}, **stix_domain_object)


def get_labels_for_indicator(score):
    """Get indicator label based on the DBot score"""
    if int(score) == 0:
        return ['']
    elif int(score) == 1:
        return ['benign']
    elif int(score) == 2:
        return ['anomalous-activity']
    elif int(score) == 3:
        return ['malicious-activity']
    return None


def create_stix_object(xsoar_indicator: dict, xsoar_type: str, extensions_dict: dict = {}) -> tuple:
    """

    Args:
        xsoar_indicator: to create stix object entry from
        xsoar_type: type of indicator in xsoar system
        extensions_dict: dict contains all object types that already have their extension defined
    Returns:
        Stix object entry for given indicator, and extension. Format described here:
        (https://docs.google.com/document/d/1wE2JibMyPap9Lm5-ABjAZ02g098KIxlNQ7lMMFkQq44/edit#heading=h.naoy41lsrgt0)
        extensions_dict: dict contains all object types that already have their extension defined
    """
    is_sdo = False
    if stix_type := XSOAR_TYPES_TO_STIX_SCO.get(xsoar_type):
        stix_id = create_sco_stix_uuid(xsoar_indicator, stix_type)
        object_type = stix_type
    elif stix_type := XSOAR_TYPES_TO_STIX_SDO.get(xsoar_type):
        stix_id = create_sdo_stix_uuid(xsoar_indicator, stix_type)
        object_type = stix_type
        is_sdo = True
    else:
        demisto.debug(f'No such indicator type: {xsoar_type} in stix format.')
        return {}, {}

    created_parsed = parse(xsoar_indicator.get('timestamp')).strftime(STIX_DATE_FORMAT)  # type: ignore[arg-type]

    try:
        modified_parsed = parse(xsoar_indicator.get('modified')).strftime(STIX_DATE_FORMAT)  # type: ignore[arg-type]
    except Exception:
        modified_parsed = ''

    stix_object: Dict[str, Any] = {
        'id': stix_id,
        'type': object_type,
        'spec_version': SERVER.version,
        'created': created_parsed,
        'modified': modified_parsed,
    }
    if xsoar_type == ThreatIntel.ObjectsNames.REPORT:
        stix_object['object_refs'] = []
    if is_sdo:
        stix_object['name'] = xsoar_indicator.get('value')
    else:
        stix_object = build_sco_object(stix_object, xsoar_indicator)

    xsoar_indicator_to_return = {}

    # filter only requested fields
    if SERVER.has_extension and SERVER.fields_to_present:
        # if Server fields_to_present is None - no filters, return all. If Existing fields - filter
        for field in SERVER.fields_to_present:
            value = xsoar_indicator.get(field)
            if not value:
                value = xsoar_indicator.get('CustomFields', {}).get(field)
            xsoar_indicator_to_return[field] = value
    else:
        xsoar_indicator_to_return = xsoar_indicator
    extension_definition = {}

    if SERVER.has_extension and object_type not in SERVER.types_for_indicator_sdo:
        stix_object, extension_definition, extensions_dict = create_extension_definition(object_type, extensions_dict, xsoar_type,
                                                                                         created_parsed, modified_parsed,
                                                                                         stix_object, xsoar_indicator_to_return)

    if is_sdo:
        stix_object['description'] = xsoar_indicator.get('CustomFields', {}).get('description', "")
    return stix_object, extension_definition, extensions_dict


def build_sco_object(stix_object: Dict[str, Any], xsoar_indicator: Dict[str, Any]) -> Dict[str, Any]:
    """
    Builds a correct JSON object for specific SCO types

    Args:
        stix_object (Dict[str, Any]): A JSON object of a STIX indicator
        xsoar_indicator (Dict[str, Any]): A JSON object of an XSOAR indicator

    Returns:
        Dict[str, Any]: A JSON object of a STIX indicator
    """

    custom_fields = xsoar_indicator.get('CustomFields', {})

    if stix_object['type'] == 'asn':
        stix_object['number'] = xsoar_indicator.get('value', '')
        stix_object['name'] = custom_fields.get('name', '')

    elif stix_object['type'] == 'file':
        value = xsoar_indicator.get('value')
        stix_object['hashes'] = {HASH_TYPE_TO_STIX_HASH_TYPE[get_hash_type(value)]: value}
        for hash_type in ('md5', 'sha1', 'sha256', 'sha512'):
            try:
                stix_object['hashes'][HASH_TYPE_TO_STIX_HASH_TYPE[hash_type]] = custom_fields[hash_type]

            except KeyError:
                pass

    elif stix_object['type'] == 'windows-registry-key':
        stix_object['key'] = xsoar_indicator.get('value')
        stix_object['values'] = []

        for keyvalue in custom_fields['keyvalue']:
            if keyvalue:
                stix_object['values'].append(keyvalue)
                stix_object['values'][-1]['data_type'] = stix_object['values'][-1]['type']
                del stix_object['values'][-1]['type']
            else:
                pass

    elif stix_object['type'] in ('mutex', 'software'):
        stix_object['name'] = xsoar_indicator.get('value')

    else:
        stix_object['value'] = xsoar_indicator.get('value')

    return stix_object


def create_extension_definition(object_type, extensions_dict, xsoar_type,
                                created_parsed, modified_parsed, stix_object, xsoar_indicator_to_return):
    """
    Args:
        object_type: the type of the stix_object.
        xsoar_type: type of indicator in xsoar system.
        extensions_dict: dict contains all object types that already have their extension defined.
        created_parsed: the stix object creation time.
        modified_parsed: the stix object last modified time.
        stix_object: Stix object entry.
        xsoar_indicator_to_return: the xsoar indicator to return.

    Create an extension definition and update the stix object and extensions dict accordingly.

    Returns:
        the updated Stix object, its extension and updated extensions_dict.
    """
    extension_definition = {}
    xsoar_indicator_to_return['extension_type'] = 'property_extension'
    extension_id = f'extension-definition--{uuid.uuid4()}'
    if object_type not in extensions_dict:
        extension_definition = {
            'id': extension_id,
            'type': 'extension-definition',
            'spec_version': SERVER.version,
            'name': f'Cortex XSOAR TIM {xsoar_type}',
            'description': 'This schema adds TIM data to the object',
            'created': created_parsed,
            'modified': modified_parsed,
            'created_by_ref': f'identity--{str(PAWN_UUID)}',
            'schema':
                'https://github.com/demisto/content/blob/4265bd5c71913cd9d9ed47d9c37d0d4d3141c3eb/'
                'Packs/TAXIIServer/doc_files/XSOAR_indicator_schema.json',
            'version': '1.0',
            'extension_types': ['property-extension']
        }
        extensions_dict[object_type] = True
    stix_object['extensions'] = {
        extension_id: xsoar_indicator_to_return
    }
    return stix_object, extension_definition, extensions_dict


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
    run_long_running(params, is_test=True)
    return 'ok'


def get_server_info_command(integration_context):
    server_info = integration_context.get('server_info', None)

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


def create_relationships_objects(stix_iocs: list[dict[str, Any]], extensions: list) -> list[dict[str, Any]]:
    """
    Create entries for the relationships returned by the searchRelationships command.
    :param stix_iocs: Entries for the Stix objects associated with given indicators
    :param extensions: A list of dictionaries representing extension properties to include in the generated STIX objects.
    :return: A list of dictionaries representing the relationships objects, including entityBs objects
    """
    def get_stix_object_value(stix_ioc):
        if stix_ioc.get('type') == "file":
            for hash_type in ["SHA-256", "MD5", "SHA-1", "SHA-512"]:
                if hash_value := stix_ioc.get("hashes").get(hash_type):
                    return hash_value
            return None

        else:
            return stix_ioc.get('value') or stix_ioc.get('name')

    relationships_list: list[dict[str, Any]] = []
    iocs_value_to_id = {get_stix_object_value(stix_ioc): stix_ioc.get('id') for stix_ioc in stix_iocs}
    search_relationships = demisto.searchRelationships({'entities': list(iocs_value_to_id.keys())}).get('data') or []
    demisto.debug(f"Found {len(search_relationships)} relationships for {len(iocs_value_to_id)} Stix IOC values.")

    relationships_list.extend(create_entity_b_stix_objects(search_relationships, iocs_value_to_id, extensions))

    for relationship in search_relationships:

        if demisto.get(relationship, 'CustomFields.revoked'):
            continue

        if not iocs_value_to_id.get(relationship.get('entityB')):
            demisto.debug(f"WARNING: Invalid entity B - Relationships will not be created to entity A:"
                          f" {relationship.get('entityA')} with relationship name {relationship.get('name')}")
            continue
        try:
            created_parsed = parse(relationship.get('createdInSystem')).strftime(STIX_DATE_FORMAT)
            modified_parsed = parse(relationship.get('modified')).strftime(STIX_DATE_FORMAT)
        except Exception as e:
            created_parsed, modified_parsed = '', ''
            demisto.debug(f"Error parsing dates for relationship {relationship.get('id')}: {e}")

        relationship_unique_id = uuid.uuid5(SERVER.namespace_uuid, f'relationship:{relationship.get("id")}')
        relationship_stix_id = f'relationship--{relationship_unique_id}'

        relationship_object: dict[str, Any] = {
            'type': "relationship",
            'spec_version': SERVER.version,
            'id': relationship_stix_id,
            'created': created_parsed,
            'modified': modified_parsed,
            "relationship_type": relationship.get('name'),
            'source_ref': iocs_value_to_id.get(relationship.get('entityA')),
            'target_ref': iocs_value_to_id.get(relationship.get('entityB')),
        }
        if description := demisto.get(relationship, 'CustomFields.description'):
            relationship_object['Description'] = description

        relationships_list.append(relationship_object)
    handle_report_relationships(relationships_list, stix_iocs)
    return relationships_list


def handle_report_relationships(relationships: list[dict[str, Any]], stix_iocs: list[dict[str, Any]]):
    """Handle specific behavior of report relationships.

    Args:
        relationships (list[dict[str, Any]]): the created relationships list.
        stix_iocs (list[dict[str, Any]]): the ioc objects.
    """
    id_to_report_objects = {
        stix_ioc.get('id'): stix_ioc
        for stix_ioc in stix_iocs
        if stix_ioc.get('type') == 'report'}

    for relationship in relationships:
        if source_report := id_to_report_objects.get(relationship.get('source_ref')):
            object_refs = source_report.get('object_refs', [])
            object_refs.extend(
                [relationship.get('target_ref'), relationship.get('id')]
            )
            source_report['object_refs'] = sorted(object_refs)
        if target_report := id_to_report_objects.get(relationship.get('target_ref')):
            object_refs = target_report.get('object_refs', [])
            object_refs.extend(
                [relationship.get('source_ref'), relationship.get('id')]
            )
            target_report['object_refs'] = sorted(object_refs)


def create_entity_b_stix_objects(relationships: list[dict[str, Any]], iocs_value_to_id: dict, extensions: list) -> list:
    """
    Generates a list of STIX objects for the 'entityB' values in the provided 'relationships' list.
    :param relationships: A list of dictionaries representing relationships between entities
    :param iocs_value_to_id: A dictionary mapping IOC values to their corresponding ID values.
    :param extensions: A list of dictionaries representing extension properties to include in the generated STIX objects.
    :return: A list of dictionaries representing STIX objects for the 'entityB' values
    """
    entity_b_objects: list[dict[str, Any]] = []
    entity_b_values = ""
    for relationship in relationships:
        if (entity_b_value := relationship.get('entityB')) and entity_b_value not in iocs_value_to_id:
            iocs_value_to_id[entity_b_value] = ""
            entity_b_values += f'\"{entity_b_value}\" '
    if not entity_b_values:
        return entity_b_objects

    found_indicators = demisto.searchIndicators(query=f'value:({entity_b_values})').get('iocs') or []

    extensions_dict: dict = {}
    for xsoar_indicator in found_indicators:
        xsoar_type = xsoar_indicator.get('indicator_type')
        stix_ioc, extension_definition, extensions_dict = create_stix_object(xsoar_indicator, xsoar_type, extensions_dict)
        if XSOAR_TYPES_TO_STIX_SCO.get(xsoar_type) in SERVER.types_for_indicator_sdo:
            stix_ioc = convert_sco_to_indicator_sdo(stix_ioc, xsoar_indicator)
        if SERVER.has_extension and stix_ioc:
            entity_b_objects.append(stix_ioc)
            if extension_definition:
                extensions.append(extension_definition)
        elif stix_ioc:
            entity_b_objects.append(stix_ioc)
        iocs_value_to_id[(stix_ioc.get('value') or stix_ioc.get('name'))] = stix_ioc.get('id')

    demisto.debug(f"Generated {len(entity_b_objects)} STIX objects for 'entityB' values.")
    return entity_b_objects


def main():  # pragma: no cover
    """
    Main
    """
    global SERVER

    params = demisto.params()
    command = demisto.command()

    fields_to_present = create_fields_list(params.get('fields_filter', ''))
    types_for_indicator_sdo = argToList(params.get('provide_as_indicator'))

    try:
        port = int(params.get('longRunningPort'))
    except ValueError as e:
        raise ValueError(f'Invalid listen port - {e}')

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

        elif command == 'test-module':
            return_results(test_module(params))

        elif command == 'taxii-server-list-collections':
            integration_context = get_integration_context(True)
            return_results(get_server_collections_command(integration_context))

        elif command == 'taxii-server-info':
            integration_context = get_integration_context(True)
            return_results(get_server_info_command(integration_context))

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


from NGINXApiModule import *  # noqa: E402

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
