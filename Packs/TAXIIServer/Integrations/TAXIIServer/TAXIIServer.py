import demistomock as demisto
from CommonServerPython import *
from flask import Flask, request, make_response, Response, stream_with_context
from gevent.pywsgi import WSGIServer
from urllib.parse import urlparse, ParseResult
from tempfile import NamedTemporaryFile
from base64 import b64decode
from collections.abc import Callable, Generator
from ssl import SSLContext, SSLError, PROTOCOL_TLSv1_2
from multiprocessing import Process
from werkzeug.datastructures import Headers

from libtaxii.messages_11 import (
    TAXIIMessage,
    DiscoveryRequest,
    DiscoveryResponse,
    CollectionInformationRequest,
    CollectionInformation,
    CollectionInformationResponse,
    PollRequest,
    PollingServiceInstance,
    ServiceInstance,
    ContentBlock,
    generate_message_id,
    get_message_from_xml)
from libtaxii.constants import (
    MSG_COLLECTION_INFORMATION_REQUEST,
    MSG_DISCOVERY_REQUEST,
    MSG_POLL_REQUEST,
    SVC_DISCOVERY,
    SVC_COLLECTION_MANAGEMENT,
    SVC_POLL,
    CB_STIX_XML_11
)
from cybox.core import Observable
from requests.utils import requote_uri

import functools
import stix.core
import stix.indicator
import stix.extensions.marking.ais
import stix.data_marking
import stix.extensions.marking.tlp
import cybox.objects.address_object
import cybox.objects.domain_name_object
import cybox.objects.uri_object
import cybox.objects.file_object
import mixbox.idgen
import mixbox.namespaces
import netaddr
import uuid
import werkzeug.urls
import pytz


''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'TAXII Server'
PAGE_SIZE = 200
APP: Flask = Flask('demisto-taxii')
NAMESPACE_URI = 'https://www.paloaltonetworks.com/cortex'
NAMESPACE = 'cortex'


''' Log Handler '''


class Handler:
    @staticmethod
    def write(message):
        """
        Writes a log message to the Demisto server.
        Args:
            message: The log message to write

        """
        demisto.info(message)


''' TAXII Server '''


class TAXIIServer:
    def __init__(self, url_scheme: str, host: str, port: int, collections: dict, certificate: str, private_key: str,
                 http_server: bool, credentials: dict, service_address: Optional[str] = None):
        """
        Class for a TAXII Server configuration.
        Args:
            url_scheme: The URL scheme (http / https)
            host: The server address.
            port: The server port.
            collections: The JSON string of collections of indicator queries.
            certificate: The server certificate for SSL.
            private_key: The private key for SSL.
            http_server: Whether to use HTTP server (not SSL).
            credentials: The user credentials.
        """
        self.url_scheme = url_scheme
        self.host = host
        self.port = port
        self.collections = collections
        self.certificate = certificate
        self.private_key = private_key
        self.http_server = http_server
        self.service_address = service_address
        self.auth = None
        if credentials:
            self.auth = (credentials.get('identifier', ''), credentials.get('password', ''))

        self.service_instances = [
            {
                'type': SVC_DISCOVERY,
                'path': 'taxii-discovery-service'
            },
            {
                'type': SVC_COLLECTION_MANAGEMENT,
                'path': 'taxii-collection-management-service'
            },
            {
                'type': SVC_POLL,
                'path': 'taxii-poll-service'
            }
        ]

    def get_discovery_service(self, taxii_message: DiscoveryRequest, request_headers: Headers) -> DiscoveryResponse:
        """
        Handle discovery request.
        Args:
            taxii_message: The discovery request message.
            request_headers: The request headers

        Returns:
            The discovery response.
        """
        demisto.debug(f"TS1: The request_headers are {request_headers.to_wsgi_list()}")
        if taxii_message.message_type != MSG_DISCOVERY_REQUEST:
            raise ValueError(f'Invalid message, invalid Message Type is {taxii_message.message_type}')

        discovery_service_url = self.get_url(request_headers)
        discovery_response = DiscoveryResponse(
            generate_message_id(),
            taxii_message.message_id
        )

        for instance in self.service_instances:
            instance_type = instance['type']
            instance_path = instance['path']
            taxii_service_instance = ServiceInstance(
                instance_type,
                'urn:taxii.mitre.org:services:1.1',
                'urn:taxii.mitre.org:protocol:http:1.0',
                f'{discovery_service_url}/{instance_path}',
                ['urn:taxii.mitre.org:message:xml:1.1'],
                available=True
            )
            discovery_response.service_instances.append(taxii_service_instance)

        return discovery_response

    def get_collections(self,
                        taxii_message: CollectionInformationRequest,
                        request_headers: Headers,
                        ) -> CollectionInformationResponse:
        """
        Handle collection management request.
        Args:
            taxii_message: The collection request message.
            request_headers: The request headers

        Returns:
            The collection management response.
        """
        taxii_feeds = list(self.collections.keys())
        url = self.get_url(request_headers)

        if taxii_message.message_type != MSG_COLLECTION_INFORMATION_REQUEST:
            raise ValueError(f'Invalid message, invalid Message Type is {taxii_message.message_type}')

        collection_info_response = CollectionInformationResponse(
            generate_message_id(),
            taxii_message.message_id
        )

        for feed in taxii_feeds:
            collection_info = CollectionInformation(
                feed,
                f'{feed} Data Feed',
                ['urn:stix.mitre.org:xml:1.1.1'],
                True
            )
            polling_instance = PollingServiceInstance(
                'urn:taxii.mitre.org:protocol:http:1.0',
                f'{url}/taxii-poll-service',
                ['urn:taxii.mitre.org:message:xml:1.1']
            )
            collection_info.polling_service_instances.append(polling_instance)
            collection_info_response.collection_informations.append(collection_info)

        return collection_info_response

    def get_poll_response(self, taxii_message: PollRequest) -> Response:
        """
        Handle poll request.
        Args:
            taxii_message: The poll request message.

        Returns:
            The poll response.
        """
        if taxii_message.message_type != MSG_POLL_REQUEST:
            raise ValueError(f'Invalid message, invalid Message Type is {taxii_message.message_type}')

        taxii_feeds = list(self.collections.keys())
        collection_name = taxii_message.collection_name
        exclusive_begin_time = taxii_message.exclusive_begin_timestamp_label
        inclusive_end_time = taxii_message.inclusive_end_timestamp_label

        return self.stream_stix_data_feed(taxii_feeds, taxii_message.message_id, collection_name,
                                          exclusive_begin_time, inclusive_end_time)

    def stream_stix_data_feed(self, taxii_feeds: list, message_id: str, collection_name: str,
                              exclusive_begin_time: datetime, inclusive_end_time: datetime) -> Response:
        """
        Get the indicator query results in STIX data feed format.
        Args:
            taxii_feeds: The available taxii feeds according to the collections.
            message_id: The taxii message ID.
            collection_name: The collection name to get the indicator query from.
            exclusive_begin_time: The query exclusive begin time.
            inclusive_end_time: The query inclusive end time.

        Returns:
            Stream of STIX indicator data feed.
        """
        if collection_name not in taxii_feeds:
            raise ValueError('Invalid message, unknown feed')

        if not inclusive_end_time:
            inclusive_end_time = datetime.utcnow().replace(tzinfo=pytz.utc)

        def yield_response() -> Generator:
            """

            Streams the STIX indicators as XML string.

            """
            # yield the opening tag of the Poll Response
            response = '<taxii_11:Poll_Response xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1"' \
                       ' xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" ' \
                       'xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1"' \
                       f' message_id="{generate_message_id()}"' \
                       f' in_response_to="{message_id}"' \
                       f' collection_name="{collection_name}" more="false" result_part_number="1"> ' \
                       f'<taxii_11:Inclusive_End_Timestamp>{inclusive_end_time.isoformat()}' \
                       '</taxii_11:Inclusive_End_Timestamp>'

            if exclusive_begin_time is not None:
                response += (f'<taxii_11:Exclusive_Begin_Timestamp>{exclusive_begin_time.isoformat()}'
                             f'</taxii_11:Exclusive_Begin_Timestamp>')

            yield response

            # yield the content blocks
            indicator_query = self.collections[str(collection_name)]

            for indicator in find_indicators_by_time_frame(indicator_query, exclusive_begin_time, inclusive_end_time):
                try:
                    stix_xml_indicator = get_stix_indicator(indicator).to_xml(ns_dict={NAMESPACE_URI: NAMESPACE})
                    content_block = ContentBlock(
                        content_binding=CB_STIX_XML_11,
                        content=stix_xml_indicator
                    )

                    content_xml = content_block.to_xml().decode('utf-8')
                    yield f'{content_xml}\n'
                except Exception as e:
                    handle_long_running_error(f'Failed parsing indicator to STIX: {e}')

            # yield the closing tag

            yield '</taxii_11:Poll_Response>'

        return Response(
            response=stream_with_context(yield_response()),
            status=200,
            headers={
                'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
                'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:http:1.0'
            },
            mimetype='application/xml'
        )

    def get_url(self, request_headers: Headers) -> str:
        """
        Args:
            request_headers: The request headers
        Returns:
            The service URL according to the protocol.
        """
        prefix = ''
        xsoar_path = ''
        if self.service_address:
            return self.service_address
        if request_headers and '/instance/execute' in request_headers.get('X-Request-URI', ''):
            # if the server rerouting is used, then the X-Request-URI header is added to the request by the server
            # and we should use the /instance/execute endpoint in the address
            self.url_scheme = 'https'
            calling_context = get_calling_context()
            instance_name = calling_context.get('IntegrationInstance', '')
            endpoint = requote_uri(os.path.join('/instance', 'execute', instance_name))

            if is_xsiam_or_xsoar_saas():
                prefix = 'ext-'
                xsoar_path = '/xsoar'
        else:
            endpoint = f':{self.port}'

        return f'{self.url_scheme}://{prefix}{self.host}{xsoar_path}{endpoint}'


SERVER: TAXIIServer
DEMISTO_LOGGER: Handler = Handler()

''' STIX MAPPING '''


def create_stix_ip_observable(namespace: str, indicator: dict) -> list[Observable]:
    """
    Create STIX IP observable.
    Args:
        namespace: The XML namespace .
        indicator: The Demisto IP indicator.

    Returns:
        STIX IP observable.
    """
    category = cybox.objects.address_object.Address.CAT_IPV4
    type_ = indicator.get('indicator_type', '')
    value = indicator.get('value', '')

    if type_ in [FeedIndicatorType.IPv6, FeedIndicatorType.IPv6CIDR]:
        category = cybox.objects.address_object.Address.CAT_IPV6

    indicator_values = [value]
    if '-' in value:
        # looks like an IP Range, let's try to make it a CIDR
        a1, a2 = value.split('-', 1)
        if a1 == a2:
            # same IP
            indicator_values = [a1]
        else:
            # use netaddr builtin algo to summarize range into CIDR
            iprange = netaddr.IPRange(a1, a2)
            cidrs = iprange.cidrs()
            indicator_values = list(map(str, cidrs))

    observables = []
    for indicator_value in indicator_values:
        id_ = f'{namespace}:observable-{uuid.uuid4()}'
        address_object = cybox.objects.address_object.Address(
            address_value=indicator_value,
            category=category
        )

        observable = Observable(
            title=f'{type_}: {indicator_value}',
            id_=id_,
            item=address_object
        )

        observables.append(observable)

    return observables


def create_stix_email_observable(namespace: str, indicator: dict) -> list[Observable]:
    """
    Create STIX Email observable.
    Args:
        namespace: The XML namespace.
        indicator: The Demisto Email indicator.

    Returns:
        STIX Email observable.
    """
    category = cybox.objects.address_object.Address.CAT_EMAIL
    type_ = indicator.get('indicator_type', '')
    value = indicator.get('value', '')
    id_ = f'{namespace}:observable-{uuid.uuid4()}'

    email_object = cybox.objects.address_object.Address(
        address_value=indicator.get('value', ''),
        category=category
    )

    observable = Observable(
        title=f'{type_}: {value}',
        id_=id_,
        item=email_object
    )

    return [observable]


def create_stix_domain_observable(namespace, indicator):
    """
    Create STIX Domain observable.
    Args:
        namespace: The XML namespace.
        indicator: The Demisto Domain indicator.

    Returns:
        STIX Domain observable.
    """
    id_ = f'{namespace}:observable-{uuid.uuid4()}'
    value = indicator.get('value', '')

    domain_object = cybox.objects.domain_name_object.DomainName()
    domain_object.value = value
    domain_object.type_ = 'FQDN'

    observable = Observable(
        title=f'FQDN: {value}',
        id_=id_,
        item=domain_object
    )

    return [observable]


def create_stix_url_observable(namespace, indicator):
    """
    Create STIX URL observable.
    Args:
        namespace: The XML namespace.
        indicator: The Demisto URL indicator.

    Returns:
        STIX URL observable.
    """
    id_ = f'{namespace}:observable-{uuid.uuid4()}'
    value = indicator.get('value', '')

    uri_object = cybox.objects.uri_object.URI(
        value=value,
        type_=cybox.objects.uri_object.URI.TYPE_URL
    )

    observable = Observable(
        title=f'URL: {value}',
        id_=id_,
        item=uri_object
    )

    return [observable]


def create_stix_hash_observable(namespace, indicator):
    """
    Create STIX file observable.
    Args:
        namespace: The XML namespace.
        indicator: The Demisto File indicator.

    Returns:
        STIX File observable.
    """

    id_ = f'{namespace}:observable-{uuid.uuid4()}'
    value = indicator.get('value', '')
    type_ = indicator.get('indicator_type', '')

    file_object = cybox.objects.file_object.File()
    file_object.add_hash(value)

    observable = Observable(
        title=f'{value}: {type_}',
        id_=id_,
        item=file_object
    )

    return [observable]


TYPE_MAPPING = {
    FeedIndicatorType.IP: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
        'mapper': create_stix_ip_observable
    },
    FeedIndicatorType.CIDR: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
        'mapper': create_stix_ip_observable
    },
    FeedIndicatorType.IPv6: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
        'mapper': create_stix_ip_observable
    },
    FeedIndicatorType.IPv6CIDR: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
        'mapper': create_stix_ip_observable
    },
    FeedIndicatorType.URL: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_URL_WATCHLIST,
        'mapper': create_stix_url_observable
    },
    FeedIndicatorType.Domain: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_DOMAIN_WATCHLIST,
        'mapper': create_stix_domain_observable
    },
    FeedIndicatorType.File: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
        'mapper': create_stix_hash_observable
    },
    FeedIndicatorType.Email: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_MALICIOUS_EMAIL,
        'mapper': create_stix_email_observable
    }
}


def set_id_namespace(uri: str, name: str):
    """
    Set the XML namespace.
    Args:
        uri: The namespace URI.
        name: The namespace name.
    """

    namespace = mixbox.namespaces.Namespace(uri, name)
    mixbox.idgen.set_id_namespace(namespace)


def get_stix_indicator(indicator: dict) -> stix.core.STIXPackage:
    """
    Convert a Demisto indicator to STIX.
    Args:
        indicator: The Demisto indicator.

    Returns:
        The STIX indicator as XML string.
    """
    set_id_namespace(NAMESPACE_URI, NAMESPACE)

    type_ = indicator.get('indicator_type', '')
    type_mapper: dict = TYPE_MAPPING.get(type_, {})

    value = indicator.get('value', '')
    source = indicator.get('sourceBrands', [])
    sources = ','.join(source)

    handling = None

    # Add TLP if available
    share_level = indicator.get('trafficlightprotocol', '').upper()
    if share_level and share_level in ['WHITE', 'GREEN', 'AMBER', 'RED']:
        marking_specification = stix.data_marking.MarkingSpecification()
        marking_specification.controlled_structure = "//node() | //@*"

        tlp = stix.extensions.marking.tlp.TLPMarkingStructure()
        tlp.color = share_level
        marking_specification.marking_structures.append(tlp)

        handling = stix.data_marking.Marking()
        handling.add_marking(marking_specification)

    header = None
    if handling is not None:
        header = stix.core.STIXHeader(
            handling=handling
        )

    # Create the STIX package
    package_id = f'{NAMESPACE}:observable-{uuid.uuid4()}'
    stix_package = stix.core.STIXPackage(id_=package_id, stix_header=header)

    # Get the STIX observables according to the indicator mapper
    observables = type_mapper['mapper'](NAMESPACE, indicator)

    # Create the STIX indicator
    for observable in observables:
        id_ = f'{NAMESPACE}:indicator-{uuid.uuid4()}'

        if type_ == 'URL':
            indicator_value = werkzeug.urls.iri_to_uri(value)
        else:
            indicator_value = value

        stix_indicator = stix.indicator.indicator.Indicator(
            id_=id_,
            title=f'{type_}: {indicator_value}',
            description=f'{type_} indicator from {sources}',
            timestamp=datetime.utcnow().replace(tzinfo=pytz.utc)
        )

        # Confidence is mapped by the indicator score
        confidence = 'Low'
        indicator_score = indicator.get('score')
        if indicator_score is None:
            demisto.error(f'indicator without score: {value}')
            stix_indicator.confidence = "Unknown"
        else:
            score = int(indicator.get('score', 0))
            if score < 2:
                pass
            elif score < 3:
                confidence = 'Medium'
            else:
                confidence = 'High'

        stix_indicator.confidence = confidence

        stix_indicator.add_indicator_type(type_mapper['indicator_type'])

        stix_indicator.add_observable(observable)

        stix_package.add_indicator(stix_indicator)

    return stix_package


''' HELPER FUNCTIONS '''


def get_calling_context():
    return demisto.callingContext.get('context', {})  # type: ignore[attr-defined]


def handle_long_running_error(error: str):
    """
    Handle errors in the long running process.
    Args:
        error: The error message.
    """
    demisto.error(error)
    demisto.updateModuleHealth(error)


def validate_credentials(f: Callable) -> Callable:
    """
    Wrapper function of HTTP requests to validate authentication headers.
    Args:
        f: The wrapped function.

    Returns:
        The function result (if the authentication is valid).
    """
    @functools.wraps(f)
    def validate(*args, **kwargs):
        headers = request.headers
        global SERVER
        if SERVER.auth:
            credentials: str = headers.get('Authorization', '')
            if not credentials or 'Basic ' not in credentials:
                return make_response('Invalid authentication', 401)
            encoded_credentials: str = credentials.split('Basic ')[1]
            credentials: str = b64decode(encoded_credentials).decode('utf-8')
            if ':' not in credentials:
                return make_response('Invalid authentication', 401)
            credentials_list = credentials.split(':')
            if len(credentials_list) != 2:
                return make_response('Invalid authentication', 401)
            username, password = credentials_list

            if not (username == SERVER.auth[0] and password == SERVER.auth[1]):
                return make_response('Invalid authentication', 401)

        return f(*args, **kwargs)

    return validate


def taxii_check(f: Callable) -> Callable:
    """
    Wrapper function of HTTP requests to validate taxii headers.
    Args:
        f: The wrapped function.

    Returns:
        The function result (if the headers are valid).
    """
    @functools.wraps(f)
    def check(*args, **kwargs):
        taxii_content_type = request.headers.get('X-TAXII-Content-Type', None)
        if taxii_content_type not in ['urn:taxii.mitre.org:message:xml:1.1', 'urn:taxii.mitre.org:message:xml:1.0']:
            return make_response('Invalid TAXII Headers', 400)
        taxii_content_type = request.headers.get('X-TAXII-Protocol', None)

        if taxii_content_type not in ['urn:taxii.mitre.org:protocol:http:1.0',
                                      'urn:taxii.mitre.org:protocol:https:1.0']:
            return make_response('Invalid TAXII Headers', 400)

        taxii_content_type = request.headers.get('X-TAXII-Services', None)
        if taxii_content_type not in ['urn:taxii.mitre.org:services:1.1', 'urn:taxii.mitre.org:services:1.0']:
            return make_response('Invalid TAXII Headers', 400)

        return f(*args, **kwargs)

    return check


def get_port(params: dict = demisto.params()) -> int:
    """
    Gets port from the integration parameters.
    """
    if not params.get('longRunningPort'):
        params['longRunningPort'] = '1111'
    try:
        port = int(params.get('longRunningPort', ''))
    except ValueError as e:
        raise ValueError(f'Invalid listen port - {e}')

    return port


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


def find_indicators_by_time_frame(indicator_query: str, begin_time: datetime, end_time: datetime) -> list:
    """
    Find indicators according to a query and begin time/end time.
    Args:
        indicator_query: The indicator query.
        begin_time: The exclusive begin time.
        end_time: The inclusive end time.

    Returns:
        Indicator query results from Demisto.
    """

    if indicator_query:
        indicator_query += ' and '
    else:
        indicator_query = ''

    if begin_time:
        tz_begin_time = datetime.strftime(begin_time, '%Y-%m-%dT%H:%M:%S %z')
        indicator_query += f'sourcetimestamp:>"{tz_begin_time}"'
        if end_time:
            indicator_query += ' and '
    if end_time:
        tz_end_time = datetime.strftime(end_time, '%Y-%m-%dT%H:%M:%S %z')
        indicator_query += f'sourcetimestamp:<="{tz_end_time}"'
    demisto.info(f'Querying indicators by: {indicator_query}')

    return find_indicators_loop(indicator_query)


def find_indicators_loop(indicator_query: str):
    """
    Find indicators in a loop according to a query.
    Args:
        indicator_query: The indicator query.

    Returns:
        Indicator query results from Demisto.
    """
    iocs: list[dict] = []
    search_indicators = IndicatorsSearcher(query=indicator_query, size=PAGE_SIZE)
    for ioc_res in search_indicators:
        fetched_iocs = ioc_res.get('iocs') or []
        iocs.extend(fetched_iocs)

    return iocs


def taxii_make_response(taxii_message: TAXIIMessage):
    """
    Create an HTTP taxii response from a taxii message.
    Args:
        taxii_message: The taxii message.

    Returns:
        A taxii HTTP response.
    """
    headers = {
        'Content-Type': "application/xml",
        'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
        'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:http:1.0'
    }
    response = make_response((taxii_message.to_xml(pretty_print=True), 200, headers))

    return response


''' ROUTE FUNCTIONS '''


@APP.route('/taxii-discovery-service', methods=['POST'])
@taxii_check
@validate_credentials
def taxii_discovery_service() -> Response:
    """
    Route for discovery service.
    """

    try:
        demisto.debug(f"TS1: the taxii_discovery_service data {request.data!r}")
        discovery_response = SERVER.get_discovery_service(get_message_from_xml(request.data), request.headers)
    except Exception as e:
        error = f'Could not perform the discovery request: {str(e)}'
        handle_long_running_error(error)
        return make_response(error, 400)

    return taxii_make_response(discovery_response)


@APP.route('/taxii-collection-management-service', methods=['POST'])
@taxii_check
@validate_credentials
def taxii_collection_management_service() -> Response:
    """
    Route for collection management.
    """

    try:
        demisto.debug(f"TS1: the taxii_collection_management_service data {request.data!r}")
        collection_response = SERVER.get_collections(get_message_from_xml(request.data), request.headers)
    except Exception as e:
        error = f'Could not perform the collection management request: {str(e)}'
        handle_long_running_error(error)
        return make_response(error, 400)

    return taxii_make_response(collection_response)


@APP.route('/taxii-poll-service', methods=['POST'])
@taxii_check
@validate_credentials
def taxii_poll_service() -> Response:
    """
    Route for poll service.
    """

    try:
        taxiicontent_type = request.headers['X-TAXII-Content-Type']
        if taxiicontent_type == 'urn:taxii.mitre.org:message:xml:1.1':
            demisto.debug(f"TS1: the taxii_poll_service data {request.data!r}")
            taxii_message = get_message_from_xml(request.data)
        else:
            raise ValueError('Invalid message')
    except Exception as e:
        error = f'Could not perform the polling request: {str(e)}'
        handle_long_running_error(error)
        return make_response(error, 400)

    return SERVER.get_poll_response(taxii_message)


''' COMMAND FUNCTIONS '''


def test_module(taxii_server: TAXIIServer):
    run_server(taxii_server, is_test=True)
    return 'ok'


def run_server(taxii_server: TAXIIServer, is_test=False):
    """
    Start the taxii server.
    """

    certificate_path = ''
    private_key_path = ''
    ssl_args = {}

    try:

        if taxii_server.certificate and taxii_server.private_key and not taxii_server.http_server:
            certificate_file = NamedTemporaryFile(delete=False)
            certificate_path = certificate_file.name
            certificate_file.write(bytes(taxii_server.certificate, 'utf-8'))
            certificate_file.close()

            private_key_file = NamedTemporaryFile(delete=False)
            private_key_path = private_key_file.name
            private_key_file.write(bytes(taxii_server.private_key, 'utf-8'))
            private_key_file.close()
            context = SSLContext(PROTOCOL_TLSv1_2)
            context.load_cert_chain(certificate_path, private_key_path)
            ssl_args['ssl_context'] = context
            demisto.debug('Starting HTTPS Server')
        else:
            demisto.debug('Starting HTTP Server')

        wsgi_server = WSGIServer(('0.0.0.0', taxii_server.port), APP, **ssl_args, log=DEMISTO_LOGGER)
        if is_test:
            server_process = Process(target=wsgi_server.serve_forever)
            server_process.start()
            time.sleep(5)
            server_process.terminate()
        else:
            demisto.updateModuleHealth('')
            wsgi_server.serve_forever()
    except SSLError as e:
        ssl_err_message = f'Failed to validate certificate and/or private key: {str(e)}'
        handle_long_running_error(ssl_err_message)
        raise ValueError(ssl_err_message)
    except Exception as e:
        handle_long_running_error(f'An error occurred: {str(e)}')
        raise ValueError(str(e))
    finally:
        if certificate_path:
            os.unlink(certificate_path)
        if private_key_path:
            os.unlink(private_key_path)


def main():
    """
    Main
    """
    params = demisto.params()
    command = demisto.command()

    certificate: str = params.get('certificate', '')
    private_key: str = params.get('key', '')
    credentials: dict = params.get('credentials', None)
    http_server = True
    if (certificate and not private_key) or (private_key and not certificate):
        raise ValueError('When using HTTPS connection, both certificate and private key must be provided.')
    elif certificate and private_key:
        http_server = False

    demisto.debug(f'Command being called is {command}')
    commands: dict = {}
    try:
        port = get_port(params)
        collections = get_collections(params)
        server_links = demisto.demistoUrls()
        server_link_parts: ParseResult = urlparse(server_links.get('server'))

        global SERVER
        scheme = 'http'
        host_name = server_link_parts.hostname
        if is_xsiam():
            # Replace the 'xdr' with 'crtx' in the hostname of XSIAM tenants
            # This substitution is related to this platform ticket: https://jira-dc.paloaltonetworks.com/browse/CIAC-12256.
            host_name = str(server_link_parts.hostname).replace('.xdr', '.crtx', 1)
        if not http_server:
            scheme = 'https'

        service_address = params.get('service_address')
        SERVER = TAXIIServer(scheme, str(host_name), port, collections,
                             certificate, private_key, http_server, credentials, service_address)
        if command == 'test-module':
            return_results(test_module(SERVER))
        elif command == 'long-running-execution':
            run_server(SERVER)
        else:
            readable_output, outputs, raw_response = commands[command](SERVER)
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
