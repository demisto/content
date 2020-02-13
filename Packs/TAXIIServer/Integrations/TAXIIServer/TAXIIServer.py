import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from flask import Flask, request, make_response, Response, stream_with_context
from gevent.pywsgi import WSGIServer
from urllib.parse import urlparse, ParseResult
from tempfile import NamedTemporaryFile
from typing import Generator, List, Any

import functools
import libtaxii
import libtaxii.messages_11
import libtaxii.constants
import stix.core
import cybox
import mixbox.idgen
import mixbox.namespaces
import netaddr
import uuid
import werkzeug.urls
import pytz


''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'TAXII Server'
PAGE_SIZE = 100
APP: Flask = Flask('demisto-taxii')
NAMESPACE_URI = 'https://www.paloaltonetworks.com/cortex'
NAMESPACE = 'cortex'


''' TAXII Server '''


class TAXIIServer:
    def __init__(self, host, port, collections, certificate, private_key, http_server):
        self.host = host
        self.port = port
        self.collections = collections
        self.certificate = certificate
        self.private_key = private_key
        self.http_server = http_server

        self.service_instances = [
            {
                'type': libtaxii.constants.SVC_DISCOVERY,
                'path': 'taxii-discovery-service'
            },
            {
                'type': libtaxii.constants.SVC_COLLECTION_MANAGEMENT,
                'path': 'taxii-collection-management-service'
            },
            {
                'type': libtaxii.constants.SVC_POLL,
                'path': 'taxii-poll-service'
            }
        ]

    def get_discovery_service(self, taxii_message) -> libtaxii.messages_11.DiscoveryResponse:
        discovery_service_url = f'{self.host}:{self.port}'

        if taxii_message.message_type != libtaxii.constants.MSG_DISCOVERY_REQUEST:
            raise ValueError('Invalid message, invalid Message Type')

        discovery_response = libtaxii.messages_11.DiscoveryResponse(
            libtaxii.messages_11.generate_message_id(),
            taxii_message.message_id
        )

        for instance in self.service_instances:
            taxii_service_instance = libtaxii.messages_11.ServiceInstance(
                instance['type'],
                'urn:taxii.mitre.org:services:1.1',
                'urn:taxii.mitre.org:protocol:http:1.0',
                "{}/{}".format(discovery_service_url, instance['path']),
                ['urn:taxii.mitre.org:message:xml:1.1'],
                available=True
            )
            discovery_response.service_instances.append(taxii_service_instance)

        return discovery_response

    def get_collections(self, taxii_message) -> libtaxii.messages_11.CollectionInformationResponse:
        taxii_feeds = [name for name, query in self.collections.items()]

        if taxii_message.message_type != \
                libtaxii.constants.MSG_COLLECTION_INFORMATION_REQUEST:
            raise ValueError('Invalid message, invalid Message Type')

        collection_info_response = libtaxii.messages_11.CollectionInformationResponse(
            libtaxii.messages_11.generate_message_id(),
            taxii_message.message_id
        )

        for feed in taxii_feeds:
            collection_info = libtaxii.messages_11.CollectionInformation(
                feed,
                '{} Data Feed'.format(feed),
                ['urn:stix.mitre.org:xml:1.1.1'],
                True
            )
            polling_instance = libtaxii.messages_11.PollingServiceInstance(
                'urn:taxii.mitre.org:protocol:http:1.0',
                '{}:{}/taxii-poll-service'.format(self.host, self.port),
                ['urn:taxii.mitre.org:message:xml:1.1']
            )
            collection_info.polling_service_instances.append(polling_instance)
            collection_info_response.collection_informations.append(collection_info)

        return collection_info_response

    def get_poll_response(self, taxii_message):
        if taxii_message.message_type != libtaxii.constants.MSG_POLL_REQUEST:
            raise ValueError('Invalid message')

        taxii_feeds = [name for name, query in self.collections.items()]
        collection_name = taxii_message.collection_name
        exclusive_begin_time = taxii_message.exclusive_begin_timestamp_label
        inclusive_end_time = taxii_message.inclusive_end_timestamp_label

        return self.get_data_feed(taxii_feeds, taxii_message.message_id, collection_name,
                                  exclusive_begin_time, inclusive_end_time)

    @staticmethod
    def get_data_feed(taxii_feeds, message_id, collection_name, exclusive_begin_time, inclusive_end_time) -> Generator:
        if collection_name not in taxii_feeds:
            raise ValueError('Invalid message, unknown feed')

        if not inclusive_end_time:
            inclusive_end_time = datetime.utcnow().replace(tzinfo=pytz.utc)

        def _resp_generator():
            # yield the opening tag of the Poll Response
            resp_header = '<taxii_11:Poll_Response xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1"' \
                          ' xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" ' \
                          'xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1"' \
                          f' message_id="{libtaxii.messages_11.generate_message_id()}"' \
                          f' in_response_to="{message_id}"' \
                          f' collection_name="{collection_name}" more="false" result_part_number="1"> ' \
                          f'<taxii_11:Inclusive_End_Timestamp>{inclusive_end_time.isoformat()}' \
                          '</taxii_11:Inclusive_End_Timestamp>'

            if exclusive_begin_time is not None:
                resp_header += (
                        '<taxii_11:Exclusive_Begin_Timestamp>' +
                        exclusive_begin_time.isoformat() +
                        '</taxii_11:Exclusive_Begin_Timestamp>'
                )

            yield resp_header

            # yield the content blocks
            indicator_query = taxii_feeds[collection_name]
            for indicator in find_indicators_by_time_frame(indicator_query, exclusive_begin_time, inclusive_end_time):
                json_stix = get_stix_indicator(indicator)
                stix_indicator = stix.core.STIXPackage.from_json(json_stix)
                cb1 = libtaxii.messages_11.ContentBlock(
                    content_binding=libtaxii.constants.CBstix_XML_11,
                    content=stix_indicator
                )
                yield cb1.to_xml() + '\n'

            # yield the closing tag
            yield '</taxii_11:Poll_Response>'

        return _resp_generator()


SERVER: TAXIIServer

''' STIX MAPPING '''


def stix_ip_observable(namespace, indicator, value):
    category = cybox.objects.address_object.Address.CAT_IPV4
    if value['type'] == 'IPv6':
        category = cybox.objects.address_object.Address.CAT_IPV6

    indicators = [indicator]
    if '-' in indicator:
        # looks like an IP Range, let's try to make it a CIDR
        a1, a2 = indicator.split('-', 1)
        if a1 == a2:
            # same IP
            indicators = [a1]
        else:
            # use netaddr builtin algo to summarize range into CIDR
            iprange = netaddr.IPRange(a1, a2)
            cidrs = iprange.cidrs()
            indicators = map(str, cidrs)

    observables = []
    for i in indicators:
        id_ = '{}:observable-{}'.format(
            namespace,
            uuid.uuid4()
        )

        ao = cybox.objects.address_object.Address(
            address_value=i,
            category=category
        )

        o = cybox.core.Observable(
            title='{}: {}'.format(value['type'], i),
            id_=id_,
            item=ao
        )

        observables.append(o)

    return observables


def stix_email_addr_observable(namespace, indicator, value):
    category = cybox.objects.address_object.Address.CAT_EMAIL

    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    ao = cybox.objects.address_object.Address(
        address_value=indicator,
        category=category
    )

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=ao
    )

    return [o]


def stix_domain_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    do = cybox.objects.domain_name_object.DomainName()
    do.value = indicator
    do.type_ = 'FQDN'

    o = cybox.core.Observable(
        title='FQDN: ' + indicator,
        id_=id_,
        item=do
    )

    return [o]


def stix_url_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    uo = cybox.objects.uri_object.URI(
        value=indicator,
        type_=cybox.objects.uri_object.URI.TYPE_URL
    )

    o = cybox.core.Observable(
        title='URL: ' + indicator,
        id_=id_,
        item=uo
    )

    return [o]


def stix_hash_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    uo = cybox.objects.file_object.File()
    uo.add_hash(indicator)

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=uo
    )

    return [o]


TYPE_MAPPING = {
    FeedIndicatorType.IP: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
        'mapper': stix_ip_observable
    },
    FeedIndicatorType.CIDR: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
        'mapper': stix_ip_observable
    },
    FeedIndicatorType.IPv6: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
        'mapper': stix_ip_observable
    },
    FeedIndicatorType.IPv6CIDR: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
        'mapper': stix_ip_observable
    },
    FeedIndicatorType.URL: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_URL_WATCHLIST,
        'mapper': stix_url_observable
    },
    FeedIndicatorType.Domain: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_DOMAIN_WATCHLIST,
        'mapper': stix_domain_observable
    },
    FeedIndicatorType.SHA256: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
        'mapper': stix_hash_observable
    },
    FeedIndicatorType.SHA1: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
        'mapper': stix_hash_observable
    },
    FeedIndicatorType.MD5: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
        'mapper': stix_hash_observable
    },
    FeedIndicatorType.File: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
        'mapper': stix_hash_observable
    },
    FeedIndicatorType.Email: {
        'indicator_type': stix.common.vocabs.IndicatorType.TERM_MALICIOUS_EMAIL,
        'mapper': stix_email_addr_observable
    }
}


def set_id_namespace(uri, name):
    # maec and cybox
    namespace = mixbox.namespaces.Namespace(uri, name)
    mixbox.idgen.set_id_namespace(namespace)


def get_stix_indicator(indicator):
    set_id_namespace(NAMESPACE_URI, NAMESPACE)

    type_ = indicator['indicator_type']
    type_mapper = TYPE_MAPPING.get(type_, None)

    value = indicator['value']
    source = indicator['source']

    title = f'{type_}: {value}'
    description = f'{type_} indicator from {source}'

    header = None
    if title is not None or description is not None:
        header = stix.core.STIXHeader(
            title=title,
            description=description
        )

    spid = '{}:indicator-{}'.format(
        NAMESPACE,
        uuid.uuid4()
    )
    sp = stix.core.STIXPackage(id_=spid, stix_header=header)

    observables = type_mapper['mapper'](NAMESPACE, indicator, value)

    for o in observables:
        id_ = '{}:indicator-{}'.format(
            NAMESPACE,
            uuid.uuid4()
        )

        if value['type'] == 'URL':
            eindicator = werkzeug.urls.iri_to_uri(indicator, safe_conversion=True)
        else:
            eindicator = indicator

        sindicator = stix.indicator.indicator.Indicator(
            id_=id_,
            title='{}: {}'.format(
                value['type'],
                eindicator
            ),
            description='{} indicator from {}'.format(
                value['type'],
                ', '.join(value['sources'])
            ),
            timestamp=datetime.utcnow().replace(tzinfo=pytz.utc)
        )

        score = indicator.get('score')
        confidence = 'Low'
        if score is None:
            LOG.error('%s - indicator without score', value)
            sindicator.confidence = "Unknown"  # We shouldn't be here
        if score < 2:
            pass
        elif score < 3:
            confidence = 'Medium'
        else:
            confidence = 'High'

        sindicator.confidence = confidence

        sindicator.add_indicator_type(type_mapper['indicator_type'])

        sindicator.add_observable(o)

        sp.add_indicator(sindicator)

    return sp.to_json()


def access_log(f):
    @functools.wraps(f)
    def log(*args, **kwargs):
        headers = request.headers

        demisto.info('Headers: ' + str(headers))

        return f(*args, **kwargs)
    return log


def taxii_check(f):
    @functools.wraps(f)
    def check(*args, **kwargs):
        taxii_content_type = request.headers.get('X-TAXII-Content-Type', None)
        if taxii_content_type not in [
            'urn:taxii.mitre.org:message:xml:1.1',
            'urn:taxii.mitre.org:message:xml:1.0'
        ]:
            return make_response('Invalid TAXII Headers', 400)
        taxii_content_type = request.headers.get('X-TAXII-Protocol', None)
        if taxii_content_type not in [
            'urn:taxii.mitre.org:protocol:http:1.0',
            'urn:taxii.mitre.org:protocol:https:1.0'
        ]:
            return make_response('Invalid TAXII Headers', 400)
        taxii_content_type = request.headers.get('X-TAXII-Services', None)
        if taxii_content_type not in [
            'urn:taxii.mitre.org:services:1.1',
            'urn:taxii.mitre.org:services:1.0'
        ]:
            return make_response('Invalid TAXII Headers', 400)
        return f(*args, **kwargs)
    return check


def get_port(params: dict = demisto.params()) -> int:
    """
    Gets port from the integration parameters
    """
    port_mapping: str = params.get('longRunningPort', '')
    port: int
    if port_mapping:
        if ':' in port_mapping:
            port = int(port_mapping.split(':')[1])
        else:
            port = int(port_mapping)
    else:
        raise ValueError('Please provide a Listen Port.')

    return port


def get_collections(params: dict = demisto.params()) -> list:
    """
    Gets the indicator query collections from the integration parameters
    """
    collections_json: str = params.get('collections', '')

    try:
        collections = json.loads(collections_json)
    except Exception:
        raise ValueError('The collections string must be a valid JSON string.')

    return collections


def find_indicators_by_time_frame(indicator_query: str, begin_time: datetime, end_time: datetime) -> list:
    """
    Finds indicators using demisto.searchIndicators
    """

    if indicator_query:
        indicator_query += ' and '
    else:
        indicator_query = ''

    if begin_time:
        tz_begin_time = datetime.strftime(begin_time, '%Y-%m-%dT%H:%M:%S %z')
        indicator_query += f'createdTime:>"{tz_begin_time}"'
        if end_time:
            indicator_query += ' and '
    if end_time:
        tz_end_time = datetime.strftime(end_time, '%Y-%m-%dT%H:%M:%S %z')
        indicator_query += f'createdTime:>="{tz_end_time}"'
    demisto.info(f'Querying indicators by: {indicator_query}')
    iocs, _ = find_indicators_loop(indicator_query)
    return iocs


def find_indicators_loop(indicator_query: str, total_fetched: int = 0, next_page: int = 0,
                         last_found_len: int = PAGE_SIZE):
    """
    Finds indicators using while loop with demisto.searchIndicators, and returns result and last page
    """
    iocs: List[dict] = []
    if not last_found_len:
        last_found_len = total_fetched
    while last_found_len == PAGE_SIZE:
        fetched_iocs = demisto.searchIndicators(query=indicator_query, page=next_page, size=PAGE_SIZE).get('iocs')
        iocs.extend(fetched_iocs)
        last_found_len = len(fetched_iocs)
        total_fetched += last_found_len
        next_page += 1
    return iocs, next_page


def taxii_make_response(taxii_message):
    h = {
        'Content-Type': "application/xml",
        'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
        'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:http:1.0'
    }
    r = make_response((taxii_message.to_xml(pretty_print=True), 200, h))

    return r


''' ROUTE FUNCTIONS '''


@APP.route('/taxii-discovery-service', methods=['POST'])
@taxii_check
def taxii_discovery_service() -> Response:
    """
    Route for discovery service
    """

    try:
        discovery_response = SERVER.get_discovery_service(libtaxii.messages_11.get_message_from_xml(request.data))
    except Exception as e:
        return make_response(str(e), 400)

    return taxii_make_response(discovery_response)


@APP.route('/taxii-collection-management-service', methods=['POST'])
@taxii_check
def taxii_collection_management_service() -> Response:
    """
    Route for collection management
    """

    try:
        collection_response = SERVER.get_collections(libtaxii.messages_11.get_message_from_xml(request.data))
    except Exception as e:
        return make_response(str(e), 400)

    return taxii_make_response(collection_response)


@APP.route('/taxii-poll-service', methods=['POST'])
@taxii_check
@access_log
def taxii_poll_service() -> Response:
    """
    Route for poll service
    """

    try:
        taxiicontent_type = request.headers['X-TAXII-Content-Type']
        if taxiicontent_type == 'urn:taxii.mitre.org:message:xml:1.1':
            taxii_message = libtaxii.messages_11.get_message_from_xml(request.data)
            poll_response = SERVER.get_poll_response(taxii_message)
        else:
            raise ValueError('Invalid message')
    except Exception as e:
        return make_response(str(e), 400)

    return Response(
        response=stream_with_context(poll_response),
        status=200,
        headers={
            'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
            'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:http:1.0'
        },
        mimetype='application/xml'
    )


''' COMMAND FUNCTIONS '''


def test_module(args, params):
    get_port(params)

    return 'ok', {}, {}


def run_long_running():
    """
    Starts the long running thread.
    """

    certificate_path = str()
    private_key_path = str()
    ssl_args = dict()
    try:
        if SERVER.certificate and SERVER.private_key and not SERVER.http_server:
            certificate_file = NamedTemporaryFile(delete=False)
            certificate_path = certificate_file.name
            certificate_file.write(bytes(SERVER.certificate, 'utf-8'))
            certificate_file.close()
            ssl_args['certfile'] = certificate_path

            private_key_file = NamedTemporaryFile(delete=False)
            private_key_path = private_key_file.name
            private_key_file.write(bytes(SERVER.private_key, 'utf-8'))
            private_key_file.close()
            ssl_args['keyfile'] = private_key_path
            demisto.debug('Starting HTTPS Server')
        else:
            demisto.debug('Starting HTTP Server')
        server = WSGIServer(('', SERVER.port), APP, **ssl_args)
        server.serve_forever()
    except Exception as e:
        if certificate_path:
            os.unlink(certificate_path)
        if private_key_path:
            os.unlink(private_key_path)
        demisto.error(f'An error occurred in long running loop: {str(e)}')
        raise ValueError(str(e))


def main():
    """
    Main
    """
    params = demisto.params()
    command = demisto.command()
    port = get_port(params)
    collections = get_collections(params)
    server_links = demisto.demistoUrls()
    server_link_parts: ParseResult = urlparse(server_links.get('server'))

    certificate: str = params.get('certificate', '')
    private_key: str = params.get('key', '')
    http_server: bool = params.get('http_flag', True)

    global SERVER
    SERVER = TAXIIServer(f'{server_link_parts.scheme}://{server_link_parts.hostname}', port, collections,
                         certificate, private_key, http_server)

    demisto.debug('Command being called is {}'.format(command))
    commands = {
        'test-module': test_module
    }

    try:
        if command == 'long-running-execution':
            run_long_running()
        else:
            readable_output, outputs, raw_response = commands[command](demisto.args(), params)
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
