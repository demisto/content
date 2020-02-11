import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from flask import Flask, request, make_response, Response
from gevent.pywsgi import WSGIServer
import functools
from urllib.parse import urlparse, ParseResult

import libtaxii
import libtaxii.messages_11
import libtaxii.constants

from tempfile import NamedTemporaryFile
from typing import Callable, List, Any

''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'TAXII Server'
PAGE_SIZE = 100
APP: Flask = Flask('demisto-taxii')
PORT: int

SERVICE_INSTANCES = [
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

''' HELPER FUNCTIONS '''


def taxii_check(f):
    @functools.wraps(f)
    def check(*args, **kwargs):
        tct = request.headers.get('X-TAXII-Content-Type', None)
        if tct not in [
            'urn:taxii.mitre.org:message:xml:1.1',
            'urn:taxii.mitre.org:message:xml:1.0'
        ]:
            return 'Invalid TAXII Headers', 400
        tct = request.headers.get('X-TAXII-Protocol', None)
        if tct not in [
            'urn:taxii.mitre.org:protocol:http:1.0',
            'urn:taxii.mitre.org:protocol:https:1.0'
        ]:
            return 'Invalid TAXII Headers', 400
        tct = request.headers.get('X-TAXII-Services', None)
        if tct not in [
            'urn:taxii.mitre.org:services:1.1',
            'urn:taxii.mitre.org:services:1.0'
        ]:
            return 'Invalid TAXII Headers', 400
        return f(*args, **kwargs)
    return check


def init_params_port(params: dict = demisto.params()):
    """
    Gets port from the integration parameters
    """
    port_mapping: str = params.get('longRunningPort', '')
    err_msg: str
    port: int
    if port_mapping:
        if ':' in port_mapping:
            port = int(port_mapping.split(':')[1])
        else:
            port = int(port_mapping)
    else:
        raise ValueError('Please provide a Listen Port.')

    global PORT
    PORT = port


def find_indicators_to_limit(indicator_query: str, limit: int) -> list:
    """
    Finds indicators using demisto.searchIndicators
    """
    iocs, _ = find_indicators_to_limit_loop(indicator_query, limit)
    return iocs[:limit]


def find_indicators_to_limit_loop(indicator_query: str, limit: int, total_fetched: int = 0, next_page: int = 0,
                                  last_found_len: int = PAGE_SIZE):
    """
    Finds indicators using while loop with demisto.searchIndicators, and returns result and last page
    """
    iocs: List[dict] = []
    if not last_found_len:
        last_found_len = total_fetched
    while last_found_len == PAGE_SIZE and limit and total_fetched < limit:
        fetched_iocs = demisto.searchIndicators(query=indicator_query, page=next_page, size=PAGE_SIZE).get('iocs')
        iocs.extend(fetched_iocs)
        last_found_len = len(fetched_iocs)
        total_fetched += last_found_len
        next_page += 1
    return iocs, next_page


def taxii_make_response(m11):
    h = {
        'Content-Type': "application/xml",
        'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
        'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:http:1.0'
    }
    r = make_response((m11.to_xml(pretty_print=True), 200, h))

    return r


''' ROUTE FUNCTIONS '''


@APP.route('/taxii-discovery-service', methods=['POST'])
@taxii_check
def taxii_discovery_service() -> Response:
    """
    Route for discovery service
    """
    server_links = demisto.demistoUrls()
    server_link_parts: ParseResult = urlparse(server_links.get('server'))
    discovery_service_url = f'{server_link_parts.scheme}://{server_link_parts.hostname}:{PORT}'

    tm = libtaxii.messages_11.get_message_from_xml(request.data)
    if tm.message_type != libtaxii.constants.MSG_DISCOVERY_REQUEST:
        return make_response(('Invalid message, invalid Message Type', 400))

    dresp = libtaxii.messages_11.DiscoveryResponse(
        libtaxii.messages_11.generate_message_id(),
        tm.message_id
    )

    for si in SERVICE_INSTANCES:
        sii = libtaxii.messages_11.ServiceInstance(
            si['type'],
            'urn:taxii.mitre.org:services:1.1',
            'urn:taxii.mitre.org:protocol:http:1.0',
            "{}/{}".format(discovery_service_url, si['path']),
            ['urn:taxii.mitre.org:message:xml:1.1'],
            available=True
        )
        dresp.service_instances.append(sii)

    return taxii_make_response(dresp)


''' COMMAND FUNCTIONS '''


def test_module(args, params):
    init_params_port(params)

    return 'ok', {}, {}


def run_long_running(params):
    """
    Starts the long running thread.
    """
    certificate: str = params.get('certificate', '')
    private_key: str = params.get('key', '')
    http_server: bool = params.get('http_flag', True)

    certificate_path = str()
    private_key_path = str()

    try:
        ssl_args = dict()

        if certificate and private_key and not http_server:
            certificate_file = NamedTemporaryFile(delete=False)
            certificate_path = certificate_file.name
            certificate_file.write(bytes(certificate, 'utf-8'))
            certificate_file.close()
            ssl_args['certfile'] = certificate_path

            private_key_file = NamedTemporaryFile(delete=False)
            private_key_path = private_key_file.name
            private_key_file.write(bytes(private_key, 'utf-8'))
            private_key_file.close()
            ssl_args['keyfile'] = private_key_path
            demisto.debug('Starting HTTPS Server')
        else:
            demisto.debug('Starting HTTP Server')

        server = WSGIServer(('', PORT), APP, **ssl_args)
        server.serve_forever()
    except Exception as e:
        if certificate_path:
            os.unlink(certificate_path)
        if private_key_path:
            os.unlink(private_key_path)
        demisto.error(f'An error occurred in long running loop: {str(e)}')
        raise ValueError(str(e))


def update_edl_command(args, params):
    """
    Updates the EDL values and format on demand
    """
    on_demand = demisto.params().get('on_demand')
    if not on_demand:
        raise DemistoException(
            '"Update EDL On Demand" is off. If you want to update the EDL manually please toggle it on.')
    limit = int(args.get('edl_size', params.get('edl_size')))
    print_indicators = args.get('print_indicators')
    query = args.get('query')
    indicators = refresh_edl_context(query, limit=limit)
    hr = tableToMarkdown('EDL was updated successfully with the following values', indicators,
                         ['Indicators']) if print_indicators == 'true' else 'EDL was updated successfully'
    return hr, {}, indicators


def main():
    """
    Main
    """
    params = demisto.params()
    command = demisto.command()
    init_params_port(params)
    demisto.debug('Command being called is {}'.format(command))
    commands = {
        'test-module': test_module,
        'edl-update': update_edl_command
    }

    try:
        if command == 'long-running-execution':
            run_long_running(params)
        else:
            readable_output, outputs, raw_response = commands[command](demisto.args(), params)
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
