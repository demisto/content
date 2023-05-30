import functools
import uuid
from typing import Callable
from flask import Flask, request, make_response, jsonify, Response
from urllib.parse import ParseResult, urlparse
from secrets import compare_digest

import demistomock as demisto
from CommonServerPython import *

''' GLOBAL VARIABLES '''
HTTP_200_OK = 200
HTTP_400_BAD_REQUEST = 400
HTTP_401_UNAUTHORIZED = 401
HTTP_404_NOT_FOUND = 404
HTTP_406_NOT_ACCEPABLE = 406
HTTP_416_RANGE_NOT_SATISFIABLE = 416
INTEGRATION_NAME: str = 'XSOAR Chrome Extension'
API_ROOT = 'threatintel'
APP: Flask = Flask('demisto-chrome-extension')
NAMESPACE_URI = 'https://www.paloaltonetworks.com/cortex'
ACCEPT_TYPE_ALL = '*/*'
TAXII_VER_2_0 = '2.0'
TAXII_VER_2_1 = '2.1'
PAWN_UUID = uuid.uuid5(uuid.NAMESPACE_URL, 'https://www.paloaltonetworks.com')
SCO_DET_ID_NAMESPACE = uuid.UUID('00abedb4-aa42-466c-9c01-fed23315a9b7')
STIX_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
UTC_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
PAGE_SIZE = 2000

''' Extension Server '''


class ExtensionServer:
    def __init__(self, url_scheme: str, host: str, port: int, certificate: str, private_key: str,
                 http_server: bool, credentials: dict):
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

        """
        self._url_scheme = url_scheme
        self._host = host
        self._port = port
        self._certificate = certificate
        self._private_key = private_key
        self._http_server = http_server

        self._auth = None
        if credentials and (identifier := credentials.get('identifier')) and (password := credentials.get('password')):
            self._auth = (identifier, password)
        self.namespace_uuid = uuid.uuid5(PAWN_UUID, demisto.getLicenseID())

    @property
    def auth(self):
        return self._auth


SERVER: ExtensionServer = None  # type: ignore[assignment]

''' HELPER FUNCTIONS '''


def extension_validate_request_headers(f: Callable) -> Callable:
    @functools.wraps(f)
    def validate_request_headers(*args, **kwargs):
        """
        function for HTTP requests to validate authentication and Accept headers.
        """

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

        return f(*args, **kwargs)

    return validate_request_headers


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

    headers = {
        'Content-Type': content_type,
    }
    if status_code == HTTP_401_UNAUTHORIZED:
        headers['WWW-Authenticate'] = 'Basic realm="Authentication Required"'

    return make_response(jsonify(content), status_code, headers)


def extract_indicators_from_text(data):
    indicators_res = demisto.executeCommand("extractIndicators", {'text': data})[0][u'Contents']
    demisto.createIndicators(indicators_res)
    return indicators_res


''' ROUTE FUNCTIONS '''


@APP.route('/demisto_extension/', methods=['POST'])
@extension_validate_request_headers
def extension_search_indicators() -> Response:
    """

    """
    try:
        discovery_response = extract_indicators_from_text(request.data, request.headers)
    except Exception as e:
        error = f'Could not perform the discovery request: {str(e)}'
        handle_long_running_error(error)
        return handle_response(HTTP_400_BAD_REQUEST, {'title': 'Discovery Request Error',
                                                      'description': error})

    return handle_response(HTTP_200_OK, discovery_response)


def test_module(params: dict) -> str:
    """
    Integration test module.
    """
    run_long_running(params, is_test=True)
    return 'ok'


def main():  # pragma: no cover
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

    credentials = params.get('credentials', {})

    server_links = demisto.demistoUrls()
    server_link_parts: ParseResult = urlparse(server_links.get('server'))
    host_name = server_link_parts.hostname

    certificate = params.get('certificate', '')
    private_key = params.get('key', '')

    if (certificate and not private_key) or (private_key and not certificate):
        raise ValueError('When using HTTPS connection, both certificate and private key must be provided.')

    http_server = not (certificate and private_key)  # False if (certificate and private_key) else True

    scheme = 'https' if not http_server else 'http'

    demisto.debug(f'Command being called is {command}')

    try:
        SERVER = ExtensionServer(scheme, str(host_name), port, certificate,
                                 private_key, http_server, credentials)

        if command == 'long-running-execution':
            run_long_running(params)

        elif command == 'test-module':
            return_results(test_module(params))

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


from NGINXApiModule import *  # noqa: E402

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
