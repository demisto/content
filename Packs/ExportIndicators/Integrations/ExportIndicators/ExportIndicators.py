import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
from flask import Flask, Response, request
from gevent.pywsgi import WSGIServer
from tempfile import NamedTemporaryFile
from typing import Callable, List, Any, cast, Dict
from base64 import b64decode


class Handler:
    @staticmethod
    def write(msg):
        demisto.info(msg)


''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'Export Indicators Service'
PAGE_SIZE: int = 200
DEMISTO_LOGGER: Handler = Handler()
APP: Flask = Flask('demisto-export_iocs')
CTX_VALUES_KEY: str = 'dmst_export_iocs_values'
CTX_MIMETYPE_KEY: str = 'dmst_export_iocs_mimetype'
FORMAT_CSV: str = 'csv'
FORMAT_TEXT: str = 'text'
FORMAT_JSON_SEQ: str = 'json-seq'
FORMAT_JSON: str = 'json'
CTX_LIMIT_ERR_MSG: str = 'Please provide a valid integer for List Size'
CTX_MISSING_REFRESH_ERR_MSG: str = 'Refresh Rate must be "number date_range_unit", examples: (2 hours, 4 minutes, ' \
                                   '6 months, 1 day, etc.)'

''' HELPER FUNCTIONS '''


def list_to_str(inp_list: list, delimiter: str = ',', map_func: Callable = str) -> str:
    """
    Transforms a list to an str, with a custom delimiter between each list item
    """
    str_res = ""
    if inp_list:
        if isinstance(inp_list, list):
            str_res = delimiter.join(map(map_func, inp_list))
        else:
            raise AttributeError('Invalid inp_list provided to list_to_str')
    return str_res


def get_params_port(params: dict = demisto.params()) -> int:
    """
    Gets port from the integration parameters
    """
    port_mapping: str = params.get('longRunningPort', '')
    err_msg: str
    port: int
    if port_mapping:
        err_msg = f'Listen Port must be an integer. {port_mapping} is not valid.'
        if ':' in port_mapping:
            port = try_parse_integer(port_mapping.split(':')[1], err_msg)
        else:
            port = try_parse_integer(port_mapping, err_msg)
    else:
        raise ValueError('Please provide a Listen Port.')
    return port


def refresh_outbound_context(indicator_query: str, out_format: str, limit: int = 0) -> str:
    """
    Refresh the cache values and format using an indicator_query to call demisto.searchIndicators
    Returns: List(IoCs in output format)
    """
    now = datetime.now()
    iocs = find_indicators_with_limit(indicator_query, limit)  # poll indicators into list from demisto
    out_dict = create_values_out_dict(iocs, out_format)
    out_dict[CTX_MIMETYPE_KEY] = 'application/json' if out_format == FORMAT_JSON else 'text/plain'
    save_context(now, out_dict)
    return out_dict[CTX_VALUES_KEY]


def save_context(now: datetime, out_dict: dict):
    """Saves export_iocs state and refresh time to context"""
    demisto.setLastRun({'last_run': date_to_timestamp(now)})
    demisto.setIntegrationContext(out_dict)


def find_indicators_with_limit(indicator_query: str, limit: int) -> list:
    """
    Finds indicators using demisto.searchIndicators
    """
    iocs, _ = find_indicators_with_limit_loop(indicator_query, limit)
    return iocs[:limit]


def find_indicators_with_limit_loop(indicator_query: str, limit: int, total_fetched: int = 0, next_page: int = 0,
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


def create_values_out_dict(iocs: list, out_format: str) -> dict:
    """
    Create a dictionary for output values using the selected format (json, json-seq, text, csv)
    """
    if out_format == FORMAT_JSON:  # handle json separately
        iocs_list = [ioc for ioc in iocs]
        return {CTX_VALUES_KEY: json.dumps(iocs_list)}
    else:
        formatted_indicators = []
        if out_format == FORMAT_CSV and len(iocs) > 0:  # add csv keys as first item
            headers = list(iocs[0].keys())
            formatted_indicators.append(list_to_str(headers))
        for ioc in iocs:
            value = ioc.get('value')
            if value:
                if out_format == FORMAT_TEXT:
                    formatted_indicators.append(value)
                elif out_format == FORMAT_JSON_SEQ:
                    formatted_indicators.append(json.dumps(ioc))
                elif out_format == FORMAT_CSV:
                    # wrap csv values with " to escape them
                    values = list(ioc.values())
                    formatted_indicators.append(list_to_str(values, map_func=lambda val: f'"{val}"'))
    return {CTX_VALUES_KEY: list_to_str(formatted_indicators, '\n')}


def get_outbound_mimetype() -> str:
    """Returns the mimetype of the export_iocs"""
    ctx = demisto.getIntegrationContext()
    return ctx.get(CTX_MIMETYPE_KEY, 'text/plain')


def get_outbound_ioc_values(on_demand, limit, indicator_query='', out_format='text', last_run=None,
                            cache_refresh_rate=None) -> str:
    """
    Get the ioc list to return in the list
    """
    # on_demand ignores cache
    if on_demand:
        values_str = get_ioc_values_str_from_context()
    else:
        if last_run:
            cache_time, _ = parse_date_range(cache_refresh_rate, to_timestamp=True)
            if last_run <= cache_time:
                values_str = refresh_outbound_context(indicator_query, out_format, limit=limit)
            else:
                values_str = get_ioc_values_str_from_context()
        else:
            values_str = refresh_outbound_context(indicator_query, out_format, limit=limit)
    return values_str


def get_ioc_values_str_from_context() -> str:
    """
    Extracts output values from cache
    """
    cache_dict = demisto.getIntegrationContext()
    return cache_dict.get(CTX_VALUES_KEY, '')


def try_parse_integer(int_to_parse: Any, err_msg: str) -> int:
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    """
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res


def validate_basic_authentication(headers: dict, username: str, password: str) -> bool:
    """
    Checks whether the authentication is valid.
    :param headers: The headers of the http request
    :param username: The integration's username
    :param password: The integration's password
    :return: Boolean which indicates whether the authentication is valid or not
    """
    credentials: str = headers.get('Authorization', '')
    if not credentials or 'Basic ' not in credentials:
        return False
    encoded_credentials: str = credentials.split('Basic ')[1]
    credentials: str = b64decode(encoded_credentials).decode('utf-8')
    if ':' not in credentials:
        return False
    credentials_list = credentials.split(':')
    if len(credentials_list) != 2:
        return False
    user, pwd = credentials_list
    return user == username and pwd == password


''' ROUTE FUNCTIONS '''


@APP.route('/', methods=['GET'])
def route_list_values() -> Response:
    """
    Main handler for values saved in the integration context
    """
    params = demisto.params()

    credentials = params.get('credentials') if params.get('credentials') else {}
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    if username and password:
        headers: dict = cast(Dict[Any, Any], request.headers)
        if not validate_basic_authentication(headers, username, password):
            err_msg: str = 'Basic authentication failed. Make sure you are using the right credentials.'
            demisto.debug(err_msg)
            return Response(err_msg, status=401)

    values = get_outbound_ioc_values(
        out_format=params.get('format'),
        on_demand=params.get('on_demand'),
        limit=try_parse_integer(params.get('list_size'), CTX_LIMIT_ERR_MSG),
        last_run=demisto.getLastRun().get('last_run'),
        indicator_query=params.get('indicators_query'),
        cache_refresh_rate=params.get('cache_refresh_rate')
    )
    mimetype = get_outbound_mimetype()
    return Response(values, status=200, mimetype=mimetype)


''' COMMAND FUNCTIONS '''


def test_module(args, params):
    """
    Validates:
        1. Valid port.
        2. Valid cache_refresh_rate
    """
    get_params_port(params)
    on_demand = params.get('on_demand', None)
    if not on_demand:
        try_parse_integer(params.get('list_size'), CTX_LIMIT_ERR_MSG)  # validate export_iocs Size was set
        query = params.get('indicators_query')  # validate indicators_query isn't empty
        if not query:
            raise ValueError('"Indicator Query" is required. Provide a valid query.')
        cache_refresh_rate = params.get('cache_refresh_rate', '')
        if not cache_refresh_rate:
            raise ValueError(CTX_MISSING_REFRESH_ERR_MSG)
        # validate cache_refresh_rate value
        range_split = cache_refresh_rate.split(' ')
        if len(range_split) != 2:
            raise ValueError(CTX_MISSING_REFRESH_ERR_MSG)
        try_parse_integer(range_split[0], 'Invalid time value for the Refresh Rate. Must be a valid integer.')
        if not range_split[1] in ['minute', 'minutes', 'hour', 'hours', 'day', 'days', 'month', 'months', 'year',
                                  'years']:
            raise ValueError(
                'Invalid time unit for the Refresh Rate. Must be minutes, hours, days, months, or years.')
        parse_date_range(cache_refresh_rate, to_timestamp=True)
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
        port = get_params_port(params)
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

        server = WSGIServer(('', port), APP, **ssl_args, log=DEMISTO_LOGGER)
        server.serve_forever()
    except Exception as e:
        if certificate_path:
            os.unlink(certificate_path)
        if private_key_path:
            os.unlink(private_key_path)
        demisto.error(f'An error occurred in long running loop: {str(e)}')
        raise ValueError(str(e))


def update_outbound_command(args, params):
    """
    Updates the export_iocs values and format on demand
    """
    on_demand = demisto.params().get('on_demand')
    if not on_demand:
        raise DemistoException(
            '"Update exported IOCs On Demand" is off. If you want to update manually please toggle it on.')
    limit = try_parse_integer(args.get('list_size', params.get('list_size')), CTX_LIMIT_ERR_MSG)
    print_indicators = args.get('print_indicators')
    query = args.get('query')
    out_format = args.get('format')
    indicators = refresh_outbound_context(query, out_format, limit=limit)
    hr = tableToMarkdown('List was updated successfully with the following values', indicators,
                         ['Indicators']) if print_indicators == 'true' else 'List was updated successfully'
    return hr, {}, indicators


def main():
    """
    Main
    """
    params = demisto.params()

    credentials = params.get('credentials') if params.get('credentials') else {}
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    if (username and not password) or (password and not username):
        err_msg: str = 'If using credentials, both username and password should be provided.'
        demisto.debug(err_msg)
        raise DemistoException(err_msg)

    command = demisto.command()
    demisto.debug('Command being called is {}'.format(command))
    commands = {
        'test-module': test_module,
        'eis-update': update_outbound_command
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
