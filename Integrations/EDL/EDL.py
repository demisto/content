import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


import re
from copy import deepcopy
from base64 import b64decode
from multiprocessing import Process
from gevent.pywsgi import WSGIServer
from tempfile import NamedTemporaryFile
from flask import Flask, Response, request
from netaddr import IPAddress, iprange_to_cidrs
from typing import Callable, List, Any, Dict, cast, Tuple
from ssl import SSLContext, SSLError, PROTOCOL_TLSv1_2


class Handler:
    @staticmethod
    def write(msg):
        demisto.info(msg)


''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'EDL'
PAGE_SIZE: int = 200
DEMISTO_LOGGER: Handler = Handler()
APP: Flask = Flask('demisto-edl')
EDL_VALUES_KEY: str = 'dmst_edl_values'
EDL_LIMIT_ERR_MSG: str = 'Please provide a valid integer for EDL Size'
EDL_MISSING_REFRESH_ERR_MSG: str = 'Refresh Rate must be "number date_range_unit", examples: (2 hours, 4 minutes, ' \
                                   '6 months, 1 day, etc.)'
''' REFORMATTING REGEXES '''
_PROTOCOL_RE = re.compile('^(?:[a-z]+:)*//')
_PORT_RE = re.compile(r'^((?:[a-z]+:)*//([a-z0-9\-\.]+)|([a-z0-9\-\.]+))(?:\:[0-9]+)*')
_URL_WITHOUT_PORT = r'\g<1>'
_INVALID_TOKEN_RE = re.compile(r'(?:[^\./+=\?&]+\*[^\./+=\?&]*)|(?:[^\./+=\?&]*\*[^\./+=\?&]+)')

DONT_COLLAPSE = "Don't Collapse"
COLLAPSE_TO_CIDR = "To CIDRS"
COLLAPSE_TO_RANGES = "To Ranges"

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


def refresh_edl_context(indicator_query: str, limit: int = 0, collapse_ips: str = DONT_COLLAPSE,
                        panos_compatible: bool = True, url_port_stripping: bool = True) -> str:
    """
    Refresh the cache values and format using an indicator_query to call demisto.searchIndicators

    Parameters:
        indicator_query (str): Query that determines which indicators to include in
            the EDL (Cortex XSOAR indicator query syntax)
        limit (int): The maximum number of indicators to include in the EDL
        collapse_ips (str): Whether to collapse IPs to Ranges or CIDRs or not at all
        panos_compatible (bool): Whether to make the indicators PANOS compatible or not
        url_port_stripping (bool): Whether to strip the port from URL indicators (if a port is present) or not

    Returns: List(IoCs in output format)
    """
    now = datetime.now()
    offset = 0
    # poll indicators into edl from demisto
    iocs = find_indicators_to_limit(indicator_query, limit, offset, panos_compatible, url_port_stripping)
    out_dict, actual_indicator_amount = create_values_for_returned_dict(iocs, collapse_ips=collapse_ips)

    if collapse_ips != DONT_COLLAPSE:
        while actual_indicator_amount < limit:
            # from where to start the new poll and how many results should be fetched
            new_offset = len(iocs) + offset + actual_indicator_amount - 1
            new_limit = limit - actual_indicator_amount

            # poll additional indicators into list from demisto
            new_iocs = find_indicators_to_limit(indicator_query, new_limit, new_offset)

            # in case no additional indicators exist - exit
            if len(new_iocs) == 0:
                break

            # add the new results to the existing results
            iocs += new_iocs

            # reformat the output
            out_dict, actual_indicator_amount = create_values_for_returned_dict(iocs, collapse_ips=collapse_ips)

    out_dict["last_run"] = date_to_timestamp(now)
    demisto.setIntegrationContext(out_dict)
    return out_dict[EDL_VALUES_KEY]


def find_indicators_to_limit(indicator_query: str, limit: int, offset: int = 0,
                             panos_compatible: bool = True, url_port_stripping: bool = False) -> list:
    """
    Finds indicators using demisto.searchIndicators

    Parameters:
        indicator_query (str): Query that determines which indicators to include in
            the EDL (Cortex XSOAR indicator query syntax)
        limit (int): The maximum number of indicators to include in the EDL
        offset (int): The starting index from which to fetch incidents
        panos_compatible (bool): Whether to make the indicators PANOS compatible or not
        url_port_stripping (bool): Whether to strip the port from URL indicators (if a port is present) or not

    Returns:
        list: The IoCs list up until the amount set by 'limit'
    """
    if offset:
        next_page = int(offset / PAGE_SIZE)

        # set the offset from the starting page
        offset_in_page = offset - (PAGE_SIZE * next_page)

    else:
        next_page = 0
        offset_in_page = 0

    # the second returned variable is the next page - it is implemented for a future use of repolling
    iocs, _ = find_indicators_to_limit_loop(indicator_query, limit, next_page=next_page,
                                            panos_compatible=panos_compatible,
                                            url_port_stripping=url_port_stripping)

    # if offset in page is bigger than the amount of results returned return empty list
    if len(iocs) <= offset_in_page:
        return []

    return iocs[offset_in_page:limit + offset_in_page]


def find_indicators_to_limit_loop(indicator_query: str, limit: int, total_fetched: int = 0,
                                  next_page: int = 0, last_found_len: int = PAGE_SIZE,
                                  panos_compatible: bool = True, url_port_stripping: bool = False):
    """
    Finds indicators using while loop with demisto.searchIndicators, and returns result and last page

    Parameters:
        indicator_query (str): Query that determines which indicators to include in
            the EDL (Cortex XSOAR indicator query syntax)
        limit (int): The maximum number of indicators to include in the EDL
        total_fetched (int): The amount of indicators already fetched
        next_page (int): The page we are up to in the loop
        last_found_len (int): The amount of indicators found in the last fetch
        panos_compatible (bool): Whether to make the indicators PANOS compatible or not
        url_port_stripping (bool): Whether to strip the port from URL indicators (if a port is present) or not

    Returns:
        (tuple): The iocs and the last page
    """
    iocs: List[dict] = []
    if not last_found_len:
        last_found_len = total_fetched
    while last_found_len == PAGE_SIZE and limit and total_fetched < limit:
        formatted_iocs = []
        fetched_iocs = demisto.searchIndicators(query=indicator_query, page=next_page, size=PAGE_SIZE).get('iocs', [])
        if panos_compatible or url_port_stripping:
            for ioc in fetched_iocs:
                ioc_value = ioc.get('value', '')
                if url_port_stripping:
                    ioc_value = _PORT_RE.sub(_URL_WITHOUT_PORT, ioc_value)
                if panos_compatible:
                    # protocol stripping
                    ioc_value = _PROTOCOL_RE.sub('', ioc_value)
                    # mix of text and wildcard in domain field handling
                    ioc_value = _INVALID_TOKEN_RE.sub('*', ioc_value)
                    # for PAN-OS *.domain.com does not match domain.com
                    # we should provide both
                    # this could generate more than num entries according to PAGE_SIZE
                    if ioc_value.startswith('*.'):
                        ioc_object_copy = deepcopy(ioc)
                        ioc_object_copy['value'] = ioc_value.lstrip('*.')
                        formatted_iocs.append(ioc_object_copy)
                ioc['value'] = ioc_value
                formatted_iocs.append(ioc)
            iocs.extend(formatted_iocs)
        else:
            iocs.extend(fetched_iocs)
        last_found_len = len(fetched_iocs)
        total_fetched += last_found_len
        next_page += 1
    return iocs, next_page


def ip_groups_to_cidrs(ip_range_groups: list):
    """Collapse ip groups list to CIDRs

    Args:
        ip_range_groups (list): a list of lists containing connected IPs

    Returns:
        list. a list of CIDRs.
    """
    ip_ranges = []  # type:List
    for group in ip_range_groups:
        # handle single ips
        if len(group) == 1:
            ip_ranges.append(str(group[0]))
            continue

        min_ip = group[0]
        max_ip = group[-1]
        moved_ip = False
        # CIDR must begin with an even LSB
        # if the first ip does not - separate it from the rest of the range
        if (int(str(min_ip).split('.')[-1]) % 2) != 0:
            ip_ranges.append(str(min_ip))
            min_ip = group[1]
            moved_ip = True

        # CIDR must end with uneven LSB
        # if the last ip does not - separate it from the rest of the range
        if (int(str(max_ip).split('.')[-1]) % 2) == 0:
            ip_ranges.append(str(max_ip))
            max_ip = group[-2]
            moved_ip = True

        # if both min and max ips were shifted and there are only 2 ips in the range
        # we added both ips by the shift and now we move to the next  range
        if moved_ip and len(group) == 2:
            continue

        else:
            ip_ranges.append(str(iprange_to_cidrs(min_ip, max_ip)[0].cidr))

    return ip_ranges


def ip_groups_to_ranges(ip_range_groups: list):
    """Collapse ip groups list to ranges.

    Args:
        ip_range_groups (list): a list of lists containing connected IPs

    Returns:
        list. a list of Ranges.
    """
    ip_ranges = []  # type:List
    for group in ip_range_groups:
        # handle single ips
        if len(group) == 1:
            ip_ranges.append(str(group[0]))
            continue

        min_ip = group[0]
        max_ip = group[-1]
        ip_ranges.append(str(min_ip) + "-" + str(max_ip))

    return ip_ranges


def ips_to_ranges(ips: list, collapse_ips):
    """Collapse IPs to Ranges or CIDRs.

    Args:
        ips (list): a list of IP strings.
        collapse_ips (str): Whether to collapse to Ranges or CIDRs.

    Returns:
        list. a list to Ranges or CIDRs.
    """
    ips_range_groups = []  # type:List
    ips = sorted(ips)

    if len(ips) > 0:
        ips_range_groups.append([ips[0]])

    if len(ips) > 1:
        for ip in ips[1:]:
            appended = False

            for group in ips_range_groups:
                if IPAddress(int(ip) + 1) in group or IPAddress(int(ip) - 1) in group:
                    group.append(ip)
                    sorted(group)
                    appended = True

            if not appended:
                ips_range_groups.append([ip])

    if collapse_ips == COLLAPSE_TO_RANGES:
        return ip_groups_to_ranges(ips_range_groups)

    else:
        return ip_groups_to_cidrs(ips_range_groups)


def create_values_for_returned_dict(iocs: list, collapse_ips: str = DONT_COLLAPSE) -> Tuple[dict, int]:
    """
    Create a dictionary for output values
    """
    formatted_indicators = []
    ipv4_formatted_indicators = []
    ipv6_formatted_indicators = []
    for ioc in iocs:
        value = ioc.get('value')
        type = ioc.get('indicator_type')
        if value:
            if collapse_ips != DONT_COLLAPSE and type == 'IP':
                ipv4_formatted_indicators.append(IPAddress(value))

            elif collapse_ips != DONT_COLLAPSE and type == 'IPv6':
                ipv6_formatted_indicators.append(IPAddress(value))

            else:
                formatted_indicators.append(value)

    if len(ipv4_formatted_indicators) > 0:
        ipv4_formatted_indicators = ips_to_ranges(ipv4_formatted_indicators, collapse_ips)
        formatted_indicators.extend(ipv4_formatted_indicators)

    if len(ipv6_formatted_indicators) > 0:
        ipv6_formatted_indicators = ips_to_ranges(ipv6_formatted_indicators, collapse_ips)
        formatted_indicators.extend(ipv6_formatted_indicators)

    return {EDL_VALUES_KEY: list_to_str(formatted_indicators, '\n')}, len(formatted_indicators)


def get_edl_ioc_values(on_demand, limit, indicator_query='', last_run=None, cache_refresh_rate=None,
                       collapse_ips: str = DONT_COLLAPSE, panos_compatible: bool = True,
                       url_port_stripping: bool = False) -> str:
    """
    Get the ioc list to return in the edl
    """
    # on_demand ignores cache
    if on_demand:
        values_str = get_ioc_values_str_from_context()
    else:
        if last_run:
            cache_time, _ = parse_date_range(cache_refresh_rate, to_timestamp=True)
            if last_run <= cache_time:
                values_str = refresh_edl_context(indicator_query, limit=limit,
                                                 panos_compatible=panos_compatible,
                                                 url_port_stripping=url_port_stripping,
                                                 collapse_ips=collapse_ips)
            else:
                values_str = get_ioc_values_str_from_context()
        else:
            values_str = refresh_edl_context(indicator_query, limit=limit,
                                             panos_compatible=panos_compatible,
                                             url_port_stripping=url_port_stripping,
                                             collapse_ips=collapse_ips)
    return values_str


def get_ioc_values_str_from_context() -> str:
    """
    Extracts output values from cache
    """
    cache_dict = demisto.getIntegrationContext()
    return cache_dict.get(EDL_VALUES_KEY, '')


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
def route_edl_values() -> Response:
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
    panos_compatible: bool = params.get('panos_compatible', False)
    url_port_stripping: bool = params.get('url_port_stripping', False)

    values = get_edl_ioc_values(
        on_demand=params.get('on_demand'),
        limit=try_parse_integer(params.get('edl_size'), EDL_LIMIT_ERR_MSG),
        last_run=demisto.getIntegrationContext().get('last_run'),
        indicator_query=params.get('indicators_query'),
        cache_refresh_rate=params.get('cache_refresh_rate'),
        panos_compatible=panos_compatible,
        url_port_stripping=url_port_stripping,
        collapse_ips=params.get('collapse_ips')
    )
    return Response(values, status=200, mimetype='text/plain')


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
        try_parse_integer(params.get('edl_size'), EDL_LIMIT_ERR_MSG)  # validate EDL Size was set
        query = params.get('indicators_query')  # validate indicators_query isn't empty
        if not query:
            raise ValueError('"Indicator Query" is required. Provide a valid query.')
        cache_refresh_rate = params.get('cache_refresh_rate', '')
        if not cache_refresh_rate:
            raise ValueError(EDL_MISSING_REFRESH_ERR_MSG)
        # validate cache_refresh_rate value
        range_split = cache_refresh_rate.split(' ')
        if len(range_split) != 2:
            raise ValueError(EDL_MISSING_REFRESH_ERR_MSG)
        try_parse_integer(range_split[0], 'Invalid time value for the Refresh Rate. Must be a valid integer.')
        if not range_split[1] in ['minute', 'minutes', 'hour', 'hours', 'day', 'days', 'month', 'months', 'year',
                                  'years']:
            raise ValueError(
                'Invalid time unit for the Refresh Rate. Must be minutes, hours, days, months, or years.')
        parse_date_range(cache_refresh_rate, to_timestamp=True)
    run_long_running(params, is_test=True)
    return 'ok', {}, {}


def run_long_running(params, is_test=False):
    """
    Start the long running server
    :param params: Demisto params
    :param is_test: Indicates whether it's test-module run or regular run
    :return: None
    """
    certificate: str = params.get('certificate', '')
    private_key: str = params.get('key', '')

    certificate_path = str()
    private_key_path = str()

    try:
        port = get_params_port(params)
        ssl_args = dict()

        if (certificate and not private_key) or (private_key and not certificate):
            raise DemistoException('If using HTTPS connection, both certificate and private key should be provided.')

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

        server = WSGIServer(('', port), APP, **ssl_args, log=DEMISTO_LOGGER)
        if is_test:
            server_process = Process(target=server.serve_forever)
            server_process.start()
            time.sleep(5)
            server_process.terminate()
        else:
            server.serve_forever()
    except SSLError as e:
        ssl_err_message = f'Failed to validate certificate and/or private key: {str(e)}'
        demisto.error(ssl_err_message)
        raise ValueError(ssl_err_message)
    except Exception as e:
        demisto.error(f'An error occurred in long running loop: {str(e)}')
        raise ValueError(str(e))
    finally:
        if certificate_path:
            os.unlink(certificate_path)
        if private_key_path:
            os.unlink(private_key_path)


def update_edl_command(args, params):
    """
    Updates the EDL values and format on demand
    """
    on_demand = demisto.params().get('on_demand')
    if not on_demand:
        raise DemistoException(
            '"Update EDL On Demand" is off. If you want to update the EDL manually please toggle it on.')
    limit = try_parse_integer(args.get('edl_size', params.get('edl_size')), EDL_LIMIT_ERR_MSG)
    print_indicators = args.get('print_indicators')
    query = args.get('query')
    collapse_ips = args.get('collapse_ips')
    indicators = refresh_edl_context(query, limit=limit, collapse_ips=collapse_ips)
    hr = tableToMarkdown('EDL was updated successfully with the following values', indicators,
                         ['Indicators']) if print_indicators == 'true' else 'EDL was updated successfully'
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
