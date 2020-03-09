import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
from flask import Flask, Response, request
from gevent.pywsgi import WSGIServer
from tempfile import NamedTemporaryFile
from typing import Callable, List, Any, cast, Dict
from base64 import b64decode
import re
import traceback


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
FORMAT_ARG_MWG = 'mwg'
FORMAT_ARG_PANOSURL = 'panosurl'
FORMAT_ARG_BLUECOAT = 'bluecoat'
FORMAT_ARG_PROXYSG = 'proxysg'
FORMAT_MWG: str = 'McAfee Web Gateway'
FORMAT_PROXYSG = "Symantec ProxySG"
FORMAT_PANOSURL = "PAN-OS URL"
CTX_FORMAT_ERR_MSG: str = 'Please provide a valid format from: text,json,json-seq,csv'
CTX_LIMIT_ERR_MSG: str = 'Please provide a valid integer for List Size'
CTX_OFFSET_ERR_MSG: str = 'Please provide a valid integer for Starting Index'
CTX_MWG_TYPE_ERR_MSG: str = 'The McAFee Web Gateway type can only be one of the following: string,' \
                            ' applcontrol, dimension, category, ip, mediatype, number, regex'
CTX_MISSING_REFRESH_ERR_MSG: str = 'Refresh Rate must be "number date_range_unit", examples: (2 hours, 4 minutes, ' \
                                   '6 months, 1 day, etc.)'

_PROTOCOL_REMOVAL = re.compile(r'^(?:[a-z]+:)*//')
_PORT_REMOVAL = re.compile(r'^([a-z0-9\-\.]+)(?:\:[0-9]+)*')
_INVALID_TOKEN_REMOVAL = re.compile(r'(?:[^\./+=\?&]+\*[^\./+=\?&]*)|(?:[^\./+=\?&]*\*[^\./+=\?&]+)')
_BROAD_PATTERN = re.compile(r'^(?:\*\.)+[a-zA-Z]+(?::[0-9]+)?$')

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


def refresh_outbound_context(indicator_query: str, out_format: str, limit: int = 0, offset: int = 0, mwg_type="string",
                             drop_invalids=False, strip_port=False, category_default='bc_category',
                             category_attribute='') -> str:
    """
    Refresh the cache values and format using an indicator_query to call demisto.searchIndicators
    Returns: List(IoCs in output format)
    """
    now = datetime.now()
    iocs = find_indicators_with_limit(indicator_query, limit, offset)  # poll indicators into list from demisto
    out_dict = create_values_out_dict(iocs, out_format, mwg_type=mwg_type,
                                      strip_port=strip_port, drop_invalids=drop_invalids,
                                      category_default=category_default, category_attribute=category_attribute)
    out_dict[CTX_MIMETYPE_KEY] = 'application/json' if out_format == FORMAT_JSON else 'text/plain'
    demisto.setIntegrationContext({
        "last_output": out_dict,
        'last_run': date_to_timestamp(now),
        'last_limit': limit,
        'last_offset': offset,
        'last_format': out_format,
        'last_query': indicator_query,
        'current_iocs': iocs,
        'mwg_type': mwg_type,
        'drop_invalids': drop_invalids,
        'strip_port': strip_port,
        'category_default': category_default,
        'category_attribute': category_attribute
    })
    return out_dict[CTX_VALUES_KEY]


def find_indicators_with_limit(indicator_query: str, limit: int, offset: int) -> list:
    """
    Finds indicators using demisto.searchIndicators
    """
    # calculate the starting page (each page holds 200 entries)
    if offset:
        next_page = int(offset / PAGE_SIZE)

        # set the offset from the starting page
        offset_in_page = offset - (PAGE_SIZE * next_page)

    else:
        next_page = 0
        offset_in_page = 0

    iocs, _ = find_indicators_with_limit_loop(indicator_query, limit, next_page=next_page)

    # if offset in page is bigger than the amount of results returned return empty list
    if len(iocs) <= offset_in_page:
        return []

    return iocs[offset_in_page:limit + offset_in_page]


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


def panos_url_formatting(iocs: list, drop_invalids: bool, strip_port: bool):
    formatted_indicators = []  # type:List
    for indicator_data in iocs:
        # only format URLs and Domains
        if indicator_data.get('indicator_type') in ['URL', 'Domain', 'DomainGlob']:
            indicator = indicator_data.get('value').lower()

            # remove initial protocol - http/https/ftp/ftps etc
            indicator = _PROTOCOL_REMOVAL.sub('', indicator)

            indicator_with_port = indicator
            # remove port from indicator - from demisto.com:369/rest/of/path -> demisto.com/rest/of/path
            indicator = _PORT_REMOVAL.sub(r'\g<1>', indicator)
            # check if removing the port changed something about the indicator
            if indicator != indicator_with_port and not strip_port:
                # if port was in the indicator and strip_port param not set - ignore the indicator
                continue

            with_invalid_tokens_indicator = indicator
            # remove invalid tokens from indicator
            indicator = _INVALID_TOKEN_REMOVAL.sub('*', indicator)

            # check if the indicator held invalid tokens
            if with_invalid_tokens_indicator != indicator:
                # invalid tokens in indicator- if drop_invalids is set - ignore the indicator
                if drop_invalids:
                    continue

                # check if after removing the tokens the indicator is too broad if so - ignore
                # example of too broad terms: "*.paloalto", "*.*.paloalto", "*.paloalto:60"
                hostname = indicator
                if '/' in hostname:
                    hostname, _ = hostname.split('/', 1)

                if _BROAD_PATTERN.match(hostname) is not None:
                    continue

            # for PAN-OS "*.domain.com" does not match "domain.com" - we should provide both
            if indicator.startswith('*.'):
                formatted_indicators.append(indicator[2:])

        formatted_indicators.append(indicator)
    return {CTX_VALUES_KEY: list_to_str(formatted_indicators, '\n')}


def add_indicator_to_category(indicator, category, category_dict):
    if category in category_dict.keys():
        category_dict[category].append(indicator)

    else:
        category_dict[category] = [indicator]

    return category_dict


def create_proxysg_out_format(iocs: list, category_default='bc_category', category_attribute=''):
    formatted_indicators = ''
    category_dict = {}  # type:Dict
    if not category_attribute:
        category_attribute = ''
    category_attribute = category_attribute.split(',')

    if len(category_attribute) == 1 and '' in category_attribute:
        category_attribute = []

    for indicator in iocs:
        if indicator.get('indicator_type') in ['URL', 'Domain', 'DomainGlob']:
            indicator_proxysg_category = indicator.get('proxysgcategory')
            # if a ProxySG Category is set and it is in the category_attribute list or that the attribute list is empty
            # than list add the indicator to it's category list
            if indicator_proxysg_category is not None and \
                    (indicator_proxysg_category in category_attribute or len(category_attribute) == 0):
                category_dict = add_indicator_to_category(indicator.get('value'), indicator_proxysg_category,
                                                          category_dict)

            else:
                # if ProxySG Category is not set or does not exist in the category_attribute list
                category_dict = add_indicator_to_category(indicator.get('value'), category_default, category_dict)

    for category, indicator_list in category_dict.items():
        sub_output_string = f"define category {category}\n"
        sub_output_string += list_to_str(indicator_list, '\n')
        sub_output_string += "\nend\n"
        formatted_indicators += sub_output_string

    return {CTX_VALUES_KEY: formatted_indicators}


def create_mwg_out_format(iocs: list, mwg_type: str) -> dict:
    formatted_indicators = []  # type:List
    for indicator in iocs:
        value = "\"" + indicator.get('value') + "\""
        sources = indicator.get('sourceBrands')
        if sources:
            sources_string = "\"" + ','.join(sources) + "\""

        else:
            sources_string = "\"from CORTEX XSOAR\""

        formatted_indicators.append(value + " " + sources_string)

    string_formatted_indicators = list_to_str(formatted_indicators, '\n')

    if isinstance(mwg_type, list):
        mwg_type = mwg_type[0]

    string_formatted_indicators = "type=" + mwg_type + "\n" + string_formatted_indicators

    return {CTX_VALUES_KEY: string_formatted_indicators}


def create_values_out_dict(iocs: list, out_format: str, mwg_type: str = "string",
                           drop_invalids=False, strip_port=False, category_default='bc_category',
                           category_attribute='') -> dict:
    """
    Create a dictionary for output values using the selected format (json, json-seq, text, csv, McAfee Web Gateway,
    Symantec ProxySG, panosurl)
    """
    if out_format == FORMAT_PANOSURL:
        return panos_url_formatting(iocs, drop_invalids, strip_port)

    if out_format == FORMAT_PROXYSG:
        return create_proxysg_out_format(iocs, category_default, category_attribute)

    if out_format == FORMAT_MWG:
        return create_mwg_out_format(iocs, mwg_type)

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
    ctx = demisto.getIntegrationContext().get('last_output')
    return ctx.get(CTX_MIMETYPE_KEY, 'text/plain')


def is_request_change(limit, offset, out_format=FORMAT_TEXT, last_update_data={}, mwg_type: str = "string",
                      drop_invalids=False, strip_port=False, category_default='bc_category',
                      category_attribute='') -> bool:
    """ Checks for changes in the request params

    Args:
        limit (int): limit on how many indicators should be exported.
        offset (int): the index of the indicator from which the list should be exported.
        out_format (str): the requested output format.
        last_update_data (dict): the cached params for the last request.
        mwg_type (str): the type indicated in the Mcafee Gateway format.
        drop_invalids (bool): Whether to drop invalid indicators in PANOS format.
        strip_port (bool): Whether to strip ports from url indicators in PANOS format.
        category_default (str): the defualt category in ProxySG format.
        category_attribute (str):the categories to print in ProxySG format.

    Returns:
        bool. True if limit/offset/out_format params have changed since the last request, False otherwise.
    """
    last_limit = last_update_data.get('last_limit')
    last_offset = last_update_data.get('last_offset')
    last_format = last_update_data.get('last_format')
    last_mwg_type = last_update_data.get('mwg_type')
    last_drop_invalids = last_update_data.get('drop_invalids')
    last_strip_port = last_update_data.get('strip_port')
    last_category_default = last_update_data.get('category_default')
    last_category_attribute = last_update_data.get('category_attribute')

    return (out_format != last_format or limit != last_limit or offset != last_offset or last_mwg_type != mwg_type
            or last_drop_invalids != drop_invalids or last_strip_port != strip_port
            or last_category_default != category_default or last_category_attribute != category_attribute)


def get_outbound_ioc_values(on_demand, limit, offset, indicator_query='', out_format=FORMAT_TEXT, last_update_data={},
                            cache_refresh_rate=None, mwg_type: str = "string", drop_invalids=False, strip_port=False,
                            category_default='bc_category', category_attribute='') -> str:
    """
    Get the ioc list to return in the list
    """
    last_update = last_update_data.get('last_run')
    last_query = last_update_data.get('last_query')
    current_iocs = last_update_data.get('current_iocs')

    # on_demand ignores cache
    if on_demand:
        if is_request_change(limit, offset, out_format, last_update_data, mwg_type, drop_invalids, strip_port,
                             category_default, category_attribute):
            values_str = get_ioc_values_str_from_context(current_iocs, out_format, limit, offset)

        else:
            values_str = get_ioc_values_str_from_context()

    else:
        if last_update:
            # takes the cache_refresh_rate amount of time back since run time.
            cache_time, _ = parse_date_range(cache_refresh_rate, to_timestamp=True)
            if last_update <= cache_time or is_request_change(limit, offset, out_format, last_update_data) or \
                    indicator_query != last_query:
                values_str = refresh_outbound_context(indicator_query, out_format, limit=limit, offset=offset,
                                                      mwg_type=mwg_type, drop_invalids=drop_invalids,
                                                      strip_port=strip_port, category_default=category_default,
                                                      category_attribute=category_attribute)
            else:
                values_str = get_ioc_values_str_from_context()
        else:
            values_str = refresh_outbound_context(indicator_query, out_format, limit=limit, offset=offset,
                                                  mwg_type=mwg_type, drop_invalids=drop_invalids, strip_port=strip_port,
                                                  category_default=category_default, category_attribute=category_attribute)

    return values_str


def get_ioc_values_str_from_context(iocs=None, new_format: str = FORMAT_TEXT,
                                    limit: int = 10000, offset: int = 0) -> str:
    """
    Extracts output values from cache
    """
    if iocs:
        if offset > len(iocs):
            return ''

        iocs = iocs[offset: limit + offset]
        returned_dict = create_values_out_dict(iocs, new_format)
        current_cache = demisto.getIntegrationContext()
        current_cache['last_output'] = returned_dict
        demisto.setIntegrationContext(current_cache)

    else:
        returned_dict = demisto.getIntegrationContext().get('last_output', {})

    return returned_dict.get(CTX_VALUES_KEY, '')


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


def get_request_args(params):
    limit = try_parse_integer(request.args.get('n', params.get('list_size', 10000)), CTX_LIMIT_ERR_MSG)
    offset = try_parse_integer(request.args.get('s', 0), CTX_OFFSET_ERR_MSG)
    out_format = request.args.get('v', params.get('format', 'text'))
    query = request.args.get('q', params.get('indicators_query'))
    mwg_type = request.args.get('t', params.get('mwg_type', "string"))
    strip_port = request.args.get('sp', params.get('strip_port', False))
    drop_invalids = request.args.get('di', params.get('drop_invalids', False))
    category_default = request.args.get('cd', params.get('category_default', 'bc_category'))
    category_attribute = request.args.get('ca', params.get('category_attribute', ''))

    # handle flags
    if strip_port == '':
        strip_port = True

    if drop_invalids == '':
        drop_invalids = True

    # prevent given empty params
    if len(query) == 0:
        query = params.get('indicators_query')

    if len(out_format) == 0:
        out_format = params.get('format', 'text')

    if out_format not in [FORMAT_PROXYSG, FORMAT_PANOSURL, FORMAT_TEXT, FORMAT_JSON, FORMAT_CSV,
                          FORMAT_JSON_SEQ, FORMAT_MWG, FORMAT_ARG_BLUECOAT, FORMAT_ARG_MWG, FORMAT_ARG_PANOSURL,
                          FORMAT_ARG_PROXYSG]:
        raise DemistoException(CTX_FORMAT_ERR_MSG)

    elif out_format in [FORMAT_ARG_PROXYSG, FORMAT_ARG_BLUECOAT]:
        out_format = FORMAT_PROXYSG

    elif out_format == FORMAT_ARG_MWG:
        out_format = FORMAT_MWG

    elif out_format == FORMAT_ARG_PANOSURL:
        out_format = FORMAT_PANOSURL

    results = {
        'limit': limit,
        'offset': offset,
        'out_format': out_format,
        'query': query,
        'mwg_type': mwg_type,
        'strip_port': strip_port,
        'drop_invalids': drop_invalids,
        'category_default': category_default,
        'category_attribute': category_attribute
    }
    return results


@APP.route('/', methods=['GET'])
def route_list_values() -> Response:
    """
    Main handler for values saved in the integration context
    """
    try:
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

        request_args = get_request_args(params)

        values = get_outbound_ioc_values(
            out_format=request_args.get('out_format'),
            on_demand=params.get('on_demand'),
            limit=request_args.get('limit'),
            offset=request_args.get('offset'),
            last_update_data=demisto.getIntegrationContext(),
            indicator_query=request_args.get('query'),
            cache_refresh_rate=params.get('cache_refresh_rate'),
            mwg_type=request_args.get('mwg_type'),
            strip_port=request_args.get('strip_port'),
            drop_invalids=request_args.get('drop_invalids'),
            category_default=request_args.get('category_default'),
            category_attribute=request_args.get('category_attribute')
        )

        mimetype = get_outbound_mimetype()
        return Response(values, status=200, mimetype=mimetype)

    except Exception as e:
        return Response(str(e) + traceback.format_exc(), status=400, mimetype='text/plain')


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
    Start the long running server
    :param params: Demisto params
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
    offset = args.get('offset')
    mwg_type = args.get('mwg_type')
    strip_port = args.get('strip_port') == 'True'
    drop_invalids = args.get('drop_invalids') == 'True'
    category_attribute = args.get('category_attribute')
    category_default = args.get('category_default')
    indicators = refresh_outbound_context(query, out_format, limit=limit, offset=offset, mwg_type=mwg_type, strip_port=strip_port,
                                          drop_invalids=drop_invalids, category_default=category_default,
                                          category_attribute=category_attribute)
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
