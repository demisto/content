import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
from flask import Flask, Response
from gevent.pywsgi import WSGIServer
from tempfile import NamedTemporaryFile
from typing import Callable, List

''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'EDL'
PAGE_SIZE: int = 200
APP: Flask = Flask('demisto-edl')
CSV_FIRST_LINE_KEY: str = 'csv_first_line'
FORMAT_CSV: str = 'csv'
FORMAT_TEXT: str = 'text'
FORMAT_JSON_SEQ: str = 'json-seq'
FORMAT_JSON: str = 'json'
EDL_LIMIT_ERR_MSG: str = 'Please provide a valid integer for EDL Size'

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
    port: int
    try:
        if port_mapping:
            if ':' in port_mapping:
                port = int(port_mapping.split(':')[1])
            else:
                port = int(port_mapping)
        else:
            raise ValueError('Please provide a Listen Port.')
    except (ValueError, TypeError):
        raise ValueError(f'Listen Port must be an integer. {port_mapping} is not valid.')
    return port


def refresh_value_cache(indicator_query: str, out_format: str, ip_grouping: bool = False, limit: int = 0) -> list:
    """
    Refresh the cache values and format using an indicator_query to call demisto.findIndicators
    """
    iocs = find_indicators_to_limit(indicator_query, limit, ip_grouping)  # poll indicators into edl from demisto
    ctx = create_values_out_dict(iocs, out_format)
    demisto.setLastRun({'last_run': date_to_timestamp(datetime.now())})
    demisto.setIntegrationContext(ctx)
    if out_format == FORMAT_CSV:
        return create_csv_out_list(ctx)
    return list(ctx.values())


def find_indicators_to_limit(indicator_query: str, limit: int, ip_grouping: bool = False) -> list:
    """
    Finds indicators using demisto.findIndicators
    """
    iocs, _ = find_indicators_to_limit_loop(indicator_query, limit)
    # if ip_grouping:
    #     iocs = find_and_consolidate_ips_to_limit(indicator_query, iocs, limit)
    return iocs[:limit]


def find_indicators_to_limit_loop(indicator_query: str, limit: int, total_fetched: int = 0, next_page: int = 0,
                                  last_found_len: int = PAGE_SIZE):
    """
    Finds indicators using while loop with demisto.findIndicators, and returns result and last page
    """
    iocs: List[dict] = []
    if not last_found_len:
        last_found_len = total_fetched
    while last_found_len == PAGE_SIZE and limit and total_fetched < limit:
        fetched_iocs = demisto.findIndicators(query=indicator_query, page=next_page, size=PAGE_SIZE).get('iocs')
        iocs.extend(fetched_iocs)
        last_found_len = len(fetched_iocs)
        total_fetched += last_found_len
        next_page += 1
    return iocs, next_page


# def find_and_consolidate_ips_to_limit(indicator_query, iocs, limit):
#     """
#     Groups IPs and find new ones afterward in a loop until limit is reached
#     """
#     pre_consolidate_iocs_len = len(iocs)
#     iocs, next_page = find_new_ips_and_consolidate(indicator_query, iocs, limit)
#     while len(iocs) != pre_consolidate_iocs_len:
#         pre_consolidate_iocs_len = len(iocs)
#         iocs, next_page = find_new_ips_and_consolidate(indicator_query, iocs, limit, next_page)
#     return iocs
#
#
# def find_new_ips_and_consolidate(indicator_query, iocs, limit, next_page=0):
#     """
#     Finds new IPs and consolidates them
#     """
#     last_iocs_found, next_page = find_indicators_to_limit_loop(indicator_query, limit, total_fetched=len(iocs),
#                                                                next_page=next_page)
#     iocs = consolidate_ips(iocs)
#     return iocs, next_page
#
#
# def consolidate_ips(iocs):
#     """
#     Groups together ips in a list of strings
#     """
#     try:
#         iocs = sorted(iocs, key=lambda ip: struct.unpack('!L', inet_aton(ip))[0])
#     except OSError:
#         demisto.debug('Failed to consolidate IPs because')
#         return iocs


def create_csv_out_list(cache_dict: dict) -> list:
    """
    Creates a csv output result
    """
    csv_headers = cache_dict.pop(CSV_FIRST_LINE_KEY, '')
    values_list = list(cache_dict.values())
    if csv_headers:
        values_list.insert(0, csv_headers)

    return values_list


def create_values_out_dict(iocs: list, out_format: str) -> dict:
    """
    Create a dictionary for output values using the selected format
    """
    out_format_func = {
        FORMAT_TEXT: out_text_format,
        FORMAT_JSON_SEQ: out_json_seq_format,
        FORMAT_CSV: out_csv_format
    }
    return create_formatted_values_out_dict(iocs, out_format, out_format_func.get(out_format, str))


def create_formatted_values_out_dict(iocs: list, out_format: str, out_format_func: Callable) -> dict:
    """
    Create a dictionary for output values formatted in the selected out_format
    """
    ctx = {}
    if out_format == FORMAT_JSON:
        iocs_list = [ioc for ioc in iocs]
        return {'iocs_list': json.dumps(iocs_list, indent=4)}
    else:
        for ioc in iocs:
            value = ioc.get('value')
            if value:
                ctx[value] = out_format_func(ioc)
        if out_format == 'csv' and len(iocs) > 0:  # add csv headers
            headers = list(iocs[0].keys())
            ctx[CSV_FIRST_LINE_KEY] = list_to_str(headers)
        return ctx


def out_text_format(ioc: dict) -> str:
    """
    Return output in text format
    """
    return ioc.get('value', '')


def out_json_seq_format(ioc: dict) -> str:
    """
    Return output in json seq format
    """
    return json.dumps(ioc)


def out_csv_format(ioc: dict) -> str:
    """
    Return output in csv format
    """
    values = list(ioc.values())
    return list_to_str(values, map_func=lambda val: f'"{val}"')


def get_edl_ioc_list():
    """
    Get the ioc list to return in the edl
    """
    params = demisto.params()
    out_format = params.get('format')
    on_demand = params.get('on_demand')
    limit = parse_integer(params.get('edl_size'), EDL_LIMIT_ERR_MSG)
    # on_demand ignores cache
    if on_demand:
        values = get_out_values_from_cache(out_format)
    else:
        last_run = demisto.getLastRun().get('last_run')
        indicator_query = demisto.params().get('indicators_query', '')
        if last_run:
            cache_refresh_rate = demisto.params().get('cache_refresh_rate', limit)
            cache_time, _ = parse_date_range(cache_refresh_rate, to_timestamp=True)
            td = last_run - cache_time
            if td <= 0:  # last_run is before cache_time
                values = refresh_value_cache(indicator_query, out_format, limit=limit)
            else:
                values = get_out_values_from_cache(out_format)
        else:
            values = refresh_value_cache(indicator_query, out_format, limit=limit)
    return values


def get_out_values_from_cache(out_format):
    """
    Extracts output values from cache
    """
    cache_dict = demisto.getIntegrationContext()
    values = create_csv_out_list(cache_dict) if out_format == FORMAT_CSV else list(cache_dict.values())
    return values


def parse_integer(int_to_parse, err_msg):
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    """
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError) as e:
        raise DemistoException(err_msg, e)
    return res


''' ROUTE FUNCTIONS '''


@APP.route('/', methods=['GET'])
def route_edl_values() -> Response:
    """
    Main handler for values saved in the integration context
    """
    params = demisto.params()
    out_format = params.get('format', 'text')
    mimetype = 'application/json' if out_format == FORMAT_JSON else 'text/plain'
    values = list_to_str(get_edl_ioc_list(), '\n')
    return Response(values, status=200, mimetype=mimetype)


''' COMMAND FUNCTIONS '''


def test_module(args, params):
    """
    Validates that the port is integer
    """
    get_params_port(params)
    cache_refresh_rate = params.get('cache_refresh_rate', '')
    if cache_refresh_rate:
        # validate $cache_refresh_rate value
        range_split = cache_refresh_rate.split(' ')
        if len(range_split) != 2:
            raise ValueError('Cache Refresh Rate must be "number date_range_unit", examples: (2 hours, 4 minutes,'
                             '6 months, 1 day, etc.)')
        if not range_split[1] in ['minute', 'minutes', 'hour', 'hours', 'day', 'days', 'month', 'months', 'year',
                                  'years']:
            raise ValueError(
                'Cache Refresh Rate time unit is invalid. Must be minutes, hours, days, months or years')
        parse_date_range(cache_refresh_rate, to_timestamp=True)
    on_demand = params.get('on_demand', None)
    if not on_demand:
        parse_integer(params.get('edl_size'), EDL_LIMIT_ERR_MSG)  # validate EDL Size was set
        query = params.get('indicators_query')  # validate $indicators_query isn't empty
        if not query:
            raise ValueError('"Indicator Query" cannot be empty, please provide a valid query')
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

        server = WSGIServer(('', port), APP, **ssl_args)
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
    limit = parse_integer(args.get('edl_size', params.get('edl_size')), EDL_LIMIT_ERR_MSG)
    if not on_demand:
        raise DemistoException(
            '"Update EDL On Demand" is turned off. If you want to update the EDL manually please turn it on.')
    query = args.get('query')
    out_format = args.get('format')
    indicators = refresh_value_cache(query, out_format, limit=limit)
    hr = tableToMarkdown('EDL was updated successfully with the following values', indicators, ['indicators'])
    return hr, {}, {}


def main():
    """
    Main
    """
    params = demisto.params()
    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))
    commands = {
        'test-module': test_module,
        'update-edl': update_edl_command
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
